import math
import os
import sys
import subprocess
import signal
import time
import redis
import json
import threading
import requests
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

# Import our custom modules
from extraction.flow_manager import FlowManager
from dqn.agent import DQNAgent
from enforcement.rule_manager import RuleManager

# Configuration
QUEUE_NUM = 0
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')

# Initialize Redis client for telemetry broadcasting
try:
    redis_client = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)
except Exception as e:
    print(f"Failed to connect to Redis: {e}")
    redis_client = None

# Initialize core architectural components
flow_manager = FlowManager(window_size=100)
dqn_agent = DQNAgent(input_dim=12, action_dim=3)
rule_manager = RuleManager(mode="simulation") 

# MOCK ORACLE: In a live enterprise environment, ground truth is unknown until a breach.
# For the RL agent's offline training phase, we simulate an established dataset (like CICDDOS2019) 
# to calculate the reward function accurately.
KNOWN_MALICIOUS_IPS = {"192.168.1.100", "10.0.0.50", "172.16.0.23"}

# MDP State Tracker: Maps flow keys to their previous state to build (S, A, R, S') tuples
flow_states = {}
blocked_states_cache = {}

LARAVEL_API_URL = "http://localhost:8000/api/ai/performance"

def log_metrics_to_laravel(epoch, epsilon, total_reward, loss, threats_blocked, threats_allowed):
    """
    Pushes training metrics to the Laravel backend after each epoch.
    """
    payload = {
        "epoch": epoch,
        "epsilon": epsilon,
        "cumulative_reward": float(total_reward), # Ensure JSON serializable
        "loss": float(loss) if loss is not None else 0.0,
        "threats_blocked": int(threats_blocked),
        "threats_allowed": int(threats_allowed)
    }
    
    try:
        # 5-second timeout so the agent doesn't hang forever
        response = requests.post(LARAVEL_API_URL, json=payload, timeout=5)
        response.raise_for_status()
        print(f"✅ [API] Epoch {epoch} metrics saved successfully.")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ [API Warning] Failed to log metrics to Laravel: {e}")

def send_realtime_telemetry(src_ip, port, confidence, action):
        payload = {
            "src_ip": src_ip,
            "port": int(port),
            "confidence": float(confidence), # e.g., 0.95 for 95%
            "action": action # 'BLOCKED', 'ACCEPTED', or 'RATE_LIMITED'
        }
        try:
            # We use a very short timeout (e.g., 0.5s or 1s). 
            # If Laravel is busy, we drop the telemetry rather than slow down the actual firewall enforcement.
            requests.post("http://localhost:8000/api/firewall/telemetry", json=payload, timeout=0.5)
        except requests.exceptions.RequestException:
            pass # Fail silently for real-time telemetry
        
def setup_iptables():
    """Routes specific traffic into the NFQUEUE."""
    print(f"Setting up iptables to route traffic to NFQUEUE {QUEUE_NUM}...")
    cmd = f"iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-num {QUEUE_NUM}"
    subprocess.run(cmd.split(), check=True)

def cleanup_iptables(signum, frame):
    """Gracefully removes the iptables rule on shutdown."""
    print("\nFlushing iptables rules and shutting down...")
    cmd = f"iptables -D INPUT -p tcp --dport 80 -j NFQUEUE --queue-num {QUEUE_NUM}"
    subprocess.run(cmd.split(), check=False)
    sys.exit(0)

def process_packet(packet):
    """Callback function executed for every packet in the queue."""
    
    scapy_pkt = IP(packet.get_payload())
    
    if scapy_pkt.haslayer(IP) and scapy_pkt.haslayer(TCP):
        src_ip = scapy_pkt[IP].src
        dst_port = scapy_pkt[TCP].dport
        flow_key = flow_manager._generate_flow_key(scapy_pkt)
        
        # Start Latency Timer 
        timer_start = time.time()
        
        # Phase 2: Feature Extraction
        state_vector, is_terminal = flow_manager.process_packet(scapy_pkt)
        
        if state_vector:

            state_vector = [0.0 if math.isnan(x) or math.isinf(x) else float(x) for x in state_vector]
            
            # Phase 5: DQN Inference
            action = dqn_agent.select_action(state_vector)
            confidence = getattr(dqn_agent, 'get_confidence', lambda x: 1.0)(state_vector)

            CONFIDENCE_THRESHOLD = 0.85 # Require 85% certainty to auto-block
            
            # Stop Latency Timer & Calculate Penalty
            processing_time_ms = (time.time() - timer_start) * 1000
            latency_penalty = -0.1 * processing_time_ms # -0.1 reward per millisecond 
            
            # --- THE REWARD FUNCTION ---
            # Evaluate the action against the "ground truth" to determine the base reward [cite: 165]
            is_malicious = src_ip in KNOWN_MALICIOUS_IPS
            base_reward = 0.0
            
            if action == 1: # DROP
                if is_malicious:
                    base_reward = 10.0  # Strong positive reward for blocking known malware [cite: 167]
                else:
                    base_reward = -50.0 # Massively asymmetric penalty for false positives [cite: 169]
            elif action == 0: # ACCEPT
                if is_malicious:
                    base_reward = -20.0 # Penalty for failing to block an attack
                else:
                    base_reward = +1.0  # Marginal reward for allowing legitimate business traffic
            elif action == 2: # RATE LIMIT
                if is_malicious:
                    base_reward = 2.0   # Partially mitigated the threat
                else:
                    base_reward = -10.0 # Unnecessarily degraded legitimate user experience
                    
            total_reward = base_reward + latency_penalty
            
            # --- MDP STATE TRACKING & TRAINING LOOP ---
            # If we have a previous state for this flow, we now have the "Next State" (S')
            if flow_key in flow_states:
                prev = flow_states[flow_key]
                
                # Push the transition tuple to the Experience Replay Buffer
                dqn_agent.memory.push(
                    state=prev['state'],
                    action=prev['action'],
                    reward=prev['reward'],
                    next_state=state_vector,
                    # We dynamically pass 1 if the flow ended via FIN/RST, otherwise 0
                    done=1 if is_terminal else 0 
                )
                
                dqn_agent.optimize_model()
                
                if dqn_agent.steps_done % 1000 == 0:
                    dqn_agent.update_target_network()

            # If the flow is dead, remove it from our previous state tracker so it doesn't leak memory
            if is_terminal:
                if flow_key in flow_states:
                    del flow_states[flow_key]
            else:
                # Otherwise, save the current state for the next window
                flow_states[flow_key] = {
                    'state': state_vector,
                    'action': action,
                    'reward': total_reward
                }

            # --- ENFORCEMENT ---
            status = "UNKNOWN"
            
            # INTERCEPT: AI wants to block, but isn't sure.
            if action == 1 and confidence < CONFIDENCE_THRESHOLD:
                # Cache the state so the human can force unlearning/reinforcement later
                blocked_states_cache[src_ip] = state_vector
                
                # QUARANTINE: Apply an incredibly strict rate limit (e.g., 2 packets/sec). 
                # This keeps the TCP handshake alive for the human to review, but stops data exfiltration.
                rule_manager.deploy_rate_limit_rule(src_ip, max_packets_per_second=2, duration_seconds=600)
                packet.accept() 
                status = "NEEDS_REVIEW"

            elif action == 0:
                packet.accept() 
                status = "ACCEPTED"
                
            elif action == 1: # High confidence block
                blocked_states_cache[src_ip] = state_vector
                rule_manager.deploy_block_rule(src_ip, duration_seconds=600)
                packet.drop()   
                status = "BLOCKED"
                
            elif action == 2: # Rate limit
                rule_manager.deploy_rate_limit_rule(src_ip, max_packets_per_second=50, duration_seconds=300)
                packet.accept() 
                status = "RATE_LIMITED"
                
            # --- REAL-TIME TELEMETRY ---
            # Fire HTTP POST to Laravel Reverb (We moved the confidence calculation higher up)
            send_realtime_telemetry(src_ip, dst_port, confidence, status)
            
            # Keep existing Redis publish if you still need it for other services
            if redis_client:
                # We are injecting "confidence": {confidence:.4f} into the JSON string
                telemetry_data = f'{{"src_ip": "{src_ip}", "port": {dst_port}, "action": "{status}", "confidence": {confidence:.4f}, "reward": {total_reward:.2f}, "latency_ms": {processing_time_ms:.2f}}}'
                redis_client.publish('firewall-telemetry', telemetry_data)
                
                print(f"[AI] Evaluated IP {src_ip} -> {status} (Reward: {total_reward:.2f})", flush=True)
                
        else:
            packet.accept()
    else:
        packet.accept()

def handle_human_overrides():
    """
    Background thread that listens to Redis for human-in-the-loop decisions.
    Applies the final firewall rule and forces the DQN to learn from the human.
    """
    if not redis_client:
        return

    pubsub = redis_client.pubsub()
    pubsub.subscribe('firewall-overrides')
    print("Listening for human overrides on Redis channel 'firewall-overrides'...")

    for message in pubsub.listen():
        if message['type'] == 'message':
            try:
                data = json.loads(message['data'])
                override_ip = data.get('ip')
                # Default to 'ALLOW' so older "Revoke Block" buttons still work
                decision = data.get('decision', 'ALLOW') 
                
                if override_ip and override_ip in blocked_states_cache:
                    faulty_state = blocked_states_cache[override_ip]
                    
                    if decision == 'ALLOW':
                        print(f"\n[!] ANALYST ALLOWED IP: {override_ip}")
                        # 1. Lift the quarantine rate limit
                        rule_manager._remove_rule(override_ip)
                        
                        # 2. Punish the AI (It wanted to block legitimate traffic)
                        dqn_agent.memory.push(
                            state=faulty_state, action=1, reward=-100.0, next_state=faulty_state, done=1 
                        )
                        print(" -> Quarantine lifted. Model punished for false positive.")
                        
                    elif decision == 'BLOCK':
                        print(f"\n[!] ANALYST BLOCKED IP: {override_ip}")
                        # 1. Upgrade the quarantine rate limit to a hard block
                        rule_manager.deploy_block_rule(override_ip, duration_seconds=600)
                        
                        # 2. Reward the AI (It was unsure, but its instinct to block was correct)
                        dqn_agent.memory.push(
                            state=faulty_state, action=1, reward=50.0, next_state=faulty_state, done=1 
                        )
                        print(" -> Hard block applied. Model rewarded for catching threat.")

                    # Trigger gradient descent to learn immediately
                    dqn_agent.optimize_model()
                    
                    # Clean up cache
                    del blocked_states_cache[override_ip]
                        
            except Exception as e:
                print(f"Error processing override: {e}")
if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup_iptables)
    signal.signal(signal.SIGTERM, cleanup_iptables)

    setup_iptables()
    
    # Start the Human-in-the-Loop Listener as a daemon thread
    override_thread = threading.Thread(target=handle_human_overrides, daemon=True)
    override_thread.start()

    nfqueue = NetfilterQueue()
    try:
        nfqueue.bind(QUEUE_NUM, process_packet)
        print("Firewall Agent running. Active Training Loop initialized...")
        nfqueue.run()
    except Exception as e:
        print(f"Error in NFQUEUE: {e}")
    finally:
        nfqueue.unbind()
        cleanup_iptables(None, None)