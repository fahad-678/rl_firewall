import os
import sys
import subprocess
import signal
import time
import redis
import json
import threading
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
            # Phase 5: DQN Inference
            action = dqn_agent.select_action(state_vector)
            
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
            if action == 0:
                packet.accept() 
                status = "ACCEPTED"
                
            elif action == 1: # DROP
                # Cache the exact state vector for Human-in-the-Loop unlearning
                blocked_states_cache[src_ip] = state_vector
                
                # Deploy absolute block via Rule Manager [cite: 161]
                rule_manager.deploy_block_rule(src_ip, duration_seconds=600)
                packet.drop()   
                status = "BLOCKED"
                
            elif action == 2: # RATE LIMIT
                # Deploy network-layer bandwidth throttling 
                rule_manager.deploy_rate_limit_rule(src_ip, max_packets_per_second=50, duration_seconds=300)
                
                # Accept the CURRENT packet sitting in the queue. 
                # The kernel/iptables will start dropping FUTURE packets if they exceed the rate limit.
                packet.accept() 
                status = "RATE_LIMITED"
                
            # Telemetry Broadcasting
            if redis_client:
                telemetry_data = f'{{"src_ip": "{src_ip}", "port": {dst_port}, "action": "{status}", "reward": {total_reward:.2f}, "latency_ms": {processing_time_ms:.2f}}}'
                redis_client.publish('firewall-telemetry', telemetry_data)
                
                print(f"[AI] Evaluated IP {src_ip} -> {status} (Reward: {total_reward:.2f})", flush=True)
                
        else:
            packet.accept()
    else:
        packet.accept()

def handle_human_overrides():
    """
    Background thread that listens to Redis for human-in-the-loop overrides.
    Triggers immediate unblocking and forces the DQN to unlearn the false positive.
    """
    if not redis_client:
        print("Redis client not available. Human-in-the-loop overrides disabled.")
        return

    pubsub = redis_client.pubsub()
    pubsub.subscribe('firewall-overrides')
    print("Listening for human overrides on Redis channel 'firewall-overrides'...")

    for message in pubsub.listen():
        if message['type'] == 'message':
            try:
                data = json.loads(message['data'])
                override_ip = data.get('ip')
                
                if override_ip:
                    print(f"\n[!] HUMAN OVERRIDE RECEIVED FOR IP: {override_ip}")
                    
                    # 1. Revoke the enforcement at the network layer 
                    rule_manager._remove_rule(override_ip)
                    print(f" -> Firewall block revoked for {override_ip}.")
                    
                    # 2. Force the AI to Unlearn the misclassification 
                    if override_ip in blocked_states_cache:
                        faulty_state = blocked_states_cache[override_ip]
                        
                        # Apply a massive negative reward penalty for the false positive
                        punishment_reward = -100.0
                        
                        # Push the (State, Action, Reward, Next State) tuple into memory
                        # Action = 1 (Block), Done = 1 (Terminal state)
                        dqn_agent.memory.push(
                            state=faulty_state,
                            action=1, 
                            reward=punishment_reward,
                            next_state=faulty_state, 
                            done=1 
                        )
                        
                        # Trigger immediate gradient descent to adjust the weights
                        dqn_agent.optimize_model()
                        print(" -> Strong negative reward applied. Model optimized to unlearn parameters.")
                        
                        # Clean up cache
                        del blocked_states_cache[override_ip]
                    else:
                        print(" -> No cached state found for unlearning.")
                        
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