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
import queue
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

# Import our custom modules
from extraction.flow_manager import FlowManager
from dqn.agent import DQNAgent
from enforcement.rule_manager import RuleManager

# Runtime configuration
QUEUE_NUM = 0
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')

class EpochTracker:
    def __init__(self, batch_size=100):
        self.batch_size = batch_size
        self.current_epoch = 1
        self.steps = 0
        self.cumulative_reward = 0.0
        self.threats_blocked = 0
        self.threats_allowed = 0
        self.losses = []

    def record_step(self, action, reward, loss):
        self.steps += 1
        self.cumulative_reward += reward
        if loss is not None:
            self.losses.append(loss)
            
        if action == 1:
            self.threats_blocked += 1
        elif action == 0:
            self.threats_allowed += 1

    def is_ready(self):
        return self.steps >= self.batch_size

    def flush(self, epsilon):
        avg_loss = sum(self.losses) / len(self.losses) if self.losses else 0.0
        
        log_metrics_to_laravel(
            epoch=self.current_epoch,
            epsilon=epsilon,
            total_reward=self.cumulative_reward,
            loss=avg_loss,
            threats_blocked=self.threats_blocked,
            threats_allowed=self.threats_allowed
        )
        
        # Reset batch accumulators.
        self.current_epoch += 1
        self.steps = 0
        self.cumulative_reward = 0.0
        self.threats_blocked = 0
        self.threats_allowed = 0
        self.losses = []

epoch_tracker = EpochTracker(batch_size=10)

# Initialize Redis telemetry client.
try:
    redis_client = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)
except Exception as e:
    print(f"Failed to connect to Redis: {e}")
    redis_client = None

# Initialize core components.
flow_manager = FlowManager(window_size=10)
dqn_agent = DQNAgent(input_dim=12, action_dim=3)
rule_manager = RuleManager(mode="simulation") 

# Simulated labels for offline reward shaping.
KNOWN_MALICIOUS_IPS = {"192.168.1.100", "10.0.0.50", "172.16.0.23"}

# Tracks prior transitions by flow key to build (S, A, R, S').
flow_states = {}
blocked_states_cache = {}
telemetry_queue = queue.Queue(maxsize=100)
metrics_queue = queue.Queue(maxsize=50)

LARAVEL_API_URL = "http://localhost/api/ai/performance"

def metrics_worker():
    """Background thread that saves graph data to Laravel without blocking."""
    while True:
        payload = metrics_queue.get()
        try:
            requests.post("http://localhost/api/ai/performance", json=payload, timeout=2)
            print(f"✅ [API] Epoch {payload['epoch']} metrics saved.")
        except Exception:
            pass
        metrics_queue.task_done()

threading.Thread(target=metrics_worker, daemon=True).start()

def log_metrics_to_laravel(epoch, epsilon, total_reward, loss, threats_blocked, threats_allowed):
    """Puts the training metrics into the queue instantly."""
    payload = {
        "epoch": epoch,
        "epsilon": epsilon,
        "cumulative_reward": float(total_reward),
        "loss": float(loss) if loss is not None else 0.0,
        "threats_blocked": int(threats_blocked),
        "threats_allowed": int(threats_allowed)
    }
    
    if not metrics_queue.full():
        metrics_queue.put_nowait(payload)
    else:
        print(f"⚠️ [Queue Full] Dropping Epoch {epoch} metrics to keep firewall speed up.")

def telemetry_worker():
    """Background thread that sends HTTP requests without blocking the firewall."""
    while True:
        payload = telemetry_queue.get()
        try:
            requests.post("http://localhost/api/firewall/telemetry", json=payload, timeout=0.5)
        except Exception:
            pass
        telemetry_queue.task_done()

threading.Thread(target=telemetry_worker, daemon=True).start()

def send_realtime_telemetry(src_ip, port, confidence, action):
    """Adds telemetry to the queue if the queue isn't full."""
    if not telemetry_queue.full(): 
        payload = {
            "src_ip": src_ip,
            "port": int(port),
            "confidence": float(confidence),
            "action": action
        }
        telemetry_queue.put_nowait(payload)
        
def setup_iptables():
    """Routes specific traffic into the NFQUEUE."""
    print(f"Setting up iptables to route traffic to NFQUEUE {QUEUE_NUM}...")
    cmd = f"iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-num {QUEUE_NUM}"
    subprocess.run(cmd.split(), check=True)

def cleanup_iptables(signum, frame):
    """Gracefully removes the iptables rule and saves weights on shutdown."""
    print("\n[!] Shutting down...")
    
    print("[*] Saving final model weights before exit...")
    try:
        if hasattr(dqn_agent, 'save'):
            dqn_agent.save("firewall_weights.pth")
        else:
            import torch
            torch.save(dqn_agent.policy_net.state_dict(), "firewall_weights.pth")
        print("[*] Weights successfully saved.")
    except Exception as e:
        print(f"[!] Failed to save weights: {e}")

    print("Flushing iptables rules...")
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
        
        # Track per-packet processing latency for reward penalty.
        timer_start = time.time()
        
        state_vector, is_terminal = flow_manager.process_packet(scapy_pkt)
        
        if state_vector:

            state_vector = [0.0 if math.isnan(x) or math.isinf(x) else float(x) for x in state_vector]
            
            dqn_agent.state_cache[src_ip] = state_vector

            action = dqn_agent.select_action(state_vector)
            confidence = getattr(dqn_agent, 'get_confidence', lambda x: 1.0)(state_vector)

            CONFIDENCE_THRESHOLD = 0.85
            
            processing_time_ms = (time.time() - timer_start) * 1000
            latency_penalty = -0.1 * processing_time_ms
            
            # Compute supervised reward signal against simulated labels.
            is_malicious = src_ip in KNOWN_MALICIOUS_IPS
            base_reward = 0.0
            
            if action == 1:
                if is_malicious:
                    base_reward = 10.0
                else:
                    base_reward = -50.0
            elif action == 0:
                if is_malicious:
                    base_reward = -20.0
                else:
                    base_reward = +1.0
            elif action == 2:
                if is_malicious:
                    base_reward = 2.0
                else:
                    base_reward = -10.0
                    
            total_reward = base_reward + latency_penalty
            loss_val = None
            
            # Training transition update.
            if flow_key in flow_states:
                prev = flow_states[flow_key]
                
                dqn_agent.memory.push(
                    state=prev['state'], action=prev['action'], reward=prev['reward'],
                    next_state=state_vector, done=1 if is_terminal else 0 
                )
                
                loss_val = dqn_agent.optimize_model()
                
                if dqn_agent.steps_done % 1000 == 0:
                    dqn_agent.update_target_network()

                    try:
                        if hasattr(dqn_agent, 'save'):
                            dqn_agent.save("firewall_weights.pth")
                        else:
                            import torch
                            torch.save(dqn_agent.policy_net.state_dict(), "firewall_weights.pth")
                        print(f"[*] Checkpoint reached (Step {dqn_agent.steps_done}): Model weights saved to disk.")
                    except Exception as e:
                        pass

            epoch_tracker.record_step(action, total_reward, loss_val)
            
            if epoch_tracker.is_ready():
                current_epsilon = dqn_agent.epsilon_end + (dqn_agent.epsilon_start - dqn_agent.epsilon_end) * \
                                  math.exp(-1. * dqn_agent.steps_done / dqn_agent.epsilon_decay)
                epoch_tracker.flush(current_epsilon)

            if is_terminal:
                if flow_key in flow_states:
                    del flow_states[flow_key]
            else:
                flow_states[flow_key] = {
                    'state': state_vector,
                    'action': action,
                    'reward': total_reward
                }

            status = "UNKNOWN"
            
            if action == 1 and confidence < CONFIDENCE_THRESHOLD:
                blocked_states_cache[src_ip] = state_vector
                
                rule_manager.deploy_rate_limit_rule(src_ip, max_packets_per_second=2, duration_seconds=600)
                packet.accept() 
                status = "NEEDS_REVIEW"

            elif action == 0:
                packet.accept() 
                status = "ACCEPTED"
                
            elif action == 1:
                blocked_states_cache[src_ip] = state_vector
                rule_manager.deploy_block_rule(src_ip, duration_seconds=600)
                packet.drop()   
                status = "BLOCKED"
                
            elif action == 2:
                rule_manager.deploy_rate_limit_rule(src_ip, max_packets_per_second=50, duration_seconds=300)
                packet.accept() 
                status = "RATE_LIMITED"
                
            send_realtime_telemetry(src_ip, dst_port, confidence, status)
            
            if redis_client:
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
                
                if override_ip:
                    # 1. Enforce the Rule immediately via iptables
                    if decision == 'ALLOW':
                        print(f"\n[!] ANALYST ALLOWED IP: {override_ip}")
                        rule_manager._remove_rule(override_ip)
                    elif decision == 'BLOCK':
                        print(f"\n[!] ANALYST BLOCKED IP: {override_ip}")
                        rule_manager.deploy_block_rule(override_ip, duration_seconds=600)

                    # ---> NEW: REWARD AI AND UPDATE GRAPH <---
                    # 2. Force the AI to learn from the human's decision
                    dqn_agent.apply_human_feedback(src_ip=override_ip, correct_action_label=decision)
                    
                    # 3. Force the graph to dip/spike
                    # -100 penalty if we had to ALLOW a false positive. +50 if we confirmed a BLOCK.
                    reward_val = -100.0 if decision == 'ALLOW' else 50.0
                    action_val = 0 if decision == 'ALLOW' else 1
                    
                    epoch_tracker.record_step(action=action_val, reward=reward_val, loss=None)
                    # ---> END NEW CODE <---
                        
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
        nfqueue.bind(QUEUE_NUM, process_packet, max_len=50)
        print("Firewall Agent running. Active Training Loop initialized...")
        nfqueue.run()
    except Exception as e:
        print(f"Error in NFQUEUE: {e}")
    finally:
        nfqueue.unbind()
        cleanup_iptables(None, None)