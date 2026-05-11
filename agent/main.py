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
from scapy.all import IP, TCP, sniff

# Import our custom modules
from extraction.flow_manager import FlowManager
from dqn.agent import DQNAgent
from enforcement.rule_manager import RuleManager

# Runtime configuration
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
CAPTURE_IFACE = os.environ.get('CAPTURE_IFACE', 'eth1')
RULE_SYNC_TOKEN = os.environ.get('RULE_SYNC_TOKEN', '')
ACTIVE_RULES_SYNC_URL = os.environ.get('ACTIVE_RULES_SYNC_URL', 'http://localhost/api/firewall/rules/active-sync')

def get_env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default

SWITCH_SYNC_INTERVAL = get_env_int('SWITCH_SYNC_INTERVAL', 15)
MANUAL_RULES_POLL_INTERVAL = get_env_int('MANUAL_RULES_POLL_INTERVAL', 30)

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
# Initialize RuleManager from environment (env overrides defaults)
mode = os.environ.get('FIREWALL_MODE', 'simulation')
mgmt_ip = os.environ.get('ICX_MGMT_IP', '192.168.1.1')
mgmt_user = os.environ.get('ICX_USER', 'admin')
mgmt_pass = os.environ.get('ICX_PASSWORD', 'password')
mgmt_key_file = os.environ.get('ICX_KEY_FILE')
mgmt_key_passphrase = os.environ.get('ICX_KEY_PASSPHRASE')
rule_manager = RuleManager(
    mode=mode,
    mgmt_ip=mgmt_ip,
    auth=(mgmt_user, mgmt_pass),
    ssh_key_file=mgmt_key_file,
    ssh_key_passphrase=mgmt_key_passphrase,
)

# Simulated labels for offline reward shaping.
KNOWN_MALICIOUS_IPS = {"192.168.1.100", "10.0.0.50", "172.16.0.23"}

# Tracks prior transitions by flow key to build (S, A, R, S').
flow_states = {}
blocked_states_cache = {}
telemetry_queue = queue.Queue(maxsize=100)
metrics_queue = queue.Queue(maxsize=50)

LARAVEL_API_URL = "http://localhost/api/ai/performance"
MANUAL_RULES_IMPORT_URL = "http://localhost/api/firewall/rules/import-switch"
MANUAL_RULES_SYNC_TOKEN = os.environ.get('RULE_SYNC_TOKEN', '')

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
            headers = {'X-Rule-Sync-Token': RULE_SYNC_TOKEN} if RULE_SYNC_TOKEN else {}
            requests.post("http://localhost/api/firewall/telemetry", json=payload, headers=headers, timeout=0.5)
        except Exception:
            pass
        telemetry_queue.task_done()

threading.Thread(target=telemetry_worker, daemon=True).start()

def import_switch_rules_to_backend(context="Switch Import"):
    """Reads switch ACLs and imports them into the backend dashboard store."""
    if not MANUAL_RULES_SYNC_TOKEN:
        print(f"[{context}] RULE_SYNC_TOKEN is not set; skipping ACL import.")
        return

    try:
        switch_rules = rule_manager.list_switch_block_rules()
        if switch_rules is None:
            print(f"[{context}] Failed to read switch ACLs; skipping import.")
            return

        response = requests.post(
            MANUAL_RULES_IMPORT_URL,
            json={"rules": switch_rules},
            headers={"X-Rule-Sync-Token": MANUAL_RULES_SYNC_TOKEN},
            timeout=10,
        )
        response.raise_for_status()
        if switch_rules:
            print(f"[{context}] Imported {len(switch_rules)} switch ACL rule(s) into backend.")
        else:
            print(f"[{context}] Switch ACL list is empty; backend state cleared.")
    except Exception as e:
        print(f"[{context}] Failed to import switch rules: {e}")

def normalize_block_target(ip_address):
    if not ip_address:
        return ip_address
    return ip_address if '/' in ip_address else f"{ip_address}/32"

def handle_manual_rule_events():
    """Listen for manual rule updates and push them to the switch immediately."""
    print("[Manual Rules] Starting event listener thread")
    if not redis_client:
        print("[Manual Rules] ERROR: Redis client not available!")
        return

    pubsub = redis_client.pubsub()
    pubsub.subscribe('manual-firewall-rules')
    print("[Manual Rules] Listening for events on 'manual-firewall-rules' channel...")

    for message in pubsub.listen():
        print(f"[Manual Rules] Received message: {message}")
        if message['type'] != 'message':
            print(f"[Manual Rules] Skipping non-message type: {message['type']}")
            continue

        try:
            data = json.loads(message['data'])
            print(f"[Manual Rules] Parsed data: {data}")
            action = data.get('action')
            rule_data = data.get('rule_data', {})
            ip_address = rule_data.get('ip_address')
            rule_action = rule_data.get('action')

            if not ip_address or not rule_action:
                print(f"[Manual Rules] Missing required fields: ip_address={ip_address}, rule_action={rule_action}")
                continue

            if action in ('created', 'updated'):
                if rule_action == 'BLOCK':
                    print(f"[Manual Rules] Applying BLOCK for {ip_address}")
                    rule_manager.deploy_block_rule(ip_address, duration_seconds=3600 if rule_data.get('rule_type') == 'PERMANENT' else 600)
                elif rule_action == 'ALLOW':
                    print(f"[Manual Rules] Applying ALLOW for {ip_address} (removing block)")
                    rule_manager._remove_rule(normalize_block_target(ip_address))
            elif action == 'deleted':
                print(f"[Manual Rules] Removing rule for {ip_address}")
                rule_manager._remove_rule(normalize_block_target(ip_address))
        except Exception as e:
            import traceback
            print(f"[Manual Rules] Error processing event: {e}")
            print(f"[Manual Rules] Traceback: {traceback.format_exc()}")

def send_realtime_telemetry(src_ip, port, confidence, action, **extra_fields):
    """Adds telemetry to the queue if the queue isn't full."""
    if not telemetry_queue.full(): 
        payload = {
            "src_ip": src_ip,
            "port": int(port),
            "confidence": float(confidence),
            "action": action,
            **extra_fields,
        }
        telemetry_queue.put_nowait(payload)
        
def setup_iptables():
    """Routes specific traffic into the NFQUEUE."""
    # No-op for out-of-band mirrored capture
    print("Info: Running in out-of-band capture mode; not modifying iptables.")

def cleanup_iptables(signum, frame):
    """Gracefully saves weights on shutdown."""
    print("\n[!] Shutting down and saving model weights...")
    try:
        if hasattr(dqn_agent, 'save'):
            dqn_agent.save("firewall_weights.pth")
        else:
            import torch
            torch.save(dqn_agent.policy_net.state_dict(), "firewall_weights.pth")
        print("[*] Weights successfully saved.")
    except Exception as e:
        print(f"[!] Failed to save weights: {e}")

    sys.exit(0)

def process_mirrored_packet(scapy_pkt):
    """Handler for mirrored Scapy packets (out-of-band)."""
    if scapy_pkt is None:
        return

    if scapy_pkt.haslayer(IP) and scapy_pkt.haslayer(TCP):
        src_ip = scapy_pkt[IP].src
        dst_port = scapy_pkt[TCP].dport
        flow_key = flow_manager._generate_flow_key(scapy_pkt)

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

            is_malicious = src_ip in KNOWN_MALICIOUS_IPS
            base_reward = 0.0

            if action == 1:
                base_reward = 10.0 if is_malicious else -50.0
            elif action == 0:
                base_reward = -20.0 if is_malicious else 1.0
            elif action == 2:
                base_reward = 2.0 if is_malicious else -10.0

            total_reward = base_reward + latency_penalty
            loss_val = None

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
                    except Exception:
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
                status = "NEEDS_REVIEW"

            elif action == 0:
                status = "ACCEPTED"

            elif action == 1:
                blocked_states_cache[src_ip] = state_vector
                rule_manager.deploy_block_rule(src_ip, duration_seconds=600)
                status = "BLOCKED"

            elif action == 2:
                rule_manager.deploy_rate_limit_rule(src_ip, max_packets_per_second=50, duration_seconds=300)
                status = "RATE_LIMITED"

            send_realtime_telemetry(
                src_ip,
                dst_port,
                confidence,
                status,
                flow_key=flow_key,
                reward=float(total_reward),
                latency_ms=float(processing_time_ms),
                is_malicious=is_malicious,
                terminal=is_terminal,
            )

            if redis_client:
                telemetry_data = {
                    "src_ip": src_ip,
                    "port": int(dst_port),
                    "action": status,
                    "confidence": float(confidence),
                    "reward": float(total_reward),
                    "latency_ms": float(processing_time_ms),
                    "flow_key": flow_key,
                    "is_malicious": is_malicious,
                    "terminal": is_terminal,
                }
                redis_client.publish('firewall-telemetry', json.dumps(telemetry_data))
                print(f"[AI] Evaluated IP {src_ip} -> {status} (Reward: {total_reward:.2f})", flush=True)

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
def handle_manual_rules():
    """
    Background thread that periodically fetches manual firewall rules from the backend
    and applies them via the rule manager.
    """
    last_rules = {}
    poll_interval = MANUAL_RULES_POLL_INTERVAL
    backend_url = ACTIVE_RULES_SYNC_URL
    
    print(f"Starting manual rules polling thread (interval: {poll_interval}s)...")
    
    while True:
        try:
            time.sleep(poll_interval)
            
            headers = {'X-Rule-Sync-Token': RULE_SYNC_TOKEN} if RULE_SYNC_TOKEN else {}
            response = requests.get(backend_url, headers=headers, timeout=5)
            response.raise_for_status()
            data = response.json()
            current_rules = {}
            
            if 'rules' in data:
                for rule in data['rules']:
                    rule_key = f"{rule.get('ip_address')}_{rule.get('port', 'any')}"
                    current_rules[rule_key] = rule
                    
                    # Check if this is a new rule
                    if rule_key not in last_rules:
                        ip_address = rule.get('ip_address')
                        action = rule.get('action')
                        
                        if action == 'BLOCK':
                            print(f"[Manual] Applying BLOCK rule for IP: {ip_address}")
                            rule_manager.deploy_block_rule(ip_address, duration_seconds=3600)
                        elif action == 'ALLOW':
                            print(f"[Manual] Applying ALLOW rule for IP: {ip_address}")
                            # For ALLOW, we remove any existing block for this IP
                            rule_manager._remove_rule(normalize_block_target(ip_address))
                
                # Check for deleted rules (exist in last_rules but not in current_rules)
                for rule_key in list(last_rules.keys()):
                    if rule_key not in current_rules:
                        old_rule = last_rules[rule_key]
                        ip_address = old_rule.get('ip_address')
                        print(f"[Manual] Removing rule for IP: {ip_address}")
                        rule_manager._remove_rule(normalize_block_target(ip_address))
                
                last_rules = current_rules
                
        except requests.exceptions.Timeout:
            print(f"[Manual Rules] Timeout fetching rules from {backend_url}")
        except requests.exceptions.ConnectionError as e:
            print(f"[Manual Rules] Connection error fetching rules: {e}")
        except requests.exceptions.HTTPError as e:
            print(f"[Manual Rules] HTTP error fetching rules: {e}")
            if hasattr(e.response, 'text'):
                print(f"[Manual Rules] Response body: {e.response.text}")
        except Exception as e:
            import traceback
            print(f"[Manual Rules] Error fetching rules: {e}")
            print(f"[Manual Rules] Traceback: {traceback.format_exc()}")
            time.sleep(5)  # Wait before retry on error

def sync_switch_rules_worker():
    """Periodically sync switch ACLs into the backend so switch state stays authoritative."""
    if not MANUAL_RULES_SYNC_TOKEN:
        print("[Switch Sync] RULE_SYNC_TOKEN is not set; skipping switch sync.")
        return

    print(f"[Switch Sync] Starting switch rules sync thread (interval: {SWITCH_SYNC_INTERVAL}s)...")

    while True:
        time.sleep(SWITCH_SYNC_INTERVAL)
        import_switch_rules_to_backend(context="Switch Sync")
if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup_iptables)
    signal.signal(signal.SIGTERM, cleanup_iptables)
    setup_iptables()

    # One-time import of switch ACLs into the dashboard store.
    import_switch_rules_to_backend()

    # Start the Human-in-the-Loop Listener as a daemon thread
    override_thread = threading.Thread(target=handle_human_overrides, daemon=True)
    override_thread.start()

    # Listen for manual rule changes so the switch is updated immediately.
    manual_rule_events_thread = threading.Thread(target=handle_manual_rule_events, daemon=True)
    manual_rule_events_thread.start()

    # Start the Manual Rules Polling thread as a daemon thread
    manual_rules_thread = threading.Thread(target=handle_manual_rules, daemon=True)
    manual_rules_thread.start()

    # Start the Switch Sync thread as a daemon thread
    switch_sync_thread = threading.Thread(target=sync_switch_rules_worker, daemon=True)
    switch_sync_thread.start()

    # Start Scapy sniffing on the mirrored interface (read-only)
    try:
        print(f"Starting out-of-band packet capture on interface {CAPTURE_IFACE} (tcp)...")
        sniff(iface=CAPTURE_IFACE, prn=process_mirrored_packet, store=0, filter="tcp")
    except Exception as e:
        print(f"Error starting packet capture: {e}")
    finally:
        cleanup_iptables(None, None)