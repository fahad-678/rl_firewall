import os
import sys
import subprocess
import signal
import redis
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

# Import our custom modules built in previous steps
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
dqn_agent = DQNAgent(input_dim=10, action_dim=3)
rule_manager = RuleManager(mode="simulation") # Set to "hardware" for RESTCONF deployments

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
    
    # 1. Convert raw payload to Scapy object
    scapy_pkt = IP(packet.get_payload())
    
    # Check if it's a valid IP/TCP packet
    if scapy_pkt.haslayer(IP) and scapy_pkt.haslayer(TCP):
        src_ip = scapy_pkt[IP].src
        dst_port = scapy_pkt[TCP].dport
        
        # Phase 2: Real-Time State Space Construction
        # Extract features and update the sliding window.
        # This will return None until the window size (e.g., 100 packets) is reached.
        state_vector = flow_manager.process_packet(scapy_pkt)
        
        if state_vector:
            # Phase 5: DQN Inference
            # Pass the normalized 10-dimensional state vector to the neural network
            action = dqn_agent.select_action(state_vector)
            
            if action == 0:
                # Action 0: Accept benign traffic
                packet.accept() 
                status = "ACCEPTED"
                
            elif action == 1:
                # Action 1: Drop threat
                # First, deploy the active block rule for all FUTURE packets from this IP
                rule_manager.deploy_block_rule(src_ip, duration_seconds=600)
                
                # Second, explicitly DROP the CURRENT packet sitting in the queue
                packet.drop()   
                status = "BLOCKED"
                
            elif action == 2:
                # Action 2: Rate Limit (Ambiguous traffic)
                # Permit the connection but throttle bandwidth (throttling handled externally)
                packet.accept() 
                status = "RATE_LIMITED"
                
            # Phase 4: Full-Stack Telemetry
            # Push live telemetry to Redis for the Vue.js WebSocket dashboard
            if redis_client:
                telemetry_data = f'{{"src_ip": "{src_ip}", "port": {dst_port}, "action": "{status}", "confidence": "high"}}'
                redis_client.publish('firewall-telemetry', telemetry_data)
                
        else:
            # If the sliding window is still building its state vector, 
            # allow the packet to proceed normally to prevent network latency.
            packet.accept()
            
    else:
        # Accept non-TCP/IP packets immediately to avoid breaking other network functions
        packet.accept()

if __name__ == "__main__":
    # Register shutdown signals for graceful degradation (failing-open/closed)
    signal.signal(signal.SIGINT, cleanup_iptables)
    signal.signal(signal.SIGTERM, cleanup_iptables)

    setup_iptables()

    # Bind to the queue and start processing
    nfqueue = NetfilterQueue()
    try:
        nfqueue.bind(QUEUE_NUM, process_packet)
        print("Firewall Agent running. Listening to NFQUEUE...")
        nfqueue.run()
    except Exception as e:
        print(f"Error in NFQUEUE: {e}")
    finally:
        nfqueue.unbind()
        cleanup_iptables(None, None)