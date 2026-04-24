import time
import random
import socket
from scapy.all import IP, TCP, UDP, Raw

# Target localhost so packets loop back into the INPUT chain
TARGET_IP = "127.0.0.1" 

MALICIOUS_IPS = ["192.168.1.100", "10.0.0.50", "172.16.0.23"]

def create_raw_socket():
    """
    Using a Layer 3 (AF_INET) raw socket bypasses Ethernet and injects 
    directly into the routing stack, ensuring iptables catches it.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    return s

def build_benign_traffic():
    print("Compiling benign payload sequences...")
    packets = []
    for _ in range(100):
        src_ip = f"10.0.0.{random.randint(100, 200)}"
        # Notice we removed the Ether() layer completely
        pkt = IP(src=src_ip, dst=TARGET_IP) / \
              TCP(sport=random.randint(1024, 65535), dport=80, flags="PA") / \
              Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        packets.append(bytes(pkt))
    return packets

def build_syn_flood():
    print("Compiling malicious SYN flood sequences...")
    packets = []
    for _ in range(500):
        src_ip = random.choice(MALICIOUS_IPS)
        pkt = IP(src=src_ip, dst=TARGET_IP) / \
              TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        packets.append(bytes(pkt))
    return packets

def build_high_entropy_exfiltration():
    print("Compiling high-entropy data exfiltration sequences...")
    packets = []
    for _ in range(50):
        src_ip = MALICIOUS_IPS[0]
        encrypted_payload = bytes([random.randint(0, 255) for _ in range(120)])
        # Changed to TCP dport 80 to match the iptables rule in main.py
        # This simulates an attacker tunneling commands through HTTP
        pkt = IP(src=src_ip, dst=TARGET_IP) / \
              TCP(sport=random.randint(1024, 65535), dport=80, flags="PA") / \
              Raw(encrypted_payload)
        packets.append(bytes(pkt))
    return packets

def blast_traffic(sock, packets, duration, description):
    print(f"\n[*] Starting Phase: {description}...")
    end_time = time.time() + duration
    count = 0
    
    while time.time() < end_time:
        for pkt in packets:
            # L3 sockets require sendto() with the target IP
            sock.sendto(pkt, (TARGET_IP, 0))
            count += 1
            
    pps = count / duration
    print(f"[+] Complete. Sent {count:,} packets in {duration}s (~{pps:,.0f} PPS).")

if __name__ == "__main__":
    print("=== Reinforcement Learning Firewall: Synthetic Traffic Simulator ===")
    try:
        raw_socket = create_raw_socket()
        
        benign_pkts = build_benign_traffic()
        syn_flood_pkts = build_syn_flood()
        entropy_pkts = build_high_entropy_exfiltration()
        
        print("\nCommencing network simulation...")
        
        blast_traffic(raw_socket, benign_pkts, duration=5, description="Benign Web Browsing")
        time.sleep(2)
        
        blast_traffic(raw_socket, syn_flood_pkts, duration=3, description="Volumetric SYN Flood Attack")
        time.sleep(2)
        
        blast_traffic(raw_socket, benign_pkts, duration=5, description="Benign Web Browsing")
        blast_traffic(raw_socket, entropy_pkts, duration=4, description="High-Entropy Encrypted C2 Exfiltration")
        
        print("\n=== Simulation Complete ===")
        
    except PermissionError:
        print("[!] ERROR: AF_INET raw sockets require elevated privileges. Please run with 'sudo'.")