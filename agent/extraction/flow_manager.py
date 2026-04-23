import time
from collections import defaultdict
from scapy.all import IP, TCP, UDP
from .features import calculate_shannon_entropy, extract_statistical_features, normalize_vector

class Flow:
    def __init__(self):
        self.packet_sizes = []
        self.arrival_times = []
        self.payload_entropies = []
        self.start_time = time.time()
        self.last_seen = self.start_time
        
    def add_packet(self, packet, payload):
        current_time = time.time()
        self.arrival_times.append(current_time)
        self.packet_sizes.append(len(packet))
        
        if payload:
            self.payload_entropies.append(calculate_shannon_entropy(bytes(payload)))
            
        self.last_seen = current_time

class FlowManager:
    def __init__(self, window_size=100, timeout=120):
        # Bidirectional hash table for flow tracking
        self.active_flows = defaultdict(Flow)
        self.window_size = window_size
        self.timeout = timeout # Seconds before garbage collection

    def _generate_flow_key(self, packet) -> str:
        """Classically defines a flow by its 5-tuple."""
        if packet.haslayer(IP):
            src, dst = packet[IP].src, packet[IP].dst
            proto = packet[IP].proto
            sport, dport = 0, 0
            
            if packet.haslayer(TCP):
                sport, dport = packet[TCP].sport, packet[TCP].dport
            elif packet.haslayer(UDP):
                sport, dport = packet[UDP].sport, packet[UDP].dport
                
            # Sort endpoints to ensure bidirectionality maps to the same key
            endpoints = sorted([f"{src}:{sport}", f"{dst}:{dport}"])
            return f"{endpoints[0]}-{endpoints[1]}-{proto}"
        return None

    def process_packet(self, packet):
        """
        Ingests a packet, updates flow state, and returns (State Vector, is_terminal).
        """
        key = self._generate_flow_key(packet)
        if not key:
            return None, False
            
        flow = self.active_flows[key]
        
        # Extract raw payload
        payload = packet[TCP].payload if packet.haslayer(TCP) else None
        flow.add_packet(packet, payload)
        
        # NEW: Check for TCP flow termination flags
        is_terminal = False
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            # 'F' = FIN (graceful teardown), 'R' = RST (abrupt connection reset)
            if 'F' in flags or 'R' in flags:
                is_terminal = True
        
        # Check if sliding window epoch is reached OR the flow is suddenly terminated
        if len(flow.packet_sizes) >= self.window_size or is_terminal:
            state_vector = self._compile_state_vector(flow)
            
            if is_terminal:
                # Aggressive garbage collection: delete from memory immediately 
                del self.active_flows[key]
            else:
                # Reset the sliding window for this ongoing flow
                flow.packet_sizes = []
                flow.arrival_times = []
                flow.payload_entropies = []
                
            return state_vector, is_terminal
            
        return None, False

    def _compile_state_vector(self, flow: Flow) -> list:
        """
        Transforms raw flow data into a 12-dimensional state vector
        required by the DQN agent.
        """
        # 1. Timing Dynamics (Inter-Arrival Times)
        iats = [j - i for i, j in zip(flow.arrival_times[:-1], flow.arrival_times[1:])]
        iat_stats = extract_statistical_features(iats)
        
        # 2. Size Distributions
        size_stats = extract_statistical_features(flow.packet_sizes)
        
        # 3. Payload Entropy
        entropy_stats = extract_statistical_features(flow.payload_entropies)
        
        # 4. Flow Volumetrics
        duration = flow.arrival_times[-1] - flow.arrival_times[0] if len(flow.arrival_times) > 1 else 0.001
        throughput = sum(flow.packet_sizes) / duration
        
        # Autocorrelation ranges from -1 to 1. Shift it to 0.0 -> 1.0 for the neural net
        normalized_autocorr = (iat_stats["autocorr"] + 1.0) / 2.0

        # Construct raw 12-dimensional vector 
        raw_vector = [
            iat_stats["mean"], 
            iat_stats["std"], 
            normalized_autocorr,          # NEW: IAT Autocorrelation
            size_stats["mean"], 
            size_stats["std"], 
            size_stats["max"], 
            size_stats["iqr"],            # NEW: Size IQR
            entropy_stats["mean"], 
            entropy_stats["var"],         # REPLACED: Entropy Variance
            duration, 
            throughput, 
            len(flow.packet_sizes)
        ]
        
        # Heuristic maximums for normalization (must match the 12 dimensions above)
        max_values = [
            1.0, 1.0, 1.0,                  # IAT (Autocorr is already pre-normalized)
            1500, 500, 1500, 1500,          # Size (1500 is standard ethernet MTU)
            1.0, 1.0,                       # Entropy
            60.0, 1000000, self.window_size # Volumetrics
        ]
        
        return normalize_vector(raw_vector, max_values)

    def garbage_collection(self):
        """Flushes flows that have exceeded predefined inactivity timeouts."""
        current_time = time.time()
        stale_keys = [k for k, v in self.active_flows.items() if (current_time - v.last_seen) > self.timeout]
        for k in stale_keys:
            del self.active_flows[k]