import time
import math
from collections import defaultdict
from scapy.all import IP, TCP, UDP
from .features import calculate_shannon_entropy, extract_statistical_features, normalize_vector

class Flow:
    def __init__(self, src_ip=None):
        self.packet_sizes = []
        self.arrival_times = []
        self.payload_entropies = []
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.src_ip = src_ip  # Track source IP for DOS metrics
        
    def add_packet(self, packet, payload):
        current_time = time.time()
        self.arrival_times.append(current_time)
        self.packet_sizes.append(len(packet))
        
        if payload:
            self.payload_entropies.append(calculate_shannon_entropy(bytes(payload)))
            
        self.last_seen = current_time

class FlowManager:
    def __init__(self, window_size=100, timeout=120):
        # Flow table keyed by normalized 5-tuple.
        self.active_flows = defaultdict(Flow)
        self.window_size = window_size
        self.timeout = timeout
        
        # Global DOS metrics: track per-source IP statistics
        # source_metrics[src_ip] = {
        #   'connection_count': int,
        #   'pps_samples': [pps1, pps2, ...],  # last 10 samples
        #   'last_update': timestamp
        # }
        self.source_metrics = defaultdict(lambda: {
            'connection_count': 0,
            'pps_samples': [],
            'last_update': time.time()
        })

    def _generate_flow_key(self, packet) -> tuple:
        """
        Classically defines a flow by its 5-tuple.
        Returns (flow_key, src_ip) tuple.
        """
        if packet.haslayer(IP):
            src, dst = packet[IP].src, packet[IP].dst
            proto = packet[IP].proto
            sport, dport = 0, 0
            
            if packet.haslayer(TCP):
                sport, dport = packet[TCP].sport, packet[TCP].dport
            elif packet.haslayer(UDP):
                sport, dport = packet[UDP].sport, packet[UDP].dport
                
            # Sort endpoints so both directions map to the same key.
            endpoints = sorted([f"{src}:{sport}", f"{dst}:{dport}"])
            flow_key = f"{endpoints[0]}-{endpoints[1]}-{proto}"
            return flow_key, src
        return None, None

    def process_packet(self, packet):
        """
        Ingests a packet, updates flow state, and returns (State Vector, is_terminal).
        """
        key, src_ip = self._generate_flow_key(packet)
        if not key:
            return None, False
        
        # Create flow if new, passing source IP for metrics tracking
        if key not in self.active_flows:
            self.active_flows[key] = Flow(src_ip=src_ip)
            self._update_source_metrics(src_ip, 'add')
            
        flow = self.active_flows[key]
        
        payload = packet[TCP].payload if packet.haslayer(TCP) else None
        flow.add_packet(packet, payload)
        
        # Detect TCP teardown or reset.
        is_terminal = False
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if 'F' in flags or 'R' in flags:
                is_terminal = True
        
        # Emit state when window completes or flow terminates.
        if len(flow.packet_sizes) >= self.window_size or is_terminal:
            state_vector = self._compile_state_vector(flow)
            
            if is_terminal:
                self._update_source_metrics(src_ip, 'remove')
                del self.active_flows[key]
            else:
                flow.packet_sizes = []
                flow.arrival_times = []
                flow.payload_entropies = []
                
            return state_vector, is_terminal
            
        return None, False

    def _compile_state_vector(self, flow: Flow) -> list:
        """
        Transforms raw flow data into a 16-dimensional state vector
        (extended from 12 dims to include DOS indicators).
        
        Dims 0-11: Original features (timing, packet sizes, entropy, volume)
        Dims 12-15: DOS indicators (flow pps, bytes/sec ratio, source conn density, synchronized flag)
        """
        iats = [j - i for i, j in zip(flow.arrival_times[:-1], flow.arrival_times[1:])]
        iat_stats = extract_statistical_features(iats)
        
        size_stats = extract_statistical_features(flow.packet_sizes)
        
        entropy_stats = extract_statistical_features(flow.payload_entropies)
        
        duration = flow.arrival_times[-1] - flow.arrival_times[0] if len(flow.arrival_times) > 1 else 0.001
        throughput = sum(flow.packet_sizes) / duration
        
        # Shift autocorrelation from [-1, 1] to [0, 1].
        normalized_autocorr = (iat_stats["autocorr"] + 1.0) / 2.0

        if math.isnan(normalized_autocorr):
            normalized_autocorr = 0.5

        # Original 12-dimensional state vector
        raw_vector = [
            iat_stats["mean"], 
            iat_stats["std"], 
            normalized_autocorr,
            size_stats["mean"], 
            size_stats["std"], 
            size_stats["max"], 
            size_stats["iqr"],
            entropy_stats["mean"], 
            entropy_stats["var"],
            duration, 
            throughput, 
            len(flow.packet_sizes)
        ]
        
        # DOS indicators (dims 12-15)
        flow_pps = len(flow.packet_sizes) / duration if duration > 0 else 0.0
        bytes_per_sec_ratio = throughput / max(len(flow.packet_sizes), 1) if len(flow.packet_sizes) > 0 else 0.0
        source_conn_density = self._get_source_conn_density(flow.src_ip)
        synchronized_flag = 1.0 if self._is_synchronized_attack(flow.src_ip, flow_pps) else 0.0
        
        raw_vector.extend([
            flow_pps,
            bytes_per_sec_ratio,
            source_conn_density,
            synchronized_flag
        ])
        
        # Normalization maxima for all 16 dimensions
        max_values = [
            1.0, 1.0, 1.0,                    # IAT: mean, std, autocorr
            1500, 500, 1500, 1500,            # Packet sizes: mean, std, max, IQR
            1.0, 1.0,                          # Entropy: mean, var
            60.0, 1000000, self.window_size,   # Duration, throughput, pkt_count
            1000, 100, 50, 1.0                 # DOS: pps, bytes/sec ratio, conn density, sync flag
        ]
        
        return normalize_vector(raw_vector, max_values)

    def _update_source_metrics(self, src_ip: str, operation: str):
        """
        Update global metrics for a source IP.
        operation: 'add' (flow started) or 'remove' (flow ended)
        """
        if not src_ip:
            return
            
        if operation == 'add':
            self.source_metrics[src_ip]['connection_count'] += 1
        elif operation == 'remove':
            self.source_metrics[src_ip]['connection_count'] = max(
                0, self.source_metrics[src_ip]['connection_count'] - 1
            )
        
        self.source_metrics[src_ip]['last_update'] = time.time()
        
        # Prune metrics older than 30 seconds
        current_time = time.time()
        stale_sources = [
            ip for ip, metrics in self.source_metrics.items()
            if (current_time - metrics['last_update']) > 30
        ]
        for ip in stale_sources:
            del self.source_metrics[ip]
    
    def _get_source_pps(self, src_ip: str, window_sec=10) -> float:
        """
        Compute packets-per-second for all flows from src_ip in the last window_sec seconds.
        """
        if not src_ip or src_ip not in self.source_metrics:
            return 0.0
        
        # Aggregate pps from all active flows from this source
        total_pps = 0.0
        current_time = time.time()
        
        for key, flow in self.active_flows.items():
            if flow.src_ip == src_ip:
                duration = current_time - flow.start_time
                if duration > 0:
                    pps = len(flow.packet_sizes) / duration
                    total_pps += pps
                    
                    # Store sample for later analysis
                    if len(self.source_metrics[src_ip]['pps_samples']) >= 10:
                        self.source_metrics[src_ip]['pps_samples'].pop(0)
                    self.source_metrics[src_ip]['pps_samples'].append(pps)
        
        return total_pps
    
    def _get_source_conn_density(self, src_ip: str) -> float:
        """
        Normalized connection density: concurrent connections from src_ip.
        Threshold: 50 concurrent connections = 1.0
        """
        if not src_ip or src_ip not in self.source_metrics:
            return 0.0
        
        conn_count = self.source_metrics[src_ip]['connection_count']
        normalized = min(1.0, conn_count / 50.0)
        return normalized
    
    def _is_synchronized_attack(self, src_ip: str, flow_pps: float, global_pps_threshold=5000) -> bool:
        """
        Detect DDoS pattern: synchronized attack across multiple flows.
        Returns True if:
        - Global source PPS > 5000 AND
        - Current flow PPS > 100 AND
        - Connection count > 5 (distributed across flows)
        """
        if not src_ip or src_ip not in self.source_metrics:
            return False
        
        conn_count = self.source_metrics[src_ip]['connection_count']
        if conn_count < 5:
            return False
        
        global_pps = self._get_source_pps(src_ip)
        if global_pps > global_pps_threshold and flow_pps > 100:
            return True
        
        return False

    def garbage_collection(self):
        """Flushes flows that have exceeded predefined inactivity timeouts."""
        current_time = time.time()
        stale_keys = [k for k, v in self.active_flows.items() if (current_time - v.last_seen) > self.timeout]
        for k in stale_keys:
            del self.active_flows[k]