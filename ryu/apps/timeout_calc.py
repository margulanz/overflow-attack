import math
from collections import defaultdict

class AdaptiveTimeoutCalculator:
    def __init__(self):
        # Configuration
        self.BASE_HARD_TIMEOUT = 30  # seconds
        self.BASE_IDLE_TIMEOUT = 10  # seconds
        self.MIN_HARD_TIMEOUT = 3
        self.MAX_HARD_TIMEOUT = 60
        self.MIN_IDLE_TIMEOUT = 2
        self.MAX_IDLE_TIMEOUT = 30
        
        # Switch capacity (adjust based on your switch)
        self.FLOW_TABLE_CAPACITY = 1000
        
        # Thresholds
        self.HIGH_OCCUPANCY_THRESHOLD = 0.8
        self.MEDIUM_OCCUPANCY_THRESHOLD = 0.6
        self.LOW_ENTROPY_THRESHOLD = 2.0  # Indicates potential attack
        self.SMALL_PACKET_THRESHOLD = 100  # bytes
        
        # Historical data
        self.flow_history = defaultdict(list)
        self.switch_metrics = {}
        self.logger = None  # Will be set by controller
        
    def calculate_timeout(self, dpid, match, packet_info, flow_stats, switch_stats):
        """
        Main timeout calculation function
        
        Args:
            dpid: Datapath ID
            match: OpenFlow match object
            packet_info: Current packet information
            flow_stats: Statistics for this specific flow (if exists)
            switch_stats: Global switch statistics
            
        Returns:
            (hard_timeout, idle_timeout) tuple
        """
        
        # Calculate three main factors
        occupancy_factor = self._calculate_occupancy_factor(switch_stats)
        traffic_factor = self._calculate_traffic_factor(switch_stats, packet_info)
        flow_factor = self._calculate_flow_factor(flow_stats, packet_info)
        
        # Calculate base timeouts with adjustments
        hard_timeout = self.BASE_HARD_TIMEOUT * occupancy_factor * traffic_factor * flow_factor
        idle_timeout = self.BASE_IDLE_TIMEOUT * occupancy_factor * traffic_factor * flow_factor
        
        # Apply protocol-specific adjustments
        hard_timeout, idle_timeout = self._apply_protocol_rules(
            hard_timeout, idle_timeout, packet_info
        )
        
        # Enforce bounds
        hard_timeout = self._clamp(hard_timeout, self.MIN_HARD_TIMEOUT, self.MAX_HARD_TIMEOUT)
        idle_timeout = self._clamp(idle_timeout, self.MIN_IDLE_TIMEOUT, self.MAX_IDLE_TIMEOUT)
        
        # Ensure idle_timeout < hard_timeout
        if idle_timeout >= hard_timeout:
            idle_timeout = hard_timeout * 0.5
        
        return int(hard_timeout), int(idle_timeout)
    
    def _calculate_occupancy_factor(self, switch_stats):
        """
        Factor 1: Flow Table Occupancy
        
        Logic:
        """
        occupancy = switch_stats.get('table_occupancy', 0)
        capacity = self.FLOW_TABLE_CAPACITY
        occupancy_rate = float(occupancy) / capacity if capacity > 0 else 0.0
        
        if occupancy_rate > self.HIGH_OCCUPANCY_THRESHOLD:
            # Critical: Very aggressive timeout
            factor = 0.3 + (0.2 * (1 - occupancy_rate) / (1 - self.HIGH_OCCUPANCY_THRESHOLD))
            if self.logger:
                self.logger.warning("HIGH OCCUPANCY: {:.2%} - Factor: {:.2f}".format(
                    occupancy_rate, factor))
        elif occupancy_rate > self.MEDIUM_OCCUPANCY_THRESHOLD:
            # Moderate: Somewhat aggressive
            factor = 0.6 + (0.4 * (self.HIGH_OCCUPANCY_THRESHOLD - occupancy_rate) / 
                           (self.HIGH_OCCUPANCY_THRESHOLD - self.MEDIUM_OCCUPANCY_THRESHOLD))
        else:
            # Normal: Full timeout
            factor = 1.0
        
        return factor
    
    def _calculate_traffic_factor(self, switch_stats, packet_info):
        """
        Factor 2: Traffic Pattern Analysis
        
        Indicators of attack:
        - Low entropy (many similar flows)
        - High packet-in rate
        - Low average packet size
        - Low source IP diversity
        """
        factor = 1.0
        
        # Sub-factor 1: Flow Entropy
        entropy = self._calculate_flow_entropy(switch_stats)
        if entropy < self.LOW_ENTROPY_THRESHOLD:
            entropy_factor = 0.5  # Likely attack - low diversity
        elif entropy < 3.5:
            entropy_factor = 0.7
        else:
            entropy_factor = 1.0
        
        # Sub-factor 2: Packet-In Rate (high rate = potential attack)
        packet_in_rate = switch_stats.get('packet_in_rate', 0)
        if packet_in_rate > 1000:  # packets/sec
            rate_factor = 0.4
        elif packet_in_rate > 500:
            rate_factor = 0.7
        else:
            rate_factor = 1.0
        
        # Sub-factor 3: Average Packet Size
        avg_pkt_size = switch_stats.get('avg_packet_size', 1000)
        if avg_pkt_size < self.SMALL_PACKET_THRESHOLD:
            size_factor = 0.6  # Small packets = suspicious
        else:
            size_factor = 1.0
        
        # Sub-factor 4: Source IP Diversity
        src_diversity = switch_stats.get('src_ip_diversity', 1.0)
        if src_diversity > 0.9:  # Too many unique sources = spoofing
            diversity_factor = 0.5
        elif src_diversity > 0.7:
            diversity_factor = 0.7
        else:
            diversity_factor = 1.0
        
        # Combine sub-factors (weighted average)
        factor = (entropy_factor * 0.3 + 
                 rate_factor * 0.3 + 
                 size_factor * 0.2 + 
                 diversity_factor * 0.2)
        
        return factor
    
    def _calculate_flow_factor(self, flow_stats, packet_info):
        """
        Factor 3: Individual Flow Characteristics
        
        Logic:
        """
        factor = 1.0
        
        if flow_stats is None:
            # New flow - use packet info only
            packet_size = packet_info.get('size', 0)
            protocol = packet_info.get('protocol', 'unknown')
            
            if packet_size < self.SMALL_PACKET_THRESHOLD:
                factor *= 0.7
            
            if protocol == 'TCP':
                tcp_flags = packet_info.get('tcp_flags', '')
                if 'S' in tcp_flags and 'A' not in tcp_flags:
                    # SYN without ACK = potential SYN flood
                    factor *= 0.5
            
            return factor
        
        # Existing flow - analyze statistics
        packet_count = flow_stats.get('packet_count', 0)
        byte_count = flow_stats.get('byte_count', 0)
        duration = flow_stats.get('duration_sec', 1)
        
        # Sub-factor 1: Flow Activity (packets per second)
        pps = float(packet_count) / duration if duration > 0 else 0
        if pps > 100:
            activity_factor = 1.3  # Very active = legitimate
        elif pps > 10:
            activity_factor = 1.1
        elif pps < 1:
            activity_factor = 0.7  # Low activity = suspicious
        else:
            activity_factor = 1.0
        
        # Sub-factor 2: Average Packet Size
        avg_size = float(byte_count) / packet_count if packet_count > 0 else 0
        if avg_size < self.SMALL_PACKET_THRESHOLD:
            size_factor = 0.6
        elif avg_size > 500:
            size_factor = 1.2  # Large packets = legitimate data transfer
        else:
            size_factor = 1.0
        
        # Sub-factor 3: Flow Age
        if duration > 60:
            age_factor = 1.3  # Long-lived flow = legitimate
        elif duration > 30:
            age_factor = 1.1
        elif duration < 5:
            age_factor = 0.8  # Very short = suspicious
        else:
            age_factor = 1.0
        
        # Combine sub-factors
        factor = activity_factor * size_factor * age_factor
        
        return factor
    
    def _apply_protocol_rules(self, hard_timeout, idle_timeout, packet_info):
        """
        Protocol-specific adjustments
        """
        protocol = packet_info.get('protocol', 'unknown')
        
        if protocol == 'TCP':
            tcp_flags = packet_info.get('tcp_flags', '')
            
            if 'F' in tcp_flags or 'R' in tcp_flags:
                # FIN or RST - connection closing
                hard_timeout *= 0.3
                idle_timeout *= 0.3
            elif 'S' in tcp_flags and 'A' in tcp_flags:
                # SYN-ACK - established connection
                hard_timeout *= 1.2
                idle_timeout *= 1.0
            elif 'S' in tcp_flags:
                # SYN only - potential flood
                hard_timeout *= 0.5
                idle_timeout *= 0.5
            else:
                # Established TCP
                hard_timeout *= 1.1
        
        elif protocol == 'UDP':
            # UDP is connectionless - shorter timeouts
            hard_timeout *= 0.8
            idle_timeout *= 0.7
        
        elif protocol == 'ICMP':
            # ICMP is short-lived
            hard_timeout *= 0.5
            idle_timeout *= 0.5
        
        return hard_timeout, idle_timeout
    
    def _calculate_flow_entropy(self, switch_stats):
        """
        Calculate Shannon entropy of flow distribution
        
        High entropy = diverse flows (normal)
        Low entropy = similar flows (potential attack)
        """
        flow_distribution = switch_stats.get('flow_distribution', {})
        
        if not flow_distribution:
            return 3.0  # Default medium entropy
        
        total = sum(flow_distribution.values())
        if total == 0:
            return 0
        
        entropy = 0.0
        for count in flow_distribution.values():
            if count > 0:
                p = float(count) / total
                entropy -= p * math.log(p, 2)
        
        return entropy
    
    def _clamp(self, value, min_val, max_val):
        """Clamp value between min and max"""
        return max(min_val, min(value, max_val))
