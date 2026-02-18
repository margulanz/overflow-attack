from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp
from ryu.lib import hub
from collections import defaultdict
import time
from timeout_calc import AdaptiveTimeoutCalculator
class AdaptiveTimeoutController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(AdaptiveTimeoutController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        
        # Initialize timeout calculator
        self.timeout_calculator = AdaptiveTimeoutCalculator()
        self.timeout_calculator.logger = self.logger
        
        # Metrics storage
        self.flow_stats = defaultdict(dict)
        self.switch_stats = defaultdict(lambda: {
            'table_occupancy': 0,
            'table_capacity': 1000,
            'occupancy_rate': 0.0,
            'packet_in_rate': 0.0,
            'flow_entropy': 3.0,
            'src_ip_diversity': 0.5,
            'avg_packet_size': 1000,
            'flow_distribution': {},
            'timestamp': time.time()
        })
        self.packet_in_count = defaultdict(int)
        self.packet_in_timestamps = defaultdict(list)
        self.flow_table_size = defaultdict(int)
        self.source_ips = defaultdict(set)
        self.packet_sizes = defaultdict(list)
        
        # Start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor_loop)
    
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == 'DEAD_DISPATCHER':
            if datapath.id in self.datapaths:
                self.logger.info('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    def _monitor_loop(self):
        """Periodic monitoring and statistics collection"""
        while True:
            for dpid, dp in self.datapaths.items():
                self._request_flow_stats(dp)
                self._update_switch_metrics(dpid)
            hub.sleep(5)  # Collect stats every 5 seconds
    
    def _request_flow_stats(self, datapath):
        """Request flow statistics from switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPFlowStatsRequest(datapath, table_id=0)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply"""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        # Update table occupancy
        body = [stat for stat in body if stat.table_id == 0]
        self.flow_table_size[dpid] = len(body)
        
        # Store flow statistics and calculate distribution
        flow_distribution = defaultdict(int)
        
        for stat in body:
            flow_key = self._create_flow_key(dpid, stat.match)
            self.flow_stats[flow_key] = {
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'duration_sec': stat.duration_sec,
                'duration_nsec': stat.duration_nsec
            }
            
            # Track flow distribution for entropy calculation
            match_tuple = str(stat.match)
            flow_distribution[match_tuple] += 1
        
        # Update switch stats with flow distribution
        self.switch_stats[dpid]['flow_distribution'] = dict(flow_distribution)
        
        self.logger.info('Datapath %016x - Flow Table Occupancy: %d flows',
                        dpid, self.flow_table_size.get(dpid, 0))
    
    def _update_switch_metrics(self, dpid):
        """Update switch-level metrics"""
        current_time = time.time()
        
        # Calculate packet-in rate
        timestamps = self.packet_in_timestamps[dpid]
        recent_timestamps = [t for t in timestamps if current_time - t < 10]
        packet_in_rate = float(len(recent_timestamps)) / 10.0 if recent_timestamps else 0.0
        self.packet_in_timestamps[dpid] = recent_timestamps
        
        # Calculate occupancy rate
        table_occupancy = self.flow_table_size.get(dpid, 0)
        occupancy_rate = float(table_occupancy) / 1000.0  # Assuming 1000 max flows
        
        # Calculate source IP diversity
        total_sources = len(self.source_ips[dpid])
        src_diversity = min(1.0, float(total_sources) / 100.0) if total_sources > 0 else 0.5
        
        # Calculate average packet size
        recent_sizes = self.packet_sizes[dpid][-1000:]  # Last 1000 packets
        avg_packet_size = sum(recent_sizes) / float(len(recent_sizes)) if recent_sizes else 1000
        
        # Calculate flow entropy
        flow_entropy = self.timeout_calculator._calculate_flow_entropy(self.switch_stats[dpid])
        
        # Store metrics
        self.switch_stats[dpid].update({
            'table_occupancy': table_occupancy,
            'table_capacity': 1000,
            'occupancy_rate': occupancy_rate,
            'packet_in_rate': packet_in_rate,
            'flow_entropy': 0,
            'src_ip_diversity': src_diversity,
            'avg_packet_size': avg_packet_size,
            'timestamp': current_time
        })
        
        self.logger.info("Switch %016x: Occupancy=%.2f%%, PacketIn Rate=%.1f/s, Entropy=%.2f",
                        dpid, occupancy_rate * 100, packet_in_rate, 0)
    
    def _create_flow_key(self, dpid, match):
        """Create a unique key for flow identification"""
        return (dpid, str(match))
    
    def _get_tcp_flags(self, tcp_pkt):
        """Extract TCP flags as string"""
        flags = ""
        if tcp_pkt.bits & 0x01:  # FIN
            flags += "F"
        if tcp_pkt.bits & 0x02:  # SYN
            flags += "S"
        if tcp_pkt.bits & 0x04:  # RST
            flags += "R"
        if tcp_pkt.bits & 0x08:  # PSH
            flags += "P"
        if tcp_pkt.bits & 0x10:  # ACK
            flags += "A"
        if tcp_pkt.bits & 0x20:  # URG
            flags += "U"
        return flags
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # Track packet-in rate
        self.packet_in_count[dpid] += 1
        self.packet_in_timestamps[dpid].append(time.time())
        self.packet_sizes[dpid].append(len(msg.data))
        
        # Extract packet information
        packet_info = {
            'size': len(msg.data),
            'protocol': 'unknown',
            'tcp_flags': ''      
        }

        # Parse protocol details
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            packet_info['src_ip'] = ip_pkt.src
            packet_info['dst_ip'] = ip_pkt.dst
            self.source_ips[dpid].add(ip_pkt.src) 
            if ip_pkt.proto == 6:  # TCP
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    packet_info['protocol'] = 'TCP'
                    packet_info['tcp_flags'] = self._get_tcp_flags(tcp_pkt)
                    packet_info['src_port'] = tcp_pkt.src_port
                    packet_info['dst_port'] = tcp_pkt.dst_port
            
            elif ip_pkt.proto == 17:  # UDP
                packet_info['protocol'] = 'UDP'
                udp_pkt = pkt.get_protocol(udp.udp)
                if udp_pkt:
                    packet_info['src_port'] = udp_pkt.src_port
                    packet_info['dst_port'] = udp_pkt.dst_port
            
            elif ip_pkt.proto == 1:  # ICMP
                packet_info['protocol'] = 'ICMP'

        self.mac_to_port.setdefault(dpid, {})
        self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)

        # Learn MAC address
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        # Install flow with adaptive timeout
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            # Get flow statistics (if exists)
            flow_key = self._create_flow_key(dpid, match)
            flow_stats = self.flow_stats.get(flow_key, None)
            
           # # Calculate adaptive timeout
            hard_timeout, idle_timeout = self.timeout_calculator.calculate_timeout(
                dpid=dpid,
                match=match,
                packet_info=packet_info,
                flow_stats=flow_stats,
                switch_stats=self.switch_stats[dpid]
                )
            
            #Log timeout decision
            self.logger.info("Flow timeout: hard=%ds, idle=%ds (protocol=%s, size=%dB)",
                              hard_timeout, idle_timeout,
                                            packet_info['protocol'], packet_info['size'])
            
            # # Verify that packet has a buffer_id
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, 
                                              hard_timeout, idle_timeout, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions,
                                                   hard_timeout, idle_timeout)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, 
                 hard_timeout=0, idle_timeout=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,
                                    hard_timeout=hard_timeout,
                                    idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    hard_timeout=hard_timeout,
                                    idle_timeout=idle_timeout)
        datapath.send_msg(mod)
