#!/usr/bin/python3
import threading
import os
import random
import time
import heapq

from collections import defaultdict
from operator import itemgetter

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import config_dispatcher, main_dispatcher
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu.lib import mac, ip
from ryu.lib import hub
from ryu.ofproto import inet
from ryu.topology.api import get_switch, get_link, get_host
from ryu.app.wsgi import controllerbase
from ryu.topology import event, switches
REFERENCE_BW = 10000000
DEFAULT_BW = 10000000
MAX_PATHS = 2

class Paths(object):
    """Paths container"""

    def __init__(self, path, cost):
        self.path = path
        self.cost = cost

class Controller13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.neigh = defaultdict(dict) 
        self.bw = defaultdict(lambda: defaultdict( lambda: DEFAULT_BW)) 
        self.prev_bytes = defaultdict(lambda: defaultdict( lambda: 0)) 
        self.hosts = {} 
        self.switches = [] 
        self.arp_table = {} 
        self.path_table = {} 
        self.paths_table = {} 
        self.path_with_ports_table = {} 
        self.datapath_list = {} 
        self.path_calculation_keeper = [] 
    
    def get_bandwidth(self, path, port, index):
    	return self.bw[path[index]][port]

    def find_path_cost(self, path):
        ''' arg path is a list with all nodes in our route '''
        path_cost = []
        i = 0
        while(i < len(path) - 1):
            port1 = self.neigh[path[i]][path[i + 1]]
            bandwidth_between_two_nodes = self.get_bandwidth(path, port1, i)
            path_cost.append(bandwidth_between_two_nodes)
            i += 1
        return sum(path_cost)

    def find_paths_and_costs(self, src, dst):
    	"""
    	Implementation of Breadth-First Search (BFS)
    	Returns a list of Paths objects
    	"""

    	if src == dst:
        	return [Paths([src], 0)]

    	queue = [(src, [src])]
    	possible_paths = []

    	while queue:
        	edge, path = queue.pop(0)  # pop(0) = BFS

        	for vertex in set(self.neigh[edge]) - set(path):
            		new_path = path + [vertex]

            		if vertex == dst:
                		cost_of_path = self.find_path_cost(new_path)
                		possible_paths.append(Paths(new_path, cost_of_path))
            		else:
                		queue.append((vertex, new_path))

    	return possible_paths
 
           
    def find_n_optimal_paths(self, paths, number_of_optimal_paths = MAX_PATHS):
        '''arg paths is an list containing lists of possible paths'''
        costs = [path.cost for path in paths]
        optimal_paths_indexes = list(map(costs.index, heapq.nsmallest(number_of_optimal_paths,costs)))
        optimal_paths = [paths[op_index] for op_index in optimal_paths_indexes]
        return optimal_paths
    
    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
        Add the ports to all switches including hosts
        '''
        paths_n_ports = list()
        bar = dict()
        in_port = first_port
        for s1, s2 in zip(paths[0].path[:-1], paths[0].path[1:]):
            out_port = self.neigh[s1][s2]
            bar[s1] = (in_port, out_port)
            in_port = self.neigh[s2][s1]
        bar[paths[0].path[-1]] = (in_port, last_port)
        paths_n_ports.append(bar)
        return paths_n_ports

    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst, type, pkt):

        if (src, first_port, dst, last_port) not in self.path_calculation_keeper:
            self.path_calculation_keeper.append((src, first_port, dst, last_port))
            self.topology_discover(src, first_port, dst, last_port)
            self.topology_discover(dst, last_port, src, first_port)

        
        for node in self.path_table[(src, first_port, dst, last_port)][0].path:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            actions = []

            in_port = self.path_with_ports_table[(src, first_port, dst, last_port)][0][node][0]
            out_port = self.path_with_ports_table[(src, first_port, dst, last_port)][0][node][1]
                
            actions = [ofp_parser.OFPActionOutput(out_port)]

            if type == 'UDP':
                nw = pkt.get_protocol(ipv4.ipv4)
                l4 = pkt.get_protocol(udp.udp)
                match = ofp_parser.OFPMatch(in_port = in_port, eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst = ip_dst,  
                				ip_proto=inet.IPPROTO_UDP, udp_src = l4.src_port, udp_dst = l4.dst_port)
                self.add_flow(dp, 33333, match, actions, 10)
            
            elif type == 'TCP':
                nw = pkt.get_protocol(ipv4.ipv4)
                l4 = pkt.get_protocol(tcp.tcp)
                match = ofp_parser.OFPMatch(in_port = in_port,eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst = ip_dst, 
                                        ip_proto=inet.IPPROTO_TCP,tcp_src = l4.src_port, tcp_dst = l4.dst_port)
                self.add_flow(dp, 44444, match, actions, 10)

            elif type == 'ICMP':
                nw = pkt.get_protocol(ipv4.ipv4)
                match = ofp_parser.OFPMatch(in_port=in_port,
                                        eth_type=ether_types.ETH_TYPE_IP, 
                                        ipv4_src=ip_src, 
                                        ipv4_dst = ip_dst, 
                                        ip_proto=inet.IPPROTO_ICMP)
                self.add_flow(dp, 22222, match, actions, 10)

            elif type == 'ARP':
                match_arp = ofp_parser.OFPMatch(in_port = in_port,eth_type=ether_types.ETH_TYPE_ARP, arp_spa=ip_src, arp_tpa=ip_dst)
                self.add_flow(dp, 1, match_arp, actions, 10)
        
        return self.path_with_ports_table[(src, first_port, dst, last_port)][0][src][1]

    def add_flow(self, datapath, priority, match, actions, idle_timeout, buffer_id = None):
        ''' Method Provided by the source Ryu library.'''
        
        ofproto = datapath.ofproto 
        parser = datapath.ofproto_parser 

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, idle_timeout = idle_timeout,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout = idle_timeout, instructions=inst)
        datapath.send_msg(mod)
    
    def run_check(self, ofp_parser, dp):
        threading.Timer(1.0, self.run_check, args=(ofp_parser, dp)).start()
        
        req = ofp_parser.OFPPortStatsRequest(dp) 
        dp.send_msg(req)

    def topology_discover(self, src, first_port, dst, last_port):
        threading.Timer(1.0, self.topology_discover, args=(src, first_port, dst, last_port)).start()
        paths = self.find_paths_and_costs(src, dst)
        path = self.find_n_optimal_paths(paths)
        path_with_port = self.add_ports_to_paths(path, first_port, last_port)
        
        
        self.paths_table[(src, first_port, dst, last_port)]  = paths
        self.path_table[(src, first_port, dst, last_port)] = path
        self.path_with_ports_table[(src, first_port, dst, last_port)] = path_with_port


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            nw = pkt.get_protocol(ipv4.ipv4)
            if nw.proto == inet.IPPROTO_UDP:
                l4 = pkt.get_protocol(udp.udp)
            elif nw.proto == inet.IPPROTO_TCP:
                l4 = pkt.get_protocol(tcp.tcp)     

        if eth.ethertype == ether_types.ETH_TYPE_IP and nw.proto == inet.IPPROTO_UDP:
            src_ip = nw.src
            dst_ip = nw.dst
            
            self.arp_table[src_ip] = src
            h1 = self.hosts[src]
            h2 = self.hosts[dst]


            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'UDP', pkt)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'UDP', pkt) 
        
        elif eth.ethertype == ether_types.ETH_TYPE_IP and nw.proto == inet.IPPROTO_TCP:
            src_ip = nw.src
            dst_ip = nw.dst
            
            self.arp_table[src_ip] = src
            h1 = self.hosts[src]
            h2 = self.hosts[dst]


            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'TCP', pkt)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'TCP', pkt) 

        elif eth.ethertype == ether_types.ETH_TYPE_IP and nw.proto == inet.IPPROTO_ICMP:
            src_ip = nw.src
            dst_ip = nw.dst
            
            self.arp_table[src_ip] = src
            h1 = self.hosts[src]
            h2 = self.hosts[dst]


            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'ICMP', pkt)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'ICMP', pkt)

        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]


                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'ARP', pkt)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'ARP', pkt) 

            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]


                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'ARP', pkt)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'ARP', pkt)

        actions = [parser.OFPActionOutput(out_port)]
        
        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, 
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        ''' 
        To send packets for which we dont have right information to the controller
        Method Provided by the source Ryu library. 
        '''

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 10)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        '''Reply to the OFPPortStatsRequest, visible beneath'''
        switch_dpid = ev.msg.datapath.id
        for p in ev.msg.body:
            self.bw[switch_dpid][p.port_no] = (p.tx_bytes - self.prev_bytes[switch_dpid][p.port_no])*8.0/1000000 
            self.prev_bytes[switch_dpid][p.port_no] = p.tx_bytes

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch_dp = ev.switch.dp
        switch_dpid = switch_dp.id
        ofp_parser = switch_dp.ofproto_parser
        
            
        if switch_dpid not in self.switches:
            self.datapath_list[switch_dpid] = switch_dp
            self.switches.append(switch_dpid)

            self.run_check(ofp_parser, switch_dp) 

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        switch = ev.switch.dp.id
        if switch in self.switches:
            try:
                self.switches.remove(switch)
                del self.datapath_list[switch]
                del self.neigh[switch]
            except KeyError:
                pass 

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        self.neigh[ev.link.src.dpid][ev.link.dst.dpid] = ev.link.src.port_no
        self.neigh[ev.link.dst.dpid][ev.link.src.dpid] = ev.link.dst.port_no

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        try:
            del self.neigh[ev.link.src.dpid][ev.link.dst.dpid] 
            del self.neigh[ev.link.dst.dpid][ev.link.src.dpid] 
        except KeyError:
            pass
