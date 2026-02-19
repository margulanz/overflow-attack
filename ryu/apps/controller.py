# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import math
import time
import csv
import json
import os
import psutil
import signal
import atexit
from collections import defaultdict, deque
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub

METRICS_LOCK = "/results/.metrics_written"

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    metrics_written = False
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        # flow statistics
        self.flow_stats = defaultdict(lambda: {
            "packet_count": 0,
            "last_seen": None,
            "iat_window": deque(maxlen=10),  # inter-arrival samples
        })
        
        # --- Parameters (thesis-controlled) ---
        self.T_MIN = 1
        self.T_MAX = 60 
        self.ALPHA = 2.0 # packet count weight
        self.BETA = 5.0 # activity weight
        self.DELTA = 10.0 # congestion penalty
        self.GAMMA = 1.5 # latency safety factor

        self.TCAM_MAX = 1000
        
        # --- Evaluation Metrics ---
        self.packet_in_count = 0
        self.rejected_flows = 0
        self.start_time = time.time()
        self.metrics = []
        
        # --- Monitoring Thread --- 
        self.monitor_thread = hub.spawn(self._monitor)
        self.process = psutil.Process(os.getpid())
        self.process.cpu_percent(interval=None)
                    
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        atexit.register(self._write_metrics)
    @set_ev_cls(ofp_event.EventOFPStateChange,
            [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        match = ev.msg.match
        in_port = match.get('in_port')
        eth_src = match.get('eth_src')
        eth_dst = match.get('eth_dst')

        if in_port and eth_src and eth_dst:
            key = (eth_src, eth_dst, in_port)
            self.flow_stats.pop(key, None)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self._write_metrics()
    def _monitor(self):
		while True:
		    for dp in self.datapaths.values():
		        self._request_stats(dp)
		        
		    hub.sleep(.5)  # sample every 1 second
		    self._collect_metrics()
    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        for stat in ev.msg.body:

            # Only consider your installed flows (priority 1)
            if stat.priority != 1:
                continue

            match = stat.match

            if ('eth_src' in match and
                'eth_dst' in match and
                'in_port' in match):

                flow_id = (
                    match['eth_src'],
                    match['eth_dst'],
                    match['in_port']
                )
                self.logger.info(stat.packet_count)
                if flow_id in self.flow_stats:
                    self.flow_stats[flow_id]["packet_count"] = stat.packet_count
    def _collect_metrics(self):
		now = time.time() - self.start_time
		#process = psutil.Process(os.getpid())
		record = {
		    "time": round(now, 2),
		    "table_occupancy": len(self.flow_stats),
		    "packet_in_count": self.packet_in_count,
		    "rejected_flows": self.rejected_flows,
		    "cpu_percent": self.process.cpu_percent(interval=None),
		    "memory_mb": self.process.memory_info().rss / (1024 * 1024),
		}
		#self.logger.info(record)
		self.metrics.append(record)
   
    def compute_idle_timeout(self, flow_id):
		stats = self.flow_stats[flow_id]

		N_k = stats["packet_count"]

		if len(stats["iat_window"]) == 0:
		    mean_iat = 1.0
		else:
		    mean_iat = sum(stats["iat_window"]) / len(stats["iat_window"])

		# Approximate TCAM occupancy
		table_occ = len(self.flow_stats)
		occ_ratio = min(table_occ / self.TCAM_MAX, 1.0)

		# --- Core adaptive equation ---
		base_timeout = (
		    self.ALPHA * (math.log(1 + N_k))
		    + self.BETA * (1.0 / mean_iat)
		    - self.DELTA * occ_ratio
		)

		latency_guard = self.GAMMA * mean_iat

		T = max(
		    self.T_MIN,
		    min(self.T_MAX, base_timeout),
		    latency_guard
		)

		return int(T)
     
        
        
	
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    def _write_metrics(self):
        self.logger.info("Writing metrics into results folder")
		# ---- GLOBAL PROCESS-LEVEL GUARD ----
        if os.path.exists(METRICS_LOCK):
		    return
        
		# create lock immediately
        with open(METRICS_LOCK, "w") as f:
		    f.write("written")
        
        if not self.metrics:
		    return
        
        with open("/results/metrics.json", "w") as f:
		    json.dump(self.metrics, f, indent=2)
        
        with open("/results/metrics.csv", "w") as f:
            writer = csv.DictWriter(f, fieldnames=self.metrics[0].keys())
            writer.writeheader()
            writer.writerows(self.metrics)
        
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=ofproto.OFPFF_SEND_FLOW_REM)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
    	#self.packet_in_count += 1
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        flow_id = (src, dst, in_port)
        if flow_id not in self.flow_stats and len(self.flow_stats) >= self.TCAM_MAX:
            self.rejected_flows += 1
            return
        now = time.time()
        flow = self.flow_stats[flow_id]
        #flow["packet_count"] += 1
        if flow["last_seen"] is not None:
        	iat = now - flow["last_seen"]
        	flow["iat_window"].append(iat)
        	
        flow["last_seen"] = now
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            idle_timeout = 5#self.compute_idle_timeout(flow_id)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=idle_timeout,  hard_timeout=10)
                return
            else:
                self.add_flow(datapath, 1, match, actions,idle_timeout=idle_timeout, hard_timeout=10)
            #self.logger.info("adding new flow!")
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
