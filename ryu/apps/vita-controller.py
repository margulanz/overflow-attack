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
from oslo_config import cfg
from collections import defaultdict, deque
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub
import os

MODE = os.environ.get('MODE', 'adaptive')
FIXED_TIMEOUT = int(os.environ.get('FIXED_TIMEOUT', '5'))


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    metrics_written = False
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.mode = MODE
        self.fixed_timeout = FIXED_TIMEOUT

        self.logger.info("Controller mode: %s", self.mode)

        if self.mode == "fixed":
            self.logger.info("Fixed timeout: %d", self.fixed_timeout)
        # flow statistics
        self.flow_stats = defaultdict(lambda: {
			# --- VITA core metrics ---
			"npacketIn": 0,
			"tpacketIn": None,
			"tlastRemoved": None,
			"tlastDuration": None,

			# --- Runtime tracking ---
			"packet_count": 0,
			"last_seen": None,
			"iat_window": deque(maxlen=10)
		})
        self.TCAM_MAX = 1000
        # VITA parameters
        self.t_init = 2
        self.t_max = 32
        self.t_max_restore = 32
        self.min_t_max = 10

        self.TCAM_lowerbound = 0.4 * self.TCAM_MAX
        self.TCAM_upperbound = 0.8 * self.TCAM_MAX

        self.coef_w = 0.75
        self.B = 2
        
        
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
		    hub.sleep(.5)  # sample every 1 second
		    for dp in self.datapaths.values():
		        self._request_stats(dp)
		    self._collect_metrics()
		    
    def _collect_metrics(self):
		now = time.time() - self.start_time
		record = {
		    "time": round(now, 2),
		    "table_occupancy": len(self.flow_stats),
		    "packet_in_count": self.packet_in_count,
		    "rejected_flows": self.rejected_flows,
		    "cpu_percent": self.process.cpu_percent(interval=None),
		    "memory_mb": self.process.memory_info().rss / (1024 * 1024),
		}
		self.logger.info(record)
		self.metrics.append(record)
   
    def compute_idle_timeout(self, flow_id):
        stats = self.flow_stats[flow_id]
        now = time.time()

        npacketIn = stats["npacketIn"]
        tpacketIn = stats["tpacketIn"]
        tlastRemoved = stats["tlastRemoved"]
        tlastDuration = stats["tlastDuration"]

        TableOcc = len(self.flow_stats)

        # --- CASE 1: First packet-in ---
        if npacketIn == 1:
            return self.t_init

        # --- CASE 2: TableOcc <= lowerbound ---
        if TableOcc <= self.TCAM_lowerbound:
            t_max = self.t_max_restore
            T = min(self.t_init * (2 ** npacketIn), t_max)
            return int(T)

        # --- CASE 3: lowerbound < TableOcc <= upperbound ---
        elif TableOcc <= self.TCAM_upperbound:

            t_max_dynamic = min(self.t_max * self.coef_w - self.B,
                            self.min_t_max)

            if tlastRemoved is not None and tlastDuration is not None:
                if (tpacketIn - tlastRemoved) <= tlastDuration:
                    T = min(
                    tlastDuration + (tpacketIn - tlastRemoved),
                    t_max_dynamic
                )
                else:
                    T = tlastDuration
            else:
                T = self.t_init

            return int(max(1, T))

        # --- CASE 4: TableOcc > upperbound ---
        else:
            return 1
     
        
        
	
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
        self.datapaths = {}
        self.datapaths[datapath.id] = datapath
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        for stat in ev.msg.body:
            match = stat.match

            in_port = match.get('in_port')
            eth_src = match.get('eth_src')
            eth_dst = match.get('eth_dst')

            if in_port and eth_src and eth_dst:
                key = (eth_src, eth_dst, in_port)
                if key in self.flow_stats:
                    self.flow_stats[key]["packet_count"] = stat.packet_count
    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    def _write_metrics(self):
        self.logger.info("Writing metrics into results folder")
        
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
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        match = msg.match

        in_port = match.get('in_port')
        eth_src = match.get('eth_src')
        eth_dst = match.get('eth_dst')

        if in_port and eth_src and eth_dst:
            key = (eth_src, eth_dst, in_port)

            if key in self.flow_stats:
                duration = msg.duration_sec + msg.duration_nsec / 1e9

                self.flow_stats[key]["tlastRemoved"] = time.time()
                self.flow_stats[key]["tlastDuration"] = duration
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
    	self.packet_in_count += 1
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

        # --- VITA metrics update ---
        flow["npacketIn"] += 1
        flow["tpacketIn"] = now

        # --- Runtime metrics ---
        flow["packet_count"] += 1
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
            if self.mode == "adaptive":
                idle_timeout = self.compute_idle_timeout(flow_id)
            elif self.mode == "fixed":
                idle_timeout = self.fixed_timeout
            else:
                idle_timeout = 5
            hard_timeout = idle_timeout * 2
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=idle_timeout,  hard_timeout=hard_timeout)
                return
            else:
                self.add_flow(datapath, 1, match, actions,idle_timeout=idle_timeout, hard_timeout=hard_timeout)
            
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
