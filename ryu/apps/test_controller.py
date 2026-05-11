

import math
import time
import csv
import json
import os
import psutil
import signal
import atexit
import errno
from collections import defaultdict, deque
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, lldp
from ryu.lib import hub

MODE          = os.environ.get('MODE', 'adaptive')
FIXED_TIMEOUT = int(os.environ.get('FIXED_TIMEOUT', '5'))
T_MIN         = float(os.environ.get('T_MIN',   2))
T_MAX         = float(os.environ.get('T_MAX',   60))
ALPHA         = float(os.environ.get('ALPHA',   15))
BETA          = float(os.environ.get('BETA',    10))
DELTA         = float(os.environ.get('DELTA',   5))
GAMMA         = float(os.environ.get('GAMMA',   3.4))
ETA           = float(os.environ.get('ETA',     5))
THETA         = float(os.environ.get('THETA',   100))

LLDP_INTERVAL = 5   # seconds between LLDP probe rounds


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    metrics_written = False

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}        
        self.mac_to_dpid = {}        
        self.datapaths   = {}        
        self.port_state  = {}        

        
        self.adjacency = {}
        
        self.graph = defaultdict(dict)

        self.mode          = MODE
        self.fixed_timeout = FIXED_TIMEOUT
        self.logger.info("Controller mode: %s", self.mode)

        self.flow_stats = defaultdict(lambda: {
            "packet_count": 0,
            "last_seen":    None,
            "iat_window":   deque(maxlen=10),
        })
        self.TCAM_MAX = 750
        self.T_MIN  = T_MIN;  self.T_MAX  = T_MAX
        self.ALPHA  = ALPHA;  self.BETA   = BETA
        self.DELTA  = DELTA;  self.GAMMA  = GAMMA
        self.ETA    = ETA;    self.THETA  = THETA
        self.cpu_load = 0

        self.packet_in_count = 0
        self.rejected_flows  = 0
        self.start_time      = time.time()
        self.metrics         = []

        self.monitor_thread = hub.spawn(self._monitor)
        self.lldp_thread    = hub.spawn(self._lldp_loop)

        self.process = psutil.Process(os.getpid())
        self.process.cpu_percent(interval=None)

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT,  self._signal_handler)
        atexit.register(self._write_metrics)

    # ==================================================================
    # Switch connect
    # ==================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        # table-miss  controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Request port list so we know which ports to probe with LLDP
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        self.port_state.setdefault(dp.id, {})
        for port in ev.msg.body:
            if port.port_no < dp.ofproto.OFPP_MAX:
                self.port_state[dp.id][port.port_no] = port

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofproto = dp.ofproto
        port    = msg.desc
        self.port_state.setdefault(dp.id, {})
        if msg.reason in (ofproto.OFPPR_ADD, ofproto.OFPPR_MODIFY):
            self.port_state[dp.id][port.port_no] = port
        elif msg.reason == ofproto.OFPPR_DELETE:
            self.port_state[dp.id].pop(port.port_no, None)
            stale = [k for k in self.adjacency
                     if k == (dp.id, port.port_no)]
            for k in stale:
                peer = self.adjacency.pop(k, None)
                if peer:
                    self.adjacency.pop(peer, None)
            self._rebuild_graph()

    # ==================================================================
    # LLDP  topology discovery
    # ==================================================================

    def _lldp_loop(self):
        hub.sleep(3)
        while True:
            for dpid, dp in list(self.datapaths.items()):
                for port_no in list(self.port_state.get(dpid, {}).keys()):
                    self._send_lldp(dp, port_no)
            hub.sleep(LLDP_INTERVAL)

    def _send_lldp(self, datapath, port_no):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=str(datapath.id).encode()
        )
        port_id = lldp.PortID(
            subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED,
            port_id=str(port_no).encode()
        )
        lldp_pkt = lldp.lldp([chassis_id, port_id, lldp.TTL(ttl=120)])

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_LLDP,
            dst=lldp.LLDP_MAC_NEAREST_BRIDGE,
            src='00:00:00:00:00:00',
        ))
        pkt.add_protocol(lldp_pkt)
        pkt.serialize()

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(port_no)],
            data=pkt.data,
        )
        datapath.send_msg(out)

    def _handle_lldp(self, datapath, in_port, pkt):
        try:
            lldp_pkt = pkt.get_protocol(lldp.lldp)
            if lldp_pkt is None:
                return
            src_dpid = src_port = None
            for tlv in lldp_pkt.tlvs:
                if isinstance(tlv, lldp.ChassisID):
                    src_dpid = int(tlv.chassis_id.decode())
                elif isinstance(tlv, lldp.PortID):
                    src_port = int(tlv.port_id.decode())
            if src_dpid is None or src_port is None:
                return
            self.adjacency[(src_dpid, src_port)]  = (datapath.id, in_port)
            self.adjacency[(datapath.id, in_port)] = (src_dpid, src_port)
            self._rebuild_graph()
        except Exception as e:
            self.logger.warning("LLDP parse error: %s", e)

    def _rebuild_graph(self):
        g = defaultdict(dict)
        for (dpid_a, port_a), (dpid_b, _) in self.adjacency.items():
            g[dpid_a][dpid_b] = port_a
        self.graph = g

    # ==================================================================
    # PacketIn
    # ==================================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.packet_in_count += 1

        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            self._handle_lldp(datapath, in_port, pkt)
            return

        dst  = eth.dst
        src  = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        flow_id = (src, dst, in_port)

        # TCAM guard
        if flow_id not in self.flow_stats and len(self.flow_stats) >= self.TCAM_MAX:
            self.rejected_flows += 1
            return

        # Update flow stats
        now  = time.time()
        flow = self.flow_stats[flow_id]
        flow["packet_count"] += 1
        if flow["last_seen"] is not None:
            flow["iat_window"].append(now - flow["last_seen"])
        flow["last_seen"] = now

        # Learn source MAC on this switch
        self.mac_to_port[dpid][src] = in_port
        self.mac_to_dpid[src]       = dpid   # FIX: maintain fast reverse lookup

        #  Forwarding decision 
        if dst in self.mac_to_port[dpid]:
            # Dst is directly reachable on this switch
            out_port = self.mac_to_port[dpid][dst]
            self._install_and_send(datapath, msg, in_port, out_port,
                                   dst, src, flow_id)

        elif dst.startswith('ff:') or dst.startswith('33:'):
            # Broadcast  multicast
            self._spanning_flood(datapath, msg, in_port)

        else:
            # Unknown unicast  try shortest path
            dst_dpid = self.mac_to_dpid.get(dst)          # FIX: use fast lookup
            if dst_dpid is None:
                self._spanning_flood(datapath, msg, in_port)
            else:
                path = self._bfs_path(dpid, dst_dpid)
                if path and self._path_is_complete(path, dst):
                    self._install_path(path, src, dst, msg, in_port)
                else:
                    # Path incomplete (graph still converging)  flood for now
                    self._spanning_flood(datapath, msg, in_port)

    # ==================================================================
    # Path helpers
    # ==================================================================

    def _path_is_complete(self, path, dst_mac):
        """
        Verify every hop in the path has a known egress port before
        committing flows. Avoids installing broken partial paths while
        the LLDP graph is still converging.
        """
        for i, dpid in enumerate(path):
            if i == len(path) - 1:
                # Last hop: must know dst MAC port on that switch
                if dst_mac not in self.mac_to_port.get(dpid, {}):
                    return False
            else:
                # Intermediate hop: must know port toward next switch
                if path[i + 1] not in self.graph.get(dpid, {}):
                    return False
        return True

    def _bfs_path(self, src_dpid, dst_dpid):
        if src_dpid == dst_dpid:
            return [src_dpid]
        visited = {src_dpid}
        queue   = deque([[src_dpid]])
        while queue:
            path = queue.popleft()
            for neighbour in self.graph.get(path[-1], {}):
                if neighbour == dst_dpid:
                    return path + [dst_dpid]
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append(path + [neighbour])
        return None

    def _install_path(self, path, src_mac, dst_mac, msg, first_in_port):
        """
        Install forwarding rules on every switch along the path,
        then send the buffered packet out of the first switch.
        """
        for i, dpid in enumerate(path):
            dp = self.datapaths.get(dpid)
            if dp is None:
                continue

            # Determine egress port for this hop
            if i == len(path) - 1:
                out_port = self.mac_to_port[dpid][dst_mac]
            else:
                out_port = self.graph[dpid][path[i + 1]]

            parser  = dp.ofproto_parser
            actions = [parser.OFPActionOutput(out_port)]
            fid     = (src_mac, dst_mac, first_in_port if i == 0 else 0)
            ito     = self._get_idle_timeout(fid)

            # FIX: only match in_port on the ingress switch to avoid
            # collisions on intermediate switches that have no in_port context
            if i == 0:
                match = parser.OFPMatch(in_port=first_in_port,
                                        eth_dst=dst_mac, eth_src=src_mac)
            else:
                match = parser.OFPMatch(eth_dst=dst_mac, eth_src=src_mac)

            self.add_flow(dp, 1, match, actions,
                          idle_timeout=ito, hard_timeout=ito * 2)

        # Send the original packet out of the first switch
        first_dp = self.datapaths.get(path[0])
        if first_dp is None:
            return

        if len(path) == 1:
            first_out_port = self.mac_to_port[path[0]][dst_mac]
        else:
            first_out_port = self.graph[path[0]][path[1]]

        self._do_packet_out(first_dp, msg, first_out_port)

    def _install_and_send(self, datapath, msg, in_port, out_port,
                          dst, src, flow_id):
        parser  = datapath.ofproto_parser
        ito     = self._get_idle_timeout(flow_id)
        match   = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        actions = [parser.OFPActionOutput(out_port)]
        if msg.buffer_id != datapath.ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, match, actions, msg.buffer_id,
                          idle_timeout=ito, hard_timeout=ito * 2)
            return
        self.add_flow(datapath, 1, match, actions,
                      idle_timeout=ito, hard_timeout=ito * 2)
        self._do_packet_out(datapath, msg, out_port)

    def _do_packet_out(self, datapath, msg, out_port):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        data    = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'],
            actions=[parser.OFPActionOutput(out_port)],
            data=data,
        ))

    def _spanning_flood(self, datapath, msg, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
        datapath=datapath,
        buffer_id=msg.buffer_id,
        in_port=in_port,
        actions=actions,
        data=data
    )

        datapath.send_msg(out)
    # ==================================================================
    # Adaptive timeout
    # ==================================================================

    def _get_idle_timeout(self, flow_id):
        if self.mode == "adaptive":
            return self.compute_idle_timeout(flow_id)
        elif self.mode == "fixed":
            return self.fixed_timeout
        return 5

    def compute_idle_timeout(self, flow_id):
        stats    = self.flow_stats[flow_id]
        N_k      = stats["packet_count"]
        mean_iat = (sum(stats["iat_window"]) / len(stats["iat_window"])
                    if stats["iat_window"] else 1.0)
        periodicity = self.detect_periodicity(flow_id)
        cpu_norm    = self.cpu_load / 100.0
        occ_ratio   = min(len(self.flow_stats) / self.TCAM_MAX, 1.0)

        if occ_ratio > 0.9:
            return int(self.T_MIN)
        effective_t_max = (max(self.T_MIN, self.T_MAX * (1.0 - occ_ratio))
                           if occ_ratio > 0.55 else self.T_MAX)
        base = (self.ALPHA * math.log(1 + N_k)
                + self.BETA  * (1.0 / mean_iat)
                + self.ETA   * periodicity
                - self.DELTA * occ_ratio
                - self.THETA * cpu_norm)
        T = max(self.T_MIN, min(effective_t_max, base), self.GAMMA * mean_iat)
        return int(T)

    def detect_periodicity(self, flow_id):
        iats = self.flow_stats[flow_id]["iat_window"]
        if len(iats) < 5:
            return 0
        mean = sum(iats) / len(iats)
        std  = math.sqrt(sum((x - mean) ** 2 for x in iats) / len(iats))
        cv   = std / mean if mean > 0 else 1
        return max(0, 1 - cv)

    # ==================================================================
    # Flow mod
    # ==================================================================

    def add_flow(self, datapath, priority, match, actions,
                 buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
        kwargs  = dict(datapath=datapath, priority=priority, match=match,
                       instructions=inst, idle_timeout=idle_timeout,
                       hard_timeout=hard_timeout,
                       flags=ofproto.OFPFF_SEND_FLOW_REM)
        if buffer_id:
            kwargs['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    # ==================================================================
    # Flow removed / stats
    # ==================================================================

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        match   = ev.msg.match
        in_port = match.get('in_port')
        eth_src = match.get('eth_src')
        eth_dst = match.get('eth_dst')
        if in_port and eth_src and eth_dst:
            self.flow_stats.pop((eth_src, eth_dst, in_port), None)
        # FIX: also clean up mac_to_dpid if this was the last flow for that MAC
        if eth_src and self.mac_to_dpid.get(eth_src) is not None:
            dpid = self.mac_to_dpid[eth_src]
            if eth_src not in self.mac_to_port.get(dpid, {}):
                self.mac_to_dpid.pop(eth_src, None)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        for stat in ev.msg.body:
            match   = stat.match
            in_port = match.get('in_port')
            eth_src = match.get('eth_src')
            eth_dst = match.get('eth_dst')
            if in_port and eth_src and eth_dst:
                key = (eth_src, eth_dst, in_port)
                if key in self.flow_stats:
                    self.flow_stats[key]["packet_count"] = stat.packet_count

    def _request_stats(self, datapath):
        datapath.send_msg(datapath.ofproto_parser.OFPFlowStatsRequest(datapath))

    # ==================================================================
    # Monitoring metrics
    # ==================================================================

    def _monitor(self):
        while True:
            hub.sleep(0.5)
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            self._collect_metrics()

    def _collect_metrics(self):
        now    = time.time() - self.start_time
        record = {
            "time":            round(now, 2),
            "table_occupancy": len(self.flow_stats),
            "packet_in_count": self.packet_in_count,
            "rejected_flows":  self.rejected_flows,
            "cpu_percent":     self.process.cpu_percent(interval=None),
            "memory_mb":       self.process.memory_info().rss / (1024 * 1024),
        }
        self.cpu_load = record["cpu_percent"]
        self.logger.info(record)
        self.metrics.append(record)

    def _signal_handler(self, signum, frame):
        self._write_metrics()

    def _write_metrics(self):
        self.logger.info("Writing metrics into results folder")
        if not self.metrics:
            return
        path = "/results/" + self.mode + "/" + str(self.TCAM_MAX) + "/"
        try:
            os.makedirs(path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        with open(path + "metrics.json", "w") as f:
            json.dump(self.metrics, f, indent=2)
        with open(path + "metrics.csv", "w") as f:
            writer = csv.DictWriter(f, fieldnames=self.metrics[0].keys())
            writer.writeheader()
            writer.writerows(self.metrics)

        n = len(self.metrics)
        summary = {
            "total_rejected_flows":        self.metrics[-1]['rejected_flows'],
            "total_packet_in_flows":       self.metrics[-1]['packet_in_count'],
            "avg_table_occupancy_percent": (
                sum(r["table_occupancy"] for r in self.metrics) / n
                * 100.0 / self.TCAM_MAX),
            "avg_cpu_percent": sum(r["cpu_percent"] for r in self.metrics) / n,
            "avg_memory_mb":   sum(r["memory_mb"]   for r in self.metrics) / n,
        }
        with open(path + "summary.json", "w") as f:
            json.dump(summary, f, indent=2)
