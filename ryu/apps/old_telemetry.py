from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import time
from datetime import datetime
import psutil
from ryu.controller.handler import CONFIG_DISPATCHER

class TelemetryConsole(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TelemetryConsole, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.packet_in = 0
        self.flow_mod = 0
        self.last = {}
        self.max_entries = {}
        self.monitor = hub.spawn(self._monitor)
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def state_change(self, ev):
        self.datapaths[ev.datapath.id] = ev.datapath
    # ---- Packet-In counter ----
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.packet_in += 1
    @set_ev_cls(ofp_event.EventOFPFlowMod, MAIN_DISPATCHER)
    def flow_mod_handler(self, ev):
        self.flow_mod += 1
    # ---- Poll tables ----
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request(dp)
            hub.sleep(3)

    def _request(self, dp):
        parser = dp.ofproto_parser
        req = parser.OFPTableStatsRequest(dp)
        dp.send_msg(req)
    @set_ev_cls(ofp_event.EventOFPStateChange, [CONFIG_DISPATCHER])
    def get_features(self, ev):
        dp = ev.datapath
        parser = dp.ofproto_parser
        req = parser.OFPTableFeaturesStatsRequest(dp)
        dp.send_msg(req)    
    # ---- Receive stats ----
    @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
    def table_reply(self, ev):
        now = datetime.now()
        cpu = psutil.cpu_percent()
        stat = ev.msg.body[0] # our simple switch uses only table 0
        dpid = ev.msg.datapath.id # switch id
        active = stat.active_count
        lookup = stat.lookup_count
        matched = stat.matched_count
        miss = lookup - matched
        max_e = 1000000 # max number of flows in one table
        occupancy = (active * 100.0) / max_e

        
        print("[dp{}-{}] PktIn={} FlowMod={} CPU={} Active={} Miss={} Occupancy={}".format(dpid,now, self.packet_in, self.flow_mod, cpu, active, miss,  occupancy))
        self.packet_in = 0
        self.flow_mod = 0

