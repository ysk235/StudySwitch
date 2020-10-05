from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto.ether import ETH_TYPE_8021Q 
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import vlan
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import mac
from ryu import utils


from ryu.lib import addrconv
import struct
import socket
import time
import random

SLEEP_PERIOD = 1

class sample(app_manager.RyuApp):
    OFP_VERSIONS= [ofproto_v1_3.OFP_VERSION]
    def __init__(self,*args, **kwargs):
        super(sample, self).__init__(*args, **kwargs)
        # self.network_aware = kwargs["Network_Aware"]
        self.mac_to_port = {}
        self.datapaths = {}

        self.port_stats = {}
        self.port_speed = {}
        self.port_a_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        # {"port":{dpid:{port:body,..},..},"flow":{dpid:body,..}
        self.stats = {}
        self.port_link = {}  # {dpid:{port_no:(config,state,cur),..},..}
        self.monitor_thread = hub.spawn(self._monitor)

        self.topology_api_app = self

        # links   :(src_dpid,dst_dpid)->(src_port,dst_port)
        self.link_to_port = {}

        # {(sw,port) :[host1_ip,host2_ip,host3_ip,host4_ip]}
        self.access_table = {}

        # ports
        self.switch_port_table = {}  # dpid->port_num

        # dpid->port_num (access ports)
        self.access_ports = {}

        # dpid->port_num(interior ports)
        self.interior_ports = {}

        self.outer_ports = {}

        self.graph = {}
        self.graph2 = {}
        self.graphAB={}
        self.linkAB = {}

        self.pre_link_to_port = {}
        self.pre_graph = {}
        self.pre_access_table = {}
        self.datapath1 = {}
        self.datapath2 = {}
        self.datapath3 = {}
        self.datapath4 = {}
        self.datapath5 = {}
        self.datapath6 = {}

        self.discover_thread = hub.spawn(self._discover)

        self.port_stats_counts = 0
        self.port_stats_recounts = 0
        self.count = 0
        
        #apuri-identification1
        self.count_identification1 = 0
        self.capacity_identification1 = 0
        self.count_apuri_tcp1 = 0
        self.count_apuri_udp1 = 0
        self.count_apuri_voip1 = 0
        self.count_apuri_file1 = 0
        self.count_apuri_hyouji1 = 0
  
       #apuri-identification2
        self.count_identification2 = 0
        self.capacity_identification2 = 0
        self.count_apuri_tcp2 = 0
        self.count_apuri_udp2 = 0
        self.count_apuri_voip2 = 0
        self.count_apuri_file2 = 0
        self.count_apuri_hyouji2 = 0 
        
     #show topo ,and get topo again
    def _discover(self):
        i = 0
        while True:
            # self.show_topology()
            if i == 5:
                self.get_topology(None)
                i = 0
            hub.sleep(SLEEP_PERIOD)
            i = i + 1
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.logger.info("switch:%s connected", datapath.id)
        
         # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        
        self.add_flow(datapath, 0, match, actions)
        if datapath.id == 1:
           self.datapath1 = datapath
           
    def get_switches(self):
        return self.switches

    def get_links(self):
        return self.link_to_port
        
        
    def create_outer_port(self):
        pass

    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]


        
    @set_ev_cls(events)
    def get_topology(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        self.create_port_map(switch_list)
        self.switches = self.switch_port_table.keys()
        links = get_link(self.topology_api_app, None)
        self.create_interior_links(links)
        self.create_access_ports()
        self.get_graph(self.link_to_port.keys())
        self.get_graph2(self.link_to_port.keys(),1)
        self.get_a_graph(self.link_to_port.keys(),1)
        self.get_a_link(self.link_to_port.keys(),1)                   
           
#monitor      
    def _monitor(self):
        while True:
            self.stats['flow'] = {}
            self.stats['port'] = {}
            for dp in self.datapaths.values():
                self.port_link.setdefault(dp.id, {})
                self._request_stats(dp)
                
            hub.sleep(SLEEP_PERIOD)
            if self.stats['flow'] or self.stats['port']:
                #self.show_stat('flow', self.stats['flow'])
                #self.show_stat('port', self.stats['port'],dp)
                hub.sleep(1)
           
           
           
####################################################################################################################################################
#monitor
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):##1 ->register_access_info
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        dpid = datapath.id




        if isinstance(arp_pkt, arp.arp):#2kaime graph hyoujinomi
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip

            #self.logger.info("packet in %s %s %s %s"%(dpid, arp_src_ip, arp_dst_ip, in_port))
            #print("packet-in,dpid, in_port, arp_src_ip, arp_dst_ip",dpid, in_port, arp_src_ip, arp_dst_ip)

            # record the access info
            self.register_access_info(datapath.id, in_port, arp_src_ip)

            result = self.get_host_location(arp_dst_ip)
            if result:  # host record in access table.
                datapath_dst, out_port = result[0], result[1]
                actions = [parser.OFPActionOutput(out_port)]
                datapath = self.datapaths[datapath_dst]
                #print("arp-result,dpid,in_port,out_port",dpid,in_port,out_port)

                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions, data=msg.data)
                datapath.send_msg(out)
            else:       # access info is not existed. send to all host.
                for dpid in self.access_ports:
                    for port in self.access_ports[dpid]:
                        if (dpid, port) not in self.access_table.keys():
                            actions = [parser.OFPActionOutput(port)]
                            datapath = self.datapaths[dpid]
                            out = parser.OFPPacketOut(
                                datapath=datapath,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER,
                                actions=actions, data=msg.data)
                            datapath.send_msg(out)
                            #print("else")

        if isinstance(ip_pkt, ipv4.ipv4):

            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst

            result = None
            src_sw = None
            dst_sw = None

            src_location = self.get_host_location(ip_src)
            dst_location = self.get_host_location(ip_dst)

            if src_location:
                src_sw = src_location[0]
                #print("src_location",src_sw)

            if dst_location:
                dst_sw = dst_location[0]
                #print("dst_location",dst_sw)

            vid = random.randint(0,1)
            if pkt.get_protocol(vlan.vlan):
               vid = pkt.get_protocol(vlan.vlan).vid

            link_ab = 0           
