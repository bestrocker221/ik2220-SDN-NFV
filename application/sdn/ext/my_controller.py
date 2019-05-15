#!/bin/python2

from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as PKT
from pox.lib.packet import *
from pox.lib.addresses import IPAddr

from forwarding.l2_learning import *

# importing MY modules
from myproj.myfw import MyFw2, MyFw1
from myproj.l2_custom import l2_learning_custom
from myproj.clickElem import click_device

import os, sys
log = core.getLogger()

if os.getuid() != 0:
	print("\nYOU ARE NOT ROOT [uiid = {}]. NEED ROOT PRIVILEGES TO CONTINUE..\n".format(os.getuid()))
	sys.exit(0)

def launch():
	fw_list_dpid = [51, 52]
	click_dpid = [71,72, 74]


	private_ip_hosts = ["10.0.0.50", "10.0.0.51"]
	
	srv_list = {"dns":["100.0.0.20", "100.0.0.21", "100.0.0.22"],
				"web":["100.0.0.40", "100.0.0.41", "100.0.0.42"]}
	
	core.registerNew(MyFw1, fw_list_dpid[0] , srv_list)
	core.registerNew(MyFw2, fw_list_dpid[1], private_ip_hosts, srv_list)
	# registering click elements
	core.registerNew(click_device, click_dpid)
	
	# Except the two firewalls, and click elements all the others are l2 learning switches
	core.registerNew(l2_learning_custom, click_dpid + fw_list_dpid)


# OpenFlow Events
#
#_handle_ConnectionUp
#_handle_ConnectionDown
#_handle_PacketIn
#_handle_PortStatus
#_handle_FlowRemoved
#_handle_ErrorIn
#_handle_BarrierIn

# OpenFlow Attributes
#
# connection
# dpid
# ofp

# OpenFlow Messages
#
# ofp_packet_out      -> CTRL instructs switch to send packet
# ofp_flow_mod 	      -> Install/modify/delete rule from SW
# ofp_stats_request   -> requests stats from switch

# OpenFlow match/Actions
#
# msg.match.dl_type = 0x800
#		   .nw_dst = IPAddr("192..")
#		   .tp_dst = 80
# msg.actions.append(action)
# ofp_action_output(port=4)  -> send packet to port 4
#

# OpenFlow Match
#
# of.ofp_flow_mod( action= action, priority= 42, match= match..)
#
# match = of.ofp_match(in_port=5, dl_dst=EthAddr("ss"))

# OpenFlow Actions

# ofp_action_output  -> Send to physical or virtual (e.g. to CNTRL) port
# ofp_action_enqueue -> Forwards a packet through the designated queue (QoS)
# ofp_action_vlan_vid -> Insert/Update VLAN header with ID
# ofp_action_vlan_pcp -> Set VLAN priority
# ofp_action_dl_addr -> Set the source or destination MAC address.
# ofp_action_nw_addr -> Set the source or destination IP address.
# ofp_action_tp_port -> Set the source or destination TCP/UDP port.

# Packet Parsing
#
# import pox.lib.packet as pkt
#
#def parse_icmp (eth_packet):
#	if eth_packet.type == pkt.IP_TYPE:
#		ip_packet = eth_packet.payload
#		if ip_packet.protocol == pkt.ICMP_PROTOCOL:
#			icmp_packet = ip_packet.payload
