#!/bin/python2
from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as PKT
from pox.lib.packet import *
from pox.lib.addresses import IPAddr
from forwarding.l2_learning import *

from firewall import MyFirewall

def resend_packet(connection, packet_in, out_port):
	#
	# Instruct SW to resend pkt that it had sent to us. packet_in is the ofp_packet_in
	#
	msg = of.ofp_packet_out()		# create of packet out
	msg.data = packet_in

	# Add action to send to the specified port
	action = of.ofp_action_output(port=out_port)

	msg.actions.append(action)
	#Send message to switch
	connection.send(msg)

#
#	Firewall protecting External Network
#
class MyFw1(MyFirewall):
	# Firewall 1 is the base firewall
	pass


#
#	Firewall protecting Private Network
#
class MyFw2(MyFirewall):
	def __init__(self, fw_dpid, hosts, srv_list):
		super(MyFw2, self).__init__(fw_dpid, srv_list)
		self.hosts = hosts

	def _handle_PacketIn(self, event):
		packet = event.parsed
		if not packet.parsed:			 #check integrity
			log.warning("Ignoring incomplete packet")
			return
		
		if event.dpid == self.fwdpid:	# pkt arriving from firewall
			if packet.type == PKT.ethernet.IP_TYPE:	
				ip_pkt = packet.payload
				#if ip_pkt.protocol == PKT.ipv4.ICMP_PROTOCOL:
				#	icmp_packet = ip_pkt.payload

				if event.port == 2:
					log.debug("Firewall {}: BLOCKING {} from {} --> {}".format(event.dpid,  ip_pkt.protocol, ip_pkt.srcip, ip_pkt.dstip ))
					event.halt = True
				elif event.port == 1:
					print("Coming from inside Private Network.. ALLOWING")
					(src, dst) = ip_pkt.srcip, ip_pkt.dstip
					
					# RULES for allowing traffic starting from internal network
					rules = set()
					'''
					del_flow_from_l2 = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT,
 						action=of.ofp_action_output(port=2), priority=65535,
 						match=of.ofp_match( in_port=1,
 											nw_src=IPAddr(src),
 											nw_dst=IPAddr(dst))
 						)
					#rules.add(del_flow_from_l2)'''

					msg = of.ofp_flow_mod(
						# allow from outside to inside
						action = of.ofp_action_output(port=1),
						match = of.ofp_match(
								in_port = 2,	# in->out
								dl_type = PKT.ethernet.IP_TYPE,
								nw_dst = IPAddr(src),	# src=internal IP
								nw_src = IPAddr(dst)
							),
						priority = 1000,
						idle_timeout = 3
					)
					rules.add(msg)
					print("Installing rule: ALLOW from {} to {} ".format(dst, src))
					msg = of.ofp_flow_mod(
						# allow from inside to outside
						action = of.ofp_action_output(port=2),
						match = of.ofp_match(
								in_port = 1,	# in->out
								dl_type = PKT.ethernet.IP_TYPE,
								nw_src = IPAddr(src),	# src=internal IP
								nw_dst = IPAddr(dst)
							),
						priority = 1000,
						idle_timeout = 3
					)
					rules.add(msg)
					print("Installing rule: ALLOW from {} to {} ".format(src, dst))
					for rule in rules:
						self.connection.send(rule)

					from time import sleep
					sleep(0.1)
					# Added delay since can happen that switches receive the new flow rules 
					# after the packet has been forwarded to destination, and destination pkt can't reach 
					# the source back
					packet_in = event.ofp
					resend_packet(self.connection, packet_in, 2)
					event.halt = True
					#super(MyFw2, self)._handle_PacketIn(event)
		return

