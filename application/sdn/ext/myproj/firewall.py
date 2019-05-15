#!/bin/python2
from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as PKT
from pox.lib.packet import *
from pox.lib.addresses import IPAddr

from forwarding.l2_learning import *


#
# Firewall base object class.
# Implements the common logic for both fw1 and fw2
#
class MyFirewall(object):
	def __init__(self, fw_dpid, srv_list):
		core.openflow.addListeners(self)
		self.fwdpid = fw_dpid
		self.srv_list = srv_list

	'''
	def _handle_PacketIn(self, event):
		if event.dpid == self.fwdpid:
			LearningSwitch(event.connection, False)	
	'''
	#
	# 	Common rules to both firewalls 1 & 2
	#
	def _handle_ConnectionUp(self, event):
		if event.dpid == self.fwdpid:
			self.connection = event.connection
			log.debug("Firewall %d : %s has come up." , event.dpid, dpid_to_str(event.dpid))

			rules = set()
			s_list = self.srv_list.values()[0] + self.srv_list.values()[1]

			# block IP traffic from outside to servers and viceversa
			for server_ip in s_list:
				msg = of.ofp_flow_mod(
					match = of.ofp_match(
							dl_type = PKT.ethernet.IP_TYPE,
							nw_dst = IPAddr(server_ip),	# src=internal IP
						),
					priority = 10,
				)
				print("BLOCKING IP in FW {} to {}".format(event.dpid, server_ip))
				rules.add(msg)

				msg = of.ofp_flow_mod(
					match = of.ofp_match(
							dl_type = PKT.ethernet.IP_TYPE,
							nw_src = IPAddr(server_ip),	# src=internal IP
						),
					priority = 10,
				)
				rules.add(msg)
				print("BLOCKING IP in FW {} from {}".format(event.dpid, server_ip))
			
			#
			#	Allow traffic to/from servers
			#
			for web_server in self.srv_list["web"]:
				# generating TCP rules for communication to web servers
				# from out (public/private zone) to inner
				msg = of.ofp_flow_mod(
					action = of.ofp_action_output(port=2),  # block ping from outside to servers and viceversa
					match = of.ofp_match(
							in_port = 1,
							dl_type = PKT.ethernet.IP_TYPE,
							nw_proto = PKT.ipv4.TCP_PROTOCOL,
							nw_dst = IPAddr(web_server),	# src=internal IP
							tp_dst = 80
						),
					priority = 111
				)
				print("ALLOWING TCP 80 in FW {} to {}".format(event.dpid, web_server))
				rules.add(msg)

				# From inner web services to the outer (public/private zone)
				msg = of.ofp_flow_mod(
					action = of.ofp_action_output(port=1),
					match = of.ofp_match(
							in_port = 2,
							dl_type = PKT.ethernet.IP_TYPE,
							nw_proto = PKT.ipv4.TCP_PROTOCOL,
							nw_src = IPAddr(web_server),	# src=internal IP
							tp_src = 80
						),
					priority = 111,
				)
				rules.add(msg)
				print("ALLOWING TCP 80 in FW {} from {}".format(event.dpid, web_server))

			# generating UDP rules for communication to DNS servers
			for dns_server in self.srv_list["dns"]:
				msg = of.ofp_flow_mod(
					action = of.ofp_action_output(port=2),
					match = of.ofp_match(
							in_port = 1,
							dl_type = PKT.ethernet.IP_TYPE,
							nw_proto = PKT.ipv4.UDP_PROTOCOL,
							nw_dst = IPAddr(dns_server),	# src=internal IP
							tp_dst = 53
						),
					priority = 112
				)
				print("ALLOWING UDP 53 in FW {} to {}".format(event.dpid, dns_server))
				rules.add(msg)
				msg = of.ofp_flow_mod(
					action = of.ofp_action_output(port=1),
					match = of.ofp_match(
							in_port = 2,
							dl_type = PKT.ethernet.IP_TYPE,
							nw_proto = PKT.ipv4.UDP_PROTOCOL,
							nw_src = IPAddr(dns_server),	# src=internal IP
							tp_src = 53
						),
					priority = 112,
				)
				rules.add(msg)
				print("ALLOWING UDP 53 in FW {} from {}".format(event.dpid, dns_server))
			# Sending rules to Firewall switch
			for rule in rules:
				self.connection.send(rule)
			
			LearningSwitch(event.connection, False)	