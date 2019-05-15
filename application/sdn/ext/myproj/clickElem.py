#!/bin/python2
from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as PKT
from pox.lib.packet import *
from pox.lib.addresses import IPAddr
import subprocess

log = core.getLogger()
import shlex

#
# My click router component
#
class click_device (object):
	def __init__(self, clicks_dpids = None):
		core.openflow.addListeners(self)
		#self.ignore = set(ignore) if ignore else ()
		self.clicks_dpids = set(clicks_dpids) if clicks_dpids else ()
		self.click_proc = None

	def _handle_ConnectionUp (self, event):
		if event.dpid not in self.clicks_dpids:
			#log.debug("Ignoring connection from {}".format(event.dpid))
			return
		log.debug("Connection from CLICK: [{}] - {} ".format(event.dpid, event.connection))
		# start click modules
		click_path = "../nfv"
		args = ""
		if event.dpid in self.clicks_dpids:
			# launch lb1 (DNS side)
			if event.dpid == 71:
				args = "sudo /usr/local/bin/click -f " + click_path + "/lb.click int_if=lb1-eth2 ext_if=lb1-eth1 sw_ip=100.0.0.25 s1=100.0.0.20 s2=100.0.0.21 s3=100.0.0.22 port=53 proto=udp lb=1"
			# launch lb2 (HTTP side)
			elif event.dpid == 72:
				args = "sudo /usr/local/bin/click -f " + click_path + "/lb.click int_if=lb2-eth2 ext_if=lb2-eth1 sw_ip=100.0.0.45 s1=100.0.0.40 s2=100.0.0.41 s3=100.0.0.42 port=80 proto=tcp lb=2"
			# launch ids
			elif event.dpid == 73:
				args = "sudo /usr/local/bin/click -f " + click_path + "/ids.click int_if=ids-eth3 ext_if=ids-eth1 insp_if=ids_eth2"
			# launch napt
			elif event.dpid == 74:
				args = "sudo /usr/local/bin/click -f " + click_path + "/nat.click int_if=napt-eth2 ext_if=napt-eth5"
			
			# launch the process
			log.debug("[{}] RUN: {}".format(event.dpid, args ))
			args = shlex.split(args)
			self.click_proc = subprocess.Popen(args)

	def _handle_ConnectionDown(self, event):
		if event.dpid in self.clicks_dpids:
			self.click_proc.terminate()
			log.debug("[CLICK: {}] Terminating..".format(event.dpid))