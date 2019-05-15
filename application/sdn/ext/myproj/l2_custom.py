#!/bin/python2
from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as PKT
from pox.lib.packet import *
from pox.lib.addresses import IPAddr

from forwarding.l2_learning import *

#
# My l2learning component
#
class l2_learning_custom (object):
	def __init__(self, ignore = None):
		core.openflow.addListeners(self)
		self.ignore = set(ignore) if ignore else ()

	def _handle_ConnectionUp (self, event):
	    if event.dpid in self.ignore:
	      #log.debug("Ignoring connection from {}".format(event.dpid))
	      return
	    log.debug("Connection from {} - {} ".format(event.dpid, event.connection))
	    # treat as learning switch
	    LearningSwitch(event.connection, False)
