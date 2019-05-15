#!/usr/bin/python2

from mininet.net import Mininet
from time import sleep
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch, Host

from logging import basicConfig, info, INFO, getLogger, StreamHandler

#basicConfig(filename='../results/phase_1_report.log',filemode="w", level=INFO, format='%(asctime)s %(message)s')
#getLogger().addHandler(StreamHandler())

def int2dpid( dpid ):
   try:
      dpid = hex( dpid )[ 2: ]
      dpid = '0' * ( 16 - len( dpid ) ) + dpid
      return dpid
   except IndexError:
      raise Exception( 'Unable to derive default datapath ID - '
                       'please either specify a dpid or use a '
		       'canonical switch name such as s23.' )

class MyTopology(Topo):
	def __init__(self):
		Topo.__init__(self)
		# assign DPID so that i can manage them in the controller.
		sw1 = self.addSwitch("sw1", dpid=int2dpid(1))		#Switch
		sw2 = self.addSwitch("sw2", dpid=int2dpid(2))		#Switch
		
		h1 = self.addHost("h1", ip="100.0.0.10/24")			#Host object

		h2 = self.addHost("h2", ip="100.0.0.40/24")
		h3 = self.addHost("h3", ip="100.0.0.41/24")		

		self.addLink(h1, sw1)

		self.addLink(sw1, sw2)				#Create link
		
		self.addLink(h2, sw2)
		self.addLink(h3, sw2)

topos = { 'mytopo': ( lambda: MyTopology() ) }
#'--topo=mytopo' from the command line.

if __name__ == "__main__":

	setLogLevel('info')
	
	topo = MyTopology()

	ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)

	net = Mininet(  topo=topo,
					switch=OVSSwitch,
					controller=ctrl,
					autoSetMacs=True,
					autoStaticArp=True,
					build=True,
					cleanup=True)

	net.start()

	#net.get("h1").cmd("ip route add default via 10.0.0.1")
	net.get("h1").cmd("python2 -m SimpleHTTPServer 80 &")
	#net.get("h1").cmd("sudo python dns_server.py 100.0.0.10 &")
	
	#net.get("h2").cmd("ip route add default via 100.0.0.1")
	net.get("h2").cmd("python2 -m SimpleHTTPServer 80 &")
	
	#net.get("h3").cmd(" ip route add default via 100.0.0.1")
	net.get("h3").cmd("python2 -m SimpleHTTPServer 80 &")

	dns_host = net.get("h3")
	dns_host.cmd("sudo python dns_server.py {} &".format(dns_host.IP()))
	
	CLI(net)

	net.stop()

	#sudo ovs-vsctl show
	#sudo ovs-ofctl dump-flows s1