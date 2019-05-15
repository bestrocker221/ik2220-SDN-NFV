#!/usr/bin/python2

from mininet.net import Mininet
from time import sleep
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch, Host

from logging import basicConfig, info, INFO, getLogger, StreamHandler

basicConfig(filename='../results/phase_1_report.log',filemode="w", level=INFO, format='%(asctime)s %(message)s')
getLogger().addHandler(StreamHandler())

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
		sw3 = self.addSwitch("sw3", dpid=int2dpid(3))		#Switch
		sw4 = self.addSwitch("sw4", dpid=int2dpid(4))		#Switch
		sw5 = self.addSwitch("sw5", dpid=int2dpid(5))		#Switch

		fw1 = self.addSwitch("fw1", dpid=int2dpid(51))		#Fw
		fw2 = self.addSwitch("fw2", dpid=int2dpid(52))		#Fw

		
		# click implements these
		
		lb1 = self.addSwitch("lb1", dpid=int2dpid(71))
		lb2 = self.addSwitch("lb2", dpid=int2dpid(72))
		ids = self.addSwitch("ids", dpid=int2dpid(73))
		napt = self.addSwitch("napt", dpid=int2dpid(74))
		
		############

		h1 = self.addHost("h1", ip="100.0.0.11/24")			#Host object
		h2 = self.addHost("h2", ip="100.0.0.12/24")		
		h3 = self.addHost("h3", ip="100.0.0.51/24")		
		h4 = self.addHost("h4", ip="100.0.0.52/24")

		ds1 = self.addHost("ds1", ip="100.0.0.20/24")
		ds2 = self.addHost("ds2", ip="100.0.0.21/24")
		ds3 = self.addHost("ds3", ip="100.0.0.22/24")
		

		ws1 = self.addHost("ws1", ip="100.0.0.40/24")
		ws2 = self.addHost("ws2", ip="100.0.0.41/24")			
		ws3 = self.addHost("ws3", ip="100.0.0.42/24")

		insp = self.addHost("insp", ip="100.0.0.103/24")

		# Firewalls:
		# port to DMZ external is 1
		# port to DMZ internal is 2
		# 

		self.addLink(h1, sw1)				#Create link
		self.addLink(h2, sw1)
		self.addLink(sw1, fw1, 5, 1)   # fw1:1 -> sw1

		self.addLink(sw2, fw1, 5, 2)   # fw1:2 -> sw2
		self.addLink(sw2, fw2, 6, 2)   # fw2:1-> sw2
		self.addLink(sw2, lb1)
		self.addLink(sw2, ids)

		self.addLink(lb1, sw3)

		self.addLink(sw3, ds1)
		self.addLink(sw3, ds2)
		self.addLink(sw3, ds3)

		self.addLink(ids, insp)
		self.addLink(ids, lb2)

		self.addLink(lb2, sw4)

		self.addLink(sw4, ws1)
		self.addLink(sw4, ws2)
		self.addLink(sw4, ws3)

		self.addLink(napt, fw2, 5, 1) # fw2:2 -> napt
		self.addLink(napt, sw5)

		self.addLink(sw5, h3)
		self.addLink(sw5, h4)

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

	# start WEB and DNS servers 
	srv_list = {"dns":["100.0.0.20", "100.0.0.21", "100.0.0.22"],
				"web":["100.0.0.40", "100.0.0.41", "100.0.0.42"]}

	hosts = {"int": {
						"h3":"100.0.0.51",
						"h4":"100.0.0.52"
					},
			 "ext": {
			 			"h1":"100.0.0.11",
			 			"h2":"100.0.0.12"
			 		}
			}

	for web in ["ws1", "ws2", "ws3"]:
		print("[{}] Starting HTTP server on port 80".format(web))
		net.get(web).cmd("python2 -m SimpleHTTPServer 80 &")
	
	for dns in ["ds1", "ds2", "ds3"]:
		print("[{}] Starting DNS server on port 53".format(dns))
		dns_host = net.get(dns)
		dns_host.cmd("sudo python dns_server.py {} &".format(dns_host.IP()))


	info("####### STARTING TESTS #######  ")
	
	total_run = 0
	total_ok = 0

	def ok():
		global total_ok
		global total_run
		total_run +=1
		total_ok +=1
		return " OK!"

	def err():
		global total_run
		total_run +=1
		return " ERROR!"

	for external in hosts["ext"]: 
		ips = set()
		ext_host = net.get(external)
		for internal in hosts["int"]:
			ips.add(hosts["int"][internal])
		for server_ip in (srv_list.values()[0] + srv_list.values()[1]):
			ips.add(server_ip)
		
		for test_ip in ips:
			info("[PING TEST] external {} to internal {} must NOT work: ".format( external, test_ip)),
			res = int(ext_host.cmd('ping -c 1 -W 1 {}'.format(test_ip) + '| grep 64 | wc | awk \'{print $1}\''))
			info( ok() if res == 0 else err() )
		
		for dns_ip in srv_list["dns"]:
			info("[DNS TEST] external {} to internal DNS {} must work: ".format( external, dns_ip)),
			res = int(ext_host.cmd('dig @{}'.format(dns_ip) + ' +timeout=1 +tries=1 ciao.it | grep "Got answer" |wc| awk \'{print $1}\''))
			info( ok() if res == 1 else err())

			# bogus DNS
			info("[DNS BOGUS TEST] external {} to internal DNS port 5353 {} must NOT work: ".format( external, dns_ip)),
			res = int(ext_host.cmd('dig -p 5353 @{}'.format(dns_ip) + ' +timeout=1 +tries=1 ciao.it | grep "Got answer" |wc| awk \'{print $1}\''))
			info( ok() if res == 0 else err() )

		for web_ip in srv_list["web"]:
			info("[WEB TEST] external {} to internal WEB {} must work: ".format( external, web_ip)),
			res = int(ext_host.cmd('curl --connect-timeout 1 {}'.format(web_ip) + ' -s | grep DOCTYPE | wc | awk \'{print $1}\''))
			info( ok() if res == 1 else err())

			# bogus WEB
			info("[WEB BOGUS TEST] external {} to internal WEB {} must NOT work: ".format( external, web_ip)),
			res = int(ext_host.cmd('curl --connect-timeout 1 {}:8080'.format(web_ip) + ' -s | grep DOCTYPE | wc | awk \'{print $1}\''))
			info( ok() if res == 0 else err())


	for internal in hosts["int"]:
		int_host = net.get(internal)
		for external in hosts["ext"]:
			e_ip =hosts["ext"][external]
			info("[PING TEST] internal {} to external {} must work: ".format(internal, external)),
			res = int(int_host.cmd('ping -c 1 -W 1 {}'.format(e_ip) + '| grep 64 | wc | awk \'{print $1}\''))
			info( ok() if res == 1 else err())

		for dns_ip in srv_list["dns"]:
			info("[DNS TEST] internal {} to internal DNS {} must work: ".format( internal, dns_ip)),
			res = int(int_host.cmd('dig @{}'.format(dns_ip) + ' +timeout=1 +tries=1 ciao.it | grep "Got answer" |wc| awk \'{print $1}\''))
			info( ok() if res == 1 else err())

			# bogus DNS
			info("[DNS BOGUS TEST] internal {} to internal DNS port 5353 {} must NOT work: ".format( internal, dns_ip)),
			res = int(int_host.cmd('dig -p 5353 @{}'.format(dns_ip) + ' +timeout=1 +tries=1 ciao.it | grep "Got answer" |wc| awk \'{print $1}\''))
			info( ok() if res == 0 else err() )

		for web_ip in srv_list["web"]:
			info("[WEB TEST] internal {} to internal WEB {} must work: ".format( internal, web_ip)),
			res = int(int_host.cmd('curl --connect-timeout 1 {}'.format(web_ip) + ' -s | grep DOCTYPE | wc | awk \'{print $1}\''))
			info( ok() if res == 1 else err())

			# bogus WEB
			info("[WEB BOGUS TEST] internal {} to internal WEB {} must NOT work: ".format( internal, web_ip)),
			res = int(int_host.cmd('curl --connect-timeout 1 {}:8080'.format(web_ip) + ' -s | grep DOCTYPE | wc | awk \'{print $1}\''))
			info( ok() if res == 0 else err())

	info("\nRESULTS:")
	info("\tTOTAL SCORE {}/{}\n".format(total_ok, total_run))
	info("####### ENDING TESTS   #######  ")
	## END TEST

	CLI(net)

	net.stop()

	#sudo ovs-vsctl show
	#sudo ovs-ofctl dump-flows s1