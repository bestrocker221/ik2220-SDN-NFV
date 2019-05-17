#!/usr/bin/python2

from mininet.net import Mininet
from time import sleep
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch, Host

from logging import basicConfig, info, INFO, getLogger, StreamHandler

basicConfig(filename='../results/phase_2_report.log',filemode="w", level=INFO, format='%(asctime)s %(message)s')
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

		h1 = self.addHost("h1", ip="100.0.0.10/24")			#Host object
		h2 = self.addHost("h2", ip="100.0.0.11/24")		
		h3 = self.addHost("h3", ip="10.0.0.50/24")		
		h4 = self.addHost("h4", ip="10.0.0.51/24")

		ds1 = self.addHost("ds1", ip="100.0.0.20/24")
		ds2 = self.addHost("ds2", ip="100.0.0.21/24")
		ds3 = self.addHost("ds3", ip="100.0.0.22/24")
		

		ws1 = self.addHost("ws1", ip="100.0.0.40/24")
		ws2 = self.addHost("ws2", ip="100.0.0.41/24")			
		ws3 = self.addHost("ws3", ip="100.0.0.42/24")

		insp = self.addHost("insp", ip="100.0.0.30/24")

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

	#
	#	Initiating variables/IP/http allowed/blocked methods
	#
	srv_list = {"dns":["100.0.0.20", "100.0.0.21", "100.0.0.22"],
				"web":["100.0.0.40", "100.0.0.41", "100.0.0.42"],
				"web_lb" : "100.0.0.45",
				"dns_lb" : "100.0.0.25",
				}

	hosts = {"int": {
						"h3":"10.0.0.50",
						"h4":"10.0.0.51"
					},
			 "ext": {
			 			"h1":"100.0.0.10",
			 			"h2":"100.0.0.11"
			 		}
			}

	http_block = ["OPTIONS","TRACE","CONNECT",'DELETE',"HEAD","GET"]
	http_allow = ["POST","PUT"]

	injections = [  "cat /etc/passwd",
					"cat /var/log/",
					"INSERT",
					"UPDATE",
					"DELETE"
					]

	#
	# start WEB and DNS servers 
	#
	for int_host in ["h3", "h4"]:
		h = net.get(int_host)
		h.cmd("ip route add default via 10.0.0.1")

	for web in ["ws1", "ws2", "ws3"]:
		wb = net.get(web)
		print("[{}] Starting HTTP server on port 80".format(web))
		wb.cmd("python3 -m http.server 80 &")
		wb.cmd("ip route add default via 100.0.0.45")

		print("[{}] Spawning testing WebServer on port 8080".format(web))
		wb.cmd("python3 -m http.server 8080 &")
	
	print("[lb2] Spawning testing WebServer on LoadBalancer 100.0.0.25 on port 8080")
	net.get("lb2").cmd("python3 -m http.server 8080 &")

	for dns in ["ds1", "ds2", "ds3"]:
		print("[{}] Starting DNS server on port 53".format(dns))
		dns_host = net.get(dns)
		dns_host.cmd("sudo python dns_server.py {} 53 &".format(dns_host.IP()))
		dns_host.cmd("ip route add default via 100.0.0.45")

		#print("Spawning testing DNS server on {} port 5353".format(dns_host))
		dns_host.cmd("sudo python dns_server.py {} 5353 &".format(dns_host.IP()))
		print("[{}] Spawning testing DNS Server on port 5353".format(dns_host))
	
	print("[lb1] Spawning testing DNS server on LoadBalancer 100.0.0.25")
	net.get("lb1").cmd("sudo python dns_server.py 100.0.0.25 5353 &")
	# needed because for some reason resolv.conf get a wrong entry making dns resolution crash
	net.get("lb1").cmd("echo nameserver 1.1.1.1 > /etc/resolv.conf")

	print("[INSP] Starting TCPDUMP for traffic capture on insp machine")
	
	net.get("insp").cmd("tcpdump -i insp-eth0 -vvv tcp -w ../results/ids_capture.pcap &")	

	# TESTING
	#
	#print(net.get("h1").cmd("curl 100.0.0.45 -m1 -s -X HEAD"))
	#CLI(net)
	#net.get("insp").cmd('kill -s SIGINT $(ps aux | grep tcpdump | awk \'{print $2}\')')
	#net.stop()
	#import sys
	#sys.exit(0)

	################
	#### TEST
	################
	info("####### STARTING TESTS #######  ")
	sleep(1)
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


	#all_hosts = hosts["int"].values()+hosts["ext"].values()
	all_hosts_obj = hosts["int"].keys()+hosts["ext"].keys()
	all_servers = srv_list["dns"] + srv_list["web"]
	## common tests from all hosts
	for h in all_hosts_obj:
		h = net.get(h)
		

		for lb_ip in [srv_list["web_lb"], srv_list["dns_lb"]]:
			info("[PING TEST] host {} to LoadBalancer {} must work: ".format( h, lb_ip)),
			res = int(h.cmd('ping -c 1 -W 1 {}'.format(lb_ip) + '> /dev/null; echo $?'))
			print('ping -c 1 -W 1 {}'.format(lb_ip) + ' > /dev/null; echo $?')
			info( ok() if res == 0 else err() )

		for test_ip in all_servers:
			info("[PING TEST] host {} to server {} must NOT work: ".format( h, test_ip)),
			res = int(h.cmd('ping -c 1 -W 1 {}'.format(test_ip) + ' > /dev/null; echo $?'))
			info( ok() if res != 0 else err() )
		### DNS TESTING
		for dns_ip in srv_list["dns"]:
			info("[DNS TEST] host {} to internal DNS {} must NOT work: ".format( h, dns_ip)),
			res = int(h.cmd('dig @{}'.format(dns_ip) + ' +timeout=1 +tries=1 ciao.it >/dev/null; echo $?'))
			info( ok() if res != 0 else err())

			# bogus DNS port
			info("[DNS BOGUS TEST] host {} to internal DNS port 5353 {} must NOT work: ".format( h, dns_ip)),
			res = int(h.cmd('dig -p 5353 @{}'.format(dns_ip) + ' +timeout=1 +tries=1 ciao.it >/dev/null; echo $?'))
			info( ok() if res != 0 else err() )

		# Testing DNS towards the virtual IP
		info("[DNS TEST] host {} to DNS LoadBalancer {} must work: ".format( h, srv_list["dns_lb"])),
		res = int(h.cmd('dig @{}'.format(srv_list["dns_lb"]) + ' +timeout=1 +tries=1 ciao.it >/dev/null; echo $?'))
		info( ok() if res == 0 else err())
		
		info("[DNS BOGUS TEST] internal {} to internal DNS LoadBalancer port 5353 {} must NOT work: ".format( h, srv_list["dns_lb"])),
		res = int(h.cmd('dig -p 5353 @{}'.format(srv_list["dns_lb"]) + ' +timeout=1 +tries=1 ciao.it >/dev/null; echo $?'))
		info( ok() if res != 0 else err() )

		### WEB SERVER TESTING
		for web_ip in srv_list["web"]:
			info("[WEB TEST] host {} to internal WEB {} must NOT work: ".format( h, web_ip)),
			res = int(h.cmd('curl --connect-timeout 1 {}'.format(web_ip) + ' -s | grep DOCTYPE | wc | awk \'{print $1}\''))
			info( ok() if res == 0 else err())

			# bogus WEB
			info("[WEB BOGUS TEST] host {} to internal BOGUS WEB {} must NOT work: ".format( h, web_ip)),
			res = int(h.cmd('curl --connect-timeout 1 {}:8080'.format(web_ip) + ' -s | grep DOCTYPE | wc | awk \'{print $1}\''))
			info( ok() if res == 0 else err())
		
		# bogus WEB port
		info("[WEB BOGUS TEST] host {} to BOGUS WEB LoadBalancer {} must NOT work: ".format( h, srv_list["web_lb"])),
		res = int(h.cmd('curl --connect-timeout 1 {}:8080'.format(srv_list["web_lb"]) + ' -s | grep DOCTYPE | wc | awk \'{print $1}\''))
		info( ok() if res == 0 else err())

		# Now TESTING HTTP methods and injections
		# Testing methods that must go to the insp
		for http_rtype in http_block:
			info("[WEB TEST] host {} to  WEB LoadBalancer {} HTTP {} must NOT work: ".format( h, srv_list["web_lb"], http_rtype) )
			res = int(h.cmd("curl {} -m1 -s -X {} >/dev/null; echo $?".format(srv_list["web_lb"], http_rtype)))
			info( ok() if res != 0 else err())

		# TESTING POST/PUT, must work
		for http_rtype in http_allow:
			info('[WEB TEST] host {} to  WEB LoadBalancer {} HTTP {} must work: '.format( h, srv_list["web_lb"], http_rtype)  )
			res = int(h.cmd('curl {} -m1 -s -X {} >/dev/null; echo $?'.format(srv_list["web_lb"], http_rtype)))
			info( ok() if res == 0 else err())
		# TESTING PUT INJECTION
		for inj in injections:
			info("[WEB TEST INJ] host {} to  WEB LoadBalancer {} HTTP {} inj: {} must NOT work: ".format( h, srv_list["web_lb"], http_rtype, inj) )
			res = int(h.cmd("curl {} -m1 -s -X PUT --data \"{}\" >/dev/null; echo $?".format(srv_list["web_lb"], inj)))
			info( ok() if res != 0 else err())
	#############################################
	# NOW TESTING FROM THE EXTERNAL
	#############################################
	info("#################### NOW TESTING FROM THE EXTERNAL ####################")
	for external in hosts["ext"].keys(): 
		ext_host = net.get(external)
		for internal in hosts["int"].values():
			info("[PING TEST] external {} to external {} must NOT work: ".format(ext_host, internal)),
			res = int(ext_host.cmd('ping -c 1  {} 2> /dev/null'.format(internal) + '; echo $?'))
			info( ok() if res == 2 else err())


	#############################################
	# NOW TESTING FROM THE INTERNAL
	#############################################
	info("#################### NOW TESTING FROM THE INTERNAL ####################")

	for internal in hosts["int"]:
		int_host = net.get(internal)
		for external in hosts["ext"]:
			e_ip = hosts["ext"][external]
			info("[PING TEST] internal {} to external {} must work: ".format(internal, external)),
			res = int(int_host.cmd('ping -c 1 -W 1 {}'.format(e_ip) + '> /dev/null; echo $?'))
			info( ok() if res == 0 else err())
		
	info("\nRESULTS:")
	info("\tTOTAL SCORE {}/{}\n".format(total_ok, total_run))
	info("####### ENDING TESTS   #######  ")
	
	##############
	# END TEST
	##############

	CLI(net)
	net.get("insp").cmd('kill -s SIGINT $(ps aux | grep tcpdump | awk \'{print $2}\')')
	# pgrep tcpdump
	net.stop()

	#sudo ovs-vsctl show
	#sudo ovs-ofctl dump-flows s1