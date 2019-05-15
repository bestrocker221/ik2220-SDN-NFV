define ($h1 100.0.0.10,
		$sw_ext_ip 100.0.0.1,
        $mac_ext aa:aa:aa:aa:aa:aa,
		$ws2 1.1.1.5,
		$ws3 1.1.1.6,
		$sw_int_ip 1.1.1.1)


// setup ifaces
from_ext  :: FromDevice(sw1-eth1);
from_int  :: FromDevice(sw1-eth2);
to_ext	:: ToDevice(sw1-eth1);
to_int  :: ToDevice(sw1-eth2);

// QUEUES for outgoing traffic
to_int_queue :: Queue(1024) -> to_int
to_ext_queue :: Queue(1024) -> to_ext


//
// managing network arping
//
// 12/0806 20/0001 ARP request
// 12/0806 20/0002 ARP response
// 12/0800 IP traffic

// ARPR, ARR , IP Classifiers
from_int -> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800);
from_ext -> ext_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800);


// respond to ARP queries for the router ext interface
ext_cl[0] -> ARPResponder($sw_ext_ip $mac_ext) -> to_ext_queue ;
ext_cl[1] -> [1]arp :: ARPQuerier($sw_ext_ip, $mac_ext);

// respond to ARP queries for the router int interface
in_cl[0] -> ARPResponder($sw_int_ip $mac_ext) -> to_int_queue ;
in_cl[1] -> [1]in_arp :: ARPQuerier($sw_int_ip, $mac_ext);



// Classifying traffic
ext_cl[2] -> Strip(14) -> CheckIPHeader
	-> ext_ipc :: IPClassifier(
	// ping from out to gw
		proto icmp && icmp type echo and dst $sw_ext_ip,
	// ping from out to in (gen error)
		proto icmp && icmp type echo and dst $sw_int_ip/24,
	// all tcp udp traffic (or ping response) from ext to int
		$sw_ext_ip/24 dst $sw_ext_ip and (proto tcp or proto udp ),
	// ping resp to rewrite
		proto icmp && icmp type echo-reply
	);

in_cl[2] -> Strip(14) -> CheckIPHeader
	-> int_ipc :: IPClassifier(
	// ping from in to in
		proto icmp && icmp type echo and ($sw_int_ip/24 dst $sw_int_ip/24), 
	// tcp, udp or ping from int to ext
		$sw_int_ip/24 dst $sw_ext_ip/24 and (proto tcp or proto udp),
	// pings req to rewrite
		proto icmp && icmp type echo and dst != $sw_int_ip/24
		);

// PING BACK
// send back pings gw to outside
ext_ipc[0] -> Print("ICMP ECHO FROM EXT->GW")
    -> ICMPPingResponder
    -> arp
    -> to_ext_queue ;

// send back pings gw to outside
ext_ipc[1] -> Print("ICMP ECHO FROM EXT-> IN")
    -> ICMPError($sw_ext_ip, 3, 1 ) //host unreachable
    -> arp
    -> to_ext_queue ;

// send back pings to inside from inside
int_ipc[0] -> Print("ICMP ECHO FROM INT -> INT")
	-> ICMPPingResponder
	-> in_arp
	-> to_int_queue 

//Discard non-IP, non-ARP packets (not captured)
//ext_cl[3] -> Print("DISCARDING PACKET") -> Discard
//in_cl[3] -> Print("DISCARDING PACKET") -> Discard



// NAT 
// int_ipc[1] = internal IP traffic to outside
// ext_ipc[1] = external IP traffic to inside (if any)

// pattern $sw_int_ip 1024-65535# - - 1 0,
//rw :: IPRewriter(pattern $sw_ext_ip 1024-65535# - - 0 1, drop);

rw :: IPAddrPairRewriter(pattern $sw_ext_ip - 0 1, drop);
//rw :: IPRewriter(pattern $sw_ext_ip 1025-65535# - - 0 1, -);
ping_rw :: ICMPPingRewriter(pattern $sw_ext_ip 1025-65535# - - 0 1, drop)

// to outside world or gateway from inside network
int_ipc[1] -> Print("IP from INT to EXT") -> [0]rw;
rw[0]	   -> arp ->  to_ext_queue;

int_ipc[2] -> Print("ICMP from INT to EXT") -> [0]ping_rw;
ping_rw[0] ->  to_ext_queue

ext_ipc[2] -> Print("IP from EXT to INT") -> [1]rw;
rw[1]	   -> in_arp -> to_int_queue;

ext_ipc[3] -> Print("ICMP from EXT to INT") -> [1]ping_rw;
ping_rw[1] 	-> to_int_queue







//tcp_rw :: TCPRewriter(pattern $sw_ext_ip - 0 1, drop); 

//int_ipc[2] -> Print("TCP from INT to EXT") -> [0]tcp_rw;
//tcp_rw[0] -> arp -> to_ext_queue;

//ext_ipc[3] -> Print("TCP from EXT to INT") -> [1]tcp_rw;
//tcp_rw[1] -> in_arp -> to_int_queue;