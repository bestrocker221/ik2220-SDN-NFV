define ($sw_ext_ip 100.0.0.1,
        $mac_ext aa:aa:aa:aa:aa:aa,
		$sw_int_ip 1.1.1.1)


// setup ifaces
from_ext  :: FromDevice(sw1-eth1);
from_int  :: FromDevice(sw1-eth2);
to_ext	:: ToDevice(sw1-eth1);
to_int  :: ToDevice(sw1-eth2);

// QUEUES for outgoing traffic
to_int_queue :: Queue(1024) 
			-> to_int;

to_ext_queue :: Queue(1024) 
			-> to_ext;


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
arp :: ARPQuerier($sw_ext_ip, $mac_ext);
ext_cl[0] -> ARPResponder($sw_ext_ip $mac_ext) -> to_ext_queue ;
ext_cl[1] -> [1]arp;

// respond to ARP queries for the router int interface
in_cl[0] -> ARPResponder($sw_int_ip $mac_ext) -> to_int_queue ;
in_cl[1] -> [1]in_arp :: ARPQuerier($sw_int_ip, $mac_ext);

// Queues to arpQueriers and then to output queues
// i need a queue with push input (ip packets coming) and push output (to arp querier push input) and the only way i found is to concatente queue and unqueue. (maybe not good use of multiple queues). All of this is needed to have a queue before the arpQuerier so that i can reuse that from multiple sources.
to_ext_arp_queue :: Queue(1024) 
			-> Unqueue(1024)
			-> arp
			-> to_ext_queue;

to_in_arp_queue :: Queue(1024)
			-> Unqueue(1024)
			-> in_arp
			-> to_int_queue;



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
    -> to_ext_arp_queue ;

// send back pings gw to outside
ext_ipc[1] -> Print("ICMP ECHO FROM EXT-> IN")
    -> ICMPError($sw_ext_ip, 3, 1 ) //host unreachable
    -> to_ext_arp_queue ;

// send back pings to inside from inside
int_ipc[0] -> Print("ICMP ECHO FROM INT -> INT")
	-> ICMPPingResponder
	-> to_in_arp_queue;

//Discard non-IP, non-ARP packets (not captured)
//ext_cl[3] -> Print("DISCARDING PACKET") -> Discard
//in_cl[3] -> Print("DISCARDING PACKET") -> Discard



// NAT 
// int_ipc[1] = internal IP traffic to outside
// int_ipc[2] = internal ICMP traffic to outside

// ext_ipc[2] = external IP traffic to inside 
// ext_ipc[3] = external ICMP traffic to inside 

// pattern $sw_int_ip 1024-65535# - - 1 0,
//rw :: IPRewriter(pattern $sw_ext_ip 1024-65535# - - 0 1, drop);

//rw :: IPAddrPairRewriter(pattern $sw_ext_ip - 0 1, drop);

rw :: IPRewriter(pattern $sw_ext_ip 1025-65535# - - 0 1, drop);
ping_rw :: ICMPPingRewriter(pattern $sw_ext_ip 1025-65535# - - 0 1, drop)


// FROM INTERNAL
// to outside world or gateway from inside network

int_ipc[1] -> Print("IP from INT to EXT") -> [0]rw;
rw[0]	   -> to_ext_arp_queue;

int_ipc[2] -> Print("ICMP from INT to EXT") -> [0]ping_rw;
ping_rw[0] ->  to_ext_arp_queue


// FROM EXTERNAL

ext_ipc[2] -> Print("IP from EXT to INT") -> [1]rw;
rw[1]	   -> to_in_arp_queue;

ext_ipc[3] -> Print("ICMP from EXT to INT") -> [1]ping_rw;
ping_rw[1] 	-> to_in_arp_queue







//tcp_rw :: TCPRewriter(pattern $sw_ext_ip - 0 1, drop); 

//int_ipc[2] -> Print("TCP from INT to EXT") -> [0]tcp_rw;
//tcp_rw[0] -> arp -> to_ext_queue;

//ext_ipc[3] -> Print("TCP from EXT to INT") -> [1]tcp_rw;
//tcp_rw[1] -> in_arp -> to_int_queue;