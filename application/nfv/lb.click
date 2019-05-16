// 1 in, 2 out
counter_in1, counter_in2, counter_out1, counter_out2 :: AverageCounter;
arp_req1, arp_res1, icmp1, ip1 :: Counter;
arp_req2, arp_res2, icmp2, ip2, icmp3 :: Counter;
to_drop1, to_drop2, to_drop3, to_drop4 :: Counter;

// setup ifaces
from_ext  :: FromDevice($ext_if, METHOD LINUX, SNIFFER false);
from_int  :: FromDevice($int_if, METHOD LINUX, SNIFFER false);
to_ext	:: ToDevice($ext_if, METHOD LINUX);
to_int  :: ToDevice($int_if, METHOD LINUX);

// QUEUES for outgoing traffic
to_ext_queue :: Queue(1024) -> counter_out1 -> to_ext;
to_int_queue :: Queue(1024) -> counter_out2 -> to_int;


//
// managing network arping
//
// 12/0806 20/0001 ARP request
// 12/0806 20/0002 ARP response
// 12/0800 IP traffic

// ARPR, ARR , IP Classifiers
from_ext -> counter_in1 
		 -> ext_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
from_int -> counter_in2
		 -> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);


// respond to ARP queries  for the router external interface

ext_cl[0] -> arp_req1 -> ARPResponder($sw_ip $ext_if) -> to_ext_queue ;
ext_cl[1] -> arp_res1 -> [1]arp :: ARPQuerier($sw_ip, $ext_if);

// respond to ARP queries for the router internal interface
in_cl[0] -> arp_req2 -> ARPResponder($sw_ip $int_if) -> to_int_queue ;
in_cl[1] -> arp_res2 -> [1]in_arp :: ARPQuerier($sw_ip, $int_if);


to_ext_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]arp -> to_ext_queue;
to_in_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]in_arp -> to_int_queue;

// Classifying IP traffic
ext_cl[2] -> ip1 -> Strip(14) -> CheckIPHeader
	-> ext_ipc :: IPClassifier(
	// ping from out to gw
		icmp && icmp type echo and dst $sw_ip,
	// ping from out to in (generate error)
		icmp && icmp type echo and (dst $s1 or dst $s2 or dst $s3),
	//  tcp traffic  from ext to lb
		dst $sw_ip and $proto port $port,
	// ping resp to rewrited ping
		proto icmp && icmp type echo-reply,
	// others
		-
	);

in_cl[2] -> ip2 -> Strip(14) -> CheckIPHeader
	-> int_ipc :: IPClassifier(
	// ping from in to in
		icmp && icmp type echo and dst $sw_ip, 
	// tcp from int to ext
		$proto,
	// pings req to rewrite
		icmp && icmp type echo and dst != $sw_ip,
	// others
		-
		);

// PING BACK
// send back pings gw to outside
ext_ipc[0] -> Print("ICMP ECHO FROM EXT->GW")
	-> icmp3
    -> ICMPPingResponder
    -> to_ext_arp_queue ;

// send back pings error gw to outside
ext_ipc[1] -> Print("ICMP ECHO FROM EXT-> IN")
    -> ICMPError($sw_ip, 3, 1 ) //host - unreachable
    -> icmp1
    -> to_ext_arp_queue ;

// send back pings to inside from inside
int_ipc[0] -> Print("ICMP ECHO FROM INT -> INT")
	-> ICMPPingResponder
	-> icmp2
	-> to_in_arp_queue;

//Discard non-IP, non-ARP packets 
ext_cl[3] -> Print("DISCARDING NON IP PACKET") -> to_drop1 -> Discard;
in_cl[3] -> Print("DISCARDING NON IP PACKET") -> to_drop2 -> Discard;

ext_ipc[4] -> Print("DISCARDING UNWANTED IP PACKET") -> to_drop3 -> Discard;
int_ipc[3] -> Print("DISCARDING UNWANTED IP PACKET") -> to_drop4 -> Discard;
 

// NAT 
// int_ipc[1] = internal IP traffic to outside
// int_ipc[2] = internal ICMP traffic to outside

// ext_ipc[2] = external IP traffic to inside 
// ext_ipc[3] = external ICMP traffic to inside 


ping_rw :: ICMPPingRewriter(pattern $sw_ip 1025-65535# - - 0 1)

ping_rw[1] 	-> to_in_arp_queue
ping_rw[0] ->  to_ext_arp_queue

rr :: RoundRobinIPMapper( $sw_ip - $s1 - 0 1,
						  $sw_ip - $s2 - 0 1,
						  $sw_ip - $s3 - 0 1
						)

rw :: IPRewriter(rr);


rw[0] -> SetTCPChecksum -> to_in_arp_queue;
rw[1] -> SetTCPChecksum -> to_ext_arp_queue;

// FROM EXTERNAL

ext_ipc[2] -> Print("IP from EXT to INT") -> [0]rw;
ext_ipc[3] -> Print("ICMP from EXT to INT") -> [0]ping_rw;

// FROM INTERNAL

int_ipc[1] -> Print("IP from INT to EXT") -> [0]rw;
int_ipc[2] -> Print("ICMP from INT to EXT") -> [0]ping_rw;


// report
DriverManager(wait , print > ../../results/lb$lb.counter  "
	=================== LB $lb Report ===================
	Input Packet Rate (pps): $(add $(counter_in1.rate) $(counter_in2.rate))
	Output Packet Rate(pps): $(add $(counter_out1.rate) $(counter_out2.rate))

	Total # of ARP requests packets: $(add $(arp_req1.count) $(arp_req2.count))
	Total # of ARP responses packets: $(add $(arp_res1.count) $(arp_res2.count))
	Total # of service requests packets: $(add $(ip1.count) $(ip2.count))
	Total # of ICMP packets: $(add $(icmp1.count) $(icmp2.count) $(icmp3.count))

	Total # of input packets: $(add $(counter_in1.count) $(counter_in2.count))
	Total # of output packets: $(add $(counter_out1.count) $(counter_out2.count))
	Total # of dropped packets: $(add $(to_drop1.count) $(to_drop2.count) $(to_drop3.count) $(to_drop4.count) )
	==================================================
" , stop);
