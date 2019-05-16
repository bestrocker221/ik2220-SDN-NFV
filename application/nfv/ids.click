define (//$sw_int_ip 10.0.0.1,
		//$sw_ext_ip 100.0.0.1,
		//$int_if sw1-eth2,
		//$ext_if sw1-eth1
		)

//AddressInfo(
//	DmZ		$sw_ext_ip $ext_if,
//	PrZ		$sw_int_ip $int_if,
//);


// 1 in, 2 out
counter_in1, counter_in2, counter_out1, counter_out2 :: AverageCounter;
arp_1, ip1 :: Counter;
arp_2, ip2 :: Counter;
to_drop1 :: Counter;
counter_insp :: Counter;

// setup ifaces
from_ext  :: FromDevice($ext_if, METHOD LINUX, SNIFFER false);
from_int  :: FromDevice($int_if, METHOD LINUX, SNIFFER false);
to_ext	:: ToDevice($ext_if, METHOD LINUX);
to_int  :: ToDevice($int_if, METHOD LINUX);
to_insp :: ToDevice($insp_if, METHOD LINUX)

// QUEUES for outgoing traffic
to_int_queue :: Queue(1024) -> counter_out1 -> to_int;
to_ext_queue :: Queue(1024) -> counter_out2 -> to_ext;
to_insp_queue :: Queue(1024)-> counter_insp -> to_insp;

// 12/0806 20/0001 ARP request
// 12/0806 20/0002 ARP response
// 12/0800 IP traffic

// classifier (ARP, IP, else)
ext_cl_first :: Classifier(12/0806 , 12/0800, -);
int_cl :: Classifier(12/0806 , 12/0800, -);

ext_cl_second :: Classifier(23/01,       //ICMP packets
							47/02,       //SYN
							47/12,       //SYN ACK
							47/10,       //ACK
							47/04,       //RST
							47/11,       //FIN ACK
							//47/18,		 //PSH ACK actual http requests has psh ack
							-);

							//72/48545450, //HTTP/1.1 PUT packets (3 letters)
							//73/48545450, //HTTP/1.1 POST packets (4 letters)

ext_cl_third :: Classifier(// HTTP
						66/474554,                          // GET
						66/48454144,                        // HEAD
						66/5452414345, 						// TRACE
						66/4f5054494f4e53, 					// OPTIONS
						66/44454c455445, 					// DELETE
						66/434f4e4e454354, 					// CONNECT
						// ids must ONLY allow
						66/504f5354,						// POST
						66/505554,							// PUT
						-);

injections_cl :: Classifier(
						209/636174202f6574632f706173737764,//cat passwd
                        209/636174202f7661722f6c6f672f,    //cat varlog
                        208/494E53455254,                  //INSERT
                        208/555044415445,                  //UPDATE
                        208/44454C455445,                  //DELETE
                        -);

// forwarding from inside to outside
from_int -> counter_in1 -> int_cl;

int_cl[0] -> arp_1 -> to_ext_queue;
int_cl[1] -> ip1 -> to_ext_queue;
int_cl[2] -> to_drop1 -> Discard;


// FROM OUT TO IN
//first round
from_ext -> counter_in2 -> ext_cl_first;

ext_cl_first[0] -> arp_2 -> to_int_queue;
ext_cl_first[2] -> to_int_queue

//second round
ext_cl_first[1] -> ip2 -> ext_cl_second;  

// TCP SIGNALING ALLOWED
ext_cl_second[0] -> to_int_queue;
ext_cl_second[1] -> to_int_queue;
ext_cl_second[2] -> to_int_queue;
ext_cl_second[3] -> to_int_queue;
ext_cl_second[4] -> to_int_queue;
ext_cl_second[5] -> to_int_queue;

//ext_cl_second[6] -> to_int_queue; // PSH ACK

//third round
ext_cl_second[6] -> ext_cl_third;

// DISCARDING HTTP METHODS
ext_cl_third[0] -> Print("HTTP GET") -> to_insp_queue;  	//GET 
ext_cl_third[1] -> Print("HTTP HEAD")-> to_insp_queue; 	//HEAD
ext_cl_third[2] -> Print("HTTP TRACE")-> to_insp_queue;	//TRACE
ext_cl_third[3] -> Print("HTTP OPTIONS")-> to_insp_queue;	//OPTIONS
ext_cl_third[4] -> Print("HTTP DELETE")-> to_insp_queue;	//DELETE
ext_cl_third[5] -> Print("HTTP CONNECT")-> to_insp_queue;	//CONNECT
ext_cl_third[8] -> to_int_queue 	// allowing other traffic

// ALLOWING HTTP POST
ext_cl_third[6] -> Print("HTTP POST")-> to_int_queue;	//POST


// PASSING PUT TO FURTHER CHECKS
ext_cl_third[7]  -> Print("HTTP PUT") -> injections_cl;	//PUT

// injections found -> forward to inspector
injections_cl[0] -> to_insp_queue;
injections_cl[1] -> to_insp_queue;
injections_cl[2] -> to_insp_queue;
injections_cl[3] -> to_insp_queue;
injections_cl[4] -> to_insp_queue;

// NO INJECTION MATCH - FORWARD NORMAL HTTP PUT TRAFFIC
injections_cl[5] -> to_int_queue;



// report
DriverManager(wait , print > ../../results/ids.counter  "
	=================== IDS Report ===================
	Input Packet Rate (pps): $(add $(counter_in1.rate) $(counter_in2.rate))
	Output Packet Rate(pps): $(add $(counter_out1.rate) $(counter_out2.rate))

	Total # of ARP packets: $(add $(arp_1.count) $(arp_2.count))
	Total # of service requests packets: $(add $(ip1.count) $(ip2.count))

	Total # of input packets: $(add $(counter_in1.count) $(counter_in2.count))
	Total # of output packets: $(add $(counter_out1.count) $(counter_out2.count))
	Total # of dropped packets: $(to_drop1.count)
	Total # of packets to inspector: $(counter_insp.count)
	==================================================
" , stop);

