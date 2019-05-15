define ($ip 100.0.0.2,
        $mac aa:aa:aa:aa:aa:aa)

fd  :: FromDevice("sw1-eth1");
td  :: ToDevice("sw1-eth2");

c :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);

fd -> c

c[0] -> Print("ARPREQ",-1)
	-> Discard
c[1] -> Print("ARPANS", -1)
	-> Discard
c[2] -> Print("IP_PKT", -1) 
	-> Queue -> td

//Discard non-IP, non-ARP packets
c[3] -> Print("DISCARDING PACKET") -> Discard

// SAME FROM IN TO OUT

from_int :: FromDevice(sw1-eth2)
to_ext :: ToDevice(sw1-eth1)

cl2 :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);

from_int -> cl2
cl2[0] -> Print("ARPREQ",-1)
	-> Discard
cl2[1] -> Print("ARPANS", -1)
	-> Discard
cl2[2] -> Print("IP_PKT", -1) 
	-> Queue -> to_ext

//Discard non-IP, non-ARP packets
cl2[3] -> Print("DISCARDING PACKET") -> Discard


