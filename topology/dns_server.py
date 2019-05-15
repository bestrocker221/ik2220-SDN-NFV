#!/bin/python
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP
import sys, socket

DNS_SERVER_IP = sys.argv[1]
DNS_SERVER_PORT = int(sys.argv[2])

dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.bind((DNS_SERVER_IP, DNS_SERVER_PORT))
print(f"Forwarding DNS queries to local {DNS_SERVER_IP}:{DNS_SERVER_PORT} IP")

#print("UDP socket ready.")

while True:
	data, addr = dns_socket.recvfrom(1024) # buffer size is 1024 bytes
	
	pkt = DNS(data)
	
	if pkt and pkt.haslayer(DNS):
		print(f"Got DNS query for: {pkt[DNSQR].qname} from {addr[0]}")

		# Generate a simple response with the DNS server IP as response.
		spf_resp = DNS(id=pkt.id, qr=1, ancount=1, \
							qd=DNSQR(qname=pkt[DNSQR].qname),\
							an=DNSRR(rrname=pkt[DNSQR].qname, rdata=DNS_SERVER_IP)
						)
		dns_socket.sendto(bytes(spf_resp), addr)