from scapy.all import *
import sys

"""
ip - an ip in the network
target_list - the pair of (ip, mac) of all hosts in the network
"""
def scan(ip):
	# create an ARP packet
	arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)

	# send packets and receive answers
	answer_list = srp(arp, timeout=1, verbose=False)[0]

	target_list = []
	for host in answer_list:
		ip_address = host[1].psrc
		mac_address = host[1].hwsrc
		target_list.append([ip_address, mac_address])

	return target_list

