from scapy.all import *
import sys

"""
@args none, so by default the machine's IP will be used for scan or one can specify 
@returns target_list - the pair of (ip, mac) of all hosts in the network
	target_list[0][0] = ip address of the first machine 
	target_list[0][1] = mac address of the first machine
"""
def scan(ip=None):

	if ip is None:
		ip = get_if_addr(conf.iface) # doesn really work with the ip of the host yet xd

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

