from scapy.all import *
import sys

"""
@args none, so by default the machine's IP will be used for scan or one can specify 
@returns target_list - the pair of (ip, mac) of all hosts in the network
	target_list[0][0] = ip address of the first machine 
	target_list[0][1] = mac address of the first machine
"""
def ip(iface):

	targets = []

	def discover_on_interface(pckt):
		
		if IP in pckt:

			# check the source
			sMAC = pckt[Ether].src
			sIP = pckt[IP].src
			add_target(sIP, sMAC)

			# check the destination
			dMAC = pckt[Ether].dst
			dIP = pckt[IP].dst
			add_target(dIP, dMAC)

			
		if ARP in pckt:

			# check the source
			sMAC = pckt[Ether].hwsrc
			sIP = pckt[IP].psrc
			add_target(sIP, sMAC)

			if pckt[ARP].op == 1:

				# check the destination
				dMAC = pckt[Ether].hwsrc
				dIP = pckt[IP].psrc
				add_target(dIP, dMAC)

	# updates the list of hosts. necessary to ensure there are no duplicates
	def add_target(ip, mac):
		host = [ip, mac]

		# make sure we don't attack the attacker machine lol
		if ip != get_if_addr(iface) and mac != get_if_hwaddr(iface):
			if host not in targets:
				targets.append(host)

	sniff(iface=iface, prn=discover_on_interface, store=0, timeout=1)


	return targets


def interface():
	interfaces =  get_if_list()

	print("Pick one interface:")
	counter = 1
	for i in interfaces:
		print("[", counter, "]:", i)
		counter += 1

	answr = int(input())
	answr -= 1
	try:
		if answr not in range(0, len(interfaces)):
			raise Exception
	except Exception:
		return 
	else:
		print("Chosen interface: ", interfaces[answr])
		return interfaces[answr]
