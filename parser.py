import argparse, os, sys, scan
#simport arp

def import_args():
	parser = argparse.ArgumentParser(description='Tool for ARP Spoofing/Poisoning and DNS Spoofing/Poisoning')

	# specify which hosts are the victims. if not specified, all machines in the network will be poisoned
	parser.add_argument('-v', '--victimIP', type=str, metavar='', required=False, nargs='+', help='List of IP addresses') 

	# choose ARP, packets will be intercepted by default
	parser.add_argument('-A', '--ARP', type=int, metavar='', help='Choose to perform ARP poisoning. Provide mandatory frquency in which packets will be sent (integer).')

	# parser.add_argument('-A', '--ARP', type=bool, metavar='', action='store_true', help='True - ARP attack will be performed, False - no ARP attack')  action='store_true'

	# choose DNS
	# the arguments will be the websites that will be spoofed
	parser.add_argument('-D', '--DNS', type=str, metavar='', required=False, nargs='+', help='True - DNS attack will be performed, False - no DNS attack')

	#parser.add_argument('-s', '--silent', type=bool, metavar='', required=False, nargs='+', help='Silent attack or all out?')

	return parser.parse_args()