import argparse, os, sys, scan
#simport arp

def import_args():
	parser = argparse.ArgumentParser(add_help=True, description='Tool for ARP Poisoning with SSL stripping capabilities and DNS Poisoning')

	# choose ARP, packets will be intercepted by default
	parser.add_argument('-A', '--ARP', type=int, metavar='', help='Choose to perform ARP poisoning. Provide mandatory frquency in which packets will be sent (integer).')

	parser.add_argument('-s', '--silent', action='store_true', help='Choose to do a silent attack. The packets will not be forwarded if -s is selected.') 

	# the arguments will be the websites that will be spoofed
	parser.add_argument('-D', '--DNS', type=str, metavar='', required=False, nargs='+', help='True - DNS attack will be performed, False - no DNS attack')

	# parser.add_argument('-h', '--help')

	return parser.parse_args()