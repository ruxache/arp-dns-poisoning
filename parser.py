import argparse, os, sys, scan
#simport arp

def import_args():
	parser = argparse.ArgumentParser(add_help=True, description='Tool for ARP Poisoning with SSL stripping capabilities and DNS Poisoning')

	# choose ARP, packets will be intercepted by default
	parser.add_argument('-A', '--ARP', type=int, metavar='', required=False, help='Choose to perform ARP poisoning. Provide mandatory frquency in which packets will be sent (integer). 10 seconds are recommended')

	parser.add_argument('-s', '--silent', action='store_true', help='Choose to do a silent attack. The intercepted packets will be forwarded back if -s is selected.') 

	# the arguments will be the websites that will be spoofed
	parser.add_argument('-D', '--DNS', type=str, metavar='', required=False, help="The server IP address to which the web traffic on the victim's machine will be redirected to.")

	# parser.add_argument('-h', '--help')

	return parser.parse_args()