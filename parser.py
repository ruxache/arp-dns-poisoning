import argparse, os, sys, scan

parser = argparse.ArgumentParser(description='Tool for ARP Spoofing/Poisoning and DNS Spoofing/Poisoning')

# specify which hosts are the victims. if not specified, all machines in the network will be poisoned
parser.add_argument('-v', '--victimIP', type=str, metavar='', required=False, nargs='+', help='List of IP addresses') 

# choose ARP
parser.add_argument('-A', '--ARP', type=bool, metavar='', required=False, nargs='+', help='True - ARP attack will be performed, False - no ARP attack') 

# choose DNS
parser.add_argument('-D', '--DNS', type=bool, metavar='', required=False, nargs='+', help='True - DNS attack will be performed, False - no DNS attack')

# choose to spoof
parser.add_argument('-s', '--spoof', type=bool, metavar='', required=False, nargs='+', help='Spoofing attack for chosen protocol')

# choose to poison
parser.add_argument('-p', '--poison', type=bool, metavar='', required=False, nargs='+', help='Poisoning attack for chosen protocol')

args = parser.parse_args()


result = scan.scan("10.0.3.14/24")
if not result:
	print("No hosts have been scanned in this local network. Configure some and try again.")
else:
	print(result)

# TODO: write those functions

if args.ARP and args.spoof:
	print("youve been spoofed")
	# ARP spoof function here
# elif args.ARP and args.poison:
	# ARP poisoning function here
# elif args.DNS and args.spoof:
	# DNS spoof function here
# elif args.DNS and args.poison:
	# DNS poisoning here