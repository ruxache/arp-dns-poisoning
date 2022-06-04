import argparse, os, sys, scan

parser = argparse.ArgumentParser(description='Tool for ARP Spoofing/Poisoning and DNS Spoofing/Poisoning')
parser.add_argument('-ip', '--ip', type=str, metavar='', required=True, nargs='+', help='List of IP addresses')
args = parser.parse_args()

for j in args.ip:
	result = scan.scan(j)
	if not result:
		print("No hosts have been scanned in this local network. Try configuring some and try again.")
	else:
		print(result)