import argparse, os, sys

parser = argparse.ArgumentParser(description='Tool for ARP Spoofing/Poisoning and DNS Spoofing/Poisoning')
parser.add_argument('-ip', '--ip', type=str, metavar='', required=True, nargs='+', help='List of IP addresses')
args = parser.parse_args()
for j in args.ip:
	print(j)