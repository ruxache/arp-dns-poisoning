# some ideas for user dialogues
import parser
import scan
import validators
from urllib.parse import urlparse

args = parser.import_args()

def is_valid_link(x):
    try:
        result = urlparse(x)
        return all([result.scheme, result.netloc])
    except:
        return False

# scan the netowrk for hosts
# result = scan.scan("10.0.3.14/16")
# if not result:
#	print("No hosts have been scanned in this local network. Configure some and try again.")
# else:if is_valid_link(url):
			#print("One URL was not correct. Please check: ", url)
			#issue = True
			#break
#	print(result)

# TODO: write those functions

if args.ARP:
	arp.posion()
elif args.DNS:
	websites = args.DNS

	no_issue = True # check if there is an issue with one of the urls. assume there is no issue
	for url in websites:
		no_issue = no_issue and is_valid_link(url)
		
	if no_issue:
		# HERE YOU CALL DNS POISONING FUNCTION
		print(websites)
	else:
		print("Cannot begin DNS poisoning. One or more URLs were not correct.\n")
		print("------------------------------------------------------------------\n")
		for url in websites:
			if not is_valid_link(url):
				print("-", url, "is not a valid weblink. Did you append \"https://\" or \"http://\"?")
