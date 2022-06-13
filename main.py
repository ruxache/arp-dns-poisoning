# some ideas for user dialogues
import parser
import scan
# import validators
import arp
from urllib.parse import urlparse
import sys

args = parser.import_args()


def is_valid_link(x):
    try:
        result = urlparse(x)
        return all([result.scheme, result.netloc])
    except:
        return False

# scan the network for hosts
interface = ' '
hosts = ' '
try:
    interface = scan.interface()
    if not interface:
        raise Exception
except Exception:
    print("There was an issue with the interface.")
    sys.exit()

if interface:
    try:
        hosts = scan.ip(interface)
        if not hosts:
            raise Exception
        else:
            print("Successful scanning on the interface", interface)
            print("------------------------------------------------------------------\n")
            print("The following hosts are up and running:")
            for host in hosts:
                print("[*] Host with IP", host[0], "and MAC", host[1]) 
    except Exception:
        print("No hosts have been scanned in this interface. Configure some and try again.")
        sys.exit()
if args.ARP:
    interval = args.ARP
    print("------------------------------------------------------------------\n")
    arp.Poison(interface, hosts, interval).poison()

elif args.DNS:
    websites = args.DNS

    no_issue = True  # check if there is an issue with one of the urls. assume there is no issue
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
                print(
                    "-", url, "is not a valid weblink. Did you append \"https://\" or \"http://\"?")
