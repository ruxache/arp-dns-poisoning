# some ideas for user dialogues
import parser
import scan
# import validators
import arp
from urllib.parse import urlparse

args = parser.import_args()


def is_valid_link(x):
    try:
        result = urlparse(x)
        return all([result.scheme, result.netloc])
    except:
        return False

# scan the netowrk for hosts
interface = ' '
hosts = ' '

try:
    interface = scan.scanInterface()
    if not interface:
        raise Exception('interface')
    hosts = scan.scanIP()
    if not hosts:
        print("balamuc")
        raise Exception('hosts')
except Exception:
    print("There was an issue with the interface or the scanned hosts.")

# print("No hosts have been scanned in this local network. Configure some and try again.")



if args.ARP:
    interval = 10
    print("arp your mom")

    # arp.Poison(interface, hosts, interval).poison()
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
