from scapy.all import *
from typing import List

def arp_scan(interface: str, ip_range: str) -> List[str]:
    """Runs a ARP scan over specified ip range over specific interface. Returns list of detected ip addresses"""
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_range), iface=interface, timeout=2, verbose=False)

    ip_addresses = []
    for req, res in ans:
        ip_addresses.append(req[ARP].pdst)

    return ip_addresses


def scan(interface: str, ip_range: str) -> List[str]:
    print(f'Scanning port range {ip_range} with interface {interface}')
    
    ip_addresses = arp_scan(interface, ip_range)

    return ip_addresses

