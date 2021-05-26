from scapy.all import *
from typing import List

INTERFACE: str = 'enp10s0u1u3u3'

def arp_scan(ip_range: str) -> List[str]:
    """Runs a ARP scan over specified ip range. Returns list of detected ip addresses"""
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_range), timeout=2, verbose=False)

    ip_addresses = []
    for req, res in ans:
        ip_addresses.append(req[ARP].pdst)

    return ip_addresses



if __name__ == "__main__":
    ip_range: str = sys.argv[1]
    print(f'Scanning port range {ip_range}')
    
    ip_addresses = arp_scan(ip_range)

    print(f'Detected ip-addresses:')
    for ip in ip_addresses:
        print(ip)