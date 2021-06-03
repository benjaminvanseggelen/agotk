from scapy.all import *
from typing import List

def arp_scan(interface: str, ip_range: str) -> List[str]:
    """Runs a ARP scan over specified ip range over specific interface. Returns list of detected ip addresses"""
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_range), iface=interface, timeout=2, verbose=False)

    ip_addresses = []
    for req, res in ans:
        ip_addresses.append(req[ARP].pdst)

    return ip_addresses



if __name__ == "__main__":
    if len(sys.argv) == 3:
        interface: str = sys.argv[1]
        ip_range: str = sys.argv[2]
    else:
        interface = conf.iface
        ip_range: str = sys.argv[1]
    
    print(f'Scanning port range {ip_range} with interface {interface}')
    
    ip_addresses = arp_scan(interface, ip_range)

    print(f'Detected ip-addresses:')
    for ip in ip_addresses:
        print(ip)