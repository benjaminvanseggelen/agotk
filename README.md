# AGOTK
The tool AGOTK sets up a man-in-the-middle attack (MITM) by means of ARP Poisoning to put itself between the gateway and the target. This way, AGOTK will receive all packets that the targets sends to the gateway, and vice versa AGOTK will receive all packets that the gate- way sends to the target. If AGOTK would only use this attack, then it would not be able to inspect a lot of packets because most packets these days are sent using HTTPS. To overcome this problem, AGOTK will route all packets to a proxy that prevents the upgrade from HTTP to HTTPS. In this case, the proxy is located at the same host as where AGOTK is located. If the proxy receives any HTTP requests to a specific website from the target, then the proxy will establish a secure HTTPS connection to that specific website using the data from the previous received HTTP request. After the response that the proxy receives from the specific website, the proxy forward the received response to the target by means of an HTTP connection.

In addition to that, the tool AGOTK can also be used in a way that only packets from a specific domain are sent to a proxy, rather than all packets. This can be done using DNS Spoofing that can inspect all DNS record that the target sends to the gateway and check whether the DNS request is a request for the target domain. If so, then it will send a request back with the IP address of the proxy. Hereby only packets that are send from and to the target domain will be redirect to the proxy.

## Requirements
To run this tool Python 3.8 is required as well as Linux as operating system.
AGOTK does not run on Windows or macOS.

## Installation
To install the packages, you need to enter the following:

```make```

## Usage
To run the module, you need to enter the following command:
```
sudo python -m AGOTK [-h] [-i INTERFACE] [-t TARGET] [-r RANGE] [-o OBTRUSIVE] [-d DOMAIN] [-n NEWIP] [--newip6 NEWIP6] [--filter FILTER]
```

If no interface is given, AGOTK will use the default one. If no target (i.e. an IP address of the target) is given, AGOTK will run a manual scan to get a list of IP addresses on the local network. If no range is given then AGOTK will scan on subnet {ip}/24.

For help, you need to enter the following command:

```sudo python -m AGOTK -h```

This will show you a list of parameters with explanations.

### Examples
Attack target '192.168.0.15' with ARP Poisoning and SSLStrip.  
```sudo python -m AGOTK -t 192.168.0.15```

Scan targets and choose, then do ARP Poisoning and SSLStrip. Block HTTPS and Quic traffic.  
```sudo python -m AGOTK -o```

Scan targets over range '192.168.0.0/16' on interface 'vboxnet0' and choose, then do ARP Poisoning and SSLStrip:  
```sudo python -m AGOTK -r 192.168.0.0/16 -i vboxnet0```

Scan and choose target, and spoof the domain 'example.com' with new A record '192.168.0.10' and (optionally) AAAA record '2001:0db8::0001:0000':  
```sudo python -m AGOTK -d example.com --newip 192.168.0.10 --newip6 2001:0db8::0001:0000``` 
