# AGOTK
AGOTK is a tool that sets up a man-im-the-middle attack by means of ARP Poisoning to put itself between the gateay and the target. Using the man-in-the-middle position, it spoofs the DNS requests by answering with the IP of the device the tool is running on such that each messsage that the target sends will be send to a proxy server that AGOTK maintains. Within this proxy server AGOTK will apply SSL stripping.

## Requirements
To run this tool Python 3.8 is required as well as Linux as operaring system.

## Installation
To install the packages, you need to enter the following:

```make```

## Usage
To run the module, you need to enter the following command:

```sudo python -m AGOTK -i <interface> -t <target> -r <range>```

If no interface is given, AGOTK will use the default one. If no target (i.e. an IP address of the target) is given, AGOTK will run a manual scan to get a list of IP addresses on the local network. If no range is given then AGOTK will scan on subnet {ip}/24.

For help, you need to enter the following command:

```sudo python -m AGOTK -h```