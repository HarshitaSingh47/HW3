import ipaddress
import socket

import dpkt
import sys

ipadr = ['192.168.0.100', '192.168.0.103', '192.168.0.1']

macadr = ['7c:d1:c3:94:9e:b8', 'd8:96:95:01:a5:c9', 'f8:1a:67:cd:57:6e']
c = 0
arpcounter = 0


def prettify(mac_string):
    return ':'.join('%02x' % ord(b) for b in mac_string)


def bytes_to_ip(ip_bytes):
    print("Method was called", ip_bytes)
    if type(ip_bytes) != bytes:
        raise ValueError('invalid bytes')
    try:
        print("WE here")
        return str(ipaddress.IPv4Address(ip_bytes))
    except:
        print("We got an error")
        return str(ipaddress.IPv6Address(ip_bytes))


def parse_pcap(inputfile, c, arpcounter=0):
    print("We got the filename here: ", inputfile)
    f = open(inputfile, 'rb')
    pcap = dpkt.pcap.Reader(f)
    for (ts, buf) in pcap:

        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            mac_src = eth.arp.sha.hex(":")
            mac_dst = eth.arp.tha.hex(":")
            ip_src = socket.inet_ntoa(eth.arp.spa)
            ip_dst = socket.inet_ntoa(eth.arp.tpa)
            if not ((ipadr[0] == ip_src and macadr[0] == mac_src ) or (ipadr[1] == ip_src and macadr[1] == mac_src) or (ipadr[2] == ip_src and macadr[2] == mac_src)):
                print("ARP spoofing!")
                print("Source MAC: ", mac_src)
                print("Dst MAC: ", mac_dst)
                print("Packet number: ", c)
        c = c + 1

if __name__ == '__main__':
    inputfile = str(sys.argv[1])
    # inputfile = "arpspoofing.pcap"
    print("This is the filename : ", inputfile)
    parse_pcap(inputfile, c, 0)
