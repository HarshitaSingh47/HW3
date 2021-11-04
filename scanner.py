import ipaddress
import socket

import dpkt
import sys

ipadr=['192.168.0.100','192.168.0.103','192.168.0.1']

macadr = ['7c:d1:c3:94:9e:b8','d8:96:95:01:a5:c9','f8:1a:67:cd:57:6e']
c = 0

def bytes_to_ip(ip_bytes):
    if type(ip_bytes) != bytes:
        raise ValueError('invalid bytes')
    try:
        return str(ipaddress.IPv4Address(ip_bytes))
    except:
        return str(ipaddress.IPv6Address(ip_bytes))


def parse_pcap(inputfile):
    # c = c+1
    print("We got the filename here: ", inputfile)
    f = open(inputfile,'rb')
    pcap = dpkt.pcap.Reader(f)
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            arp = eth.arp
            # if arp.op == 1:
            #     print("Request")
            # elif arp.op == 2:
            #     print("Response")
                # src = socket.inet_ntoa(ip.src)
                # dst = socket.inet_ntoa(ip.dst)
                # print('Source: ' + src + ' Destination: ' + dst)




            # src = r''
            print("From: ", (eth.src))
            print(" to: ", (eth.dst))
            print(bytes_to_ip(eth.src))
            # read the source IP in src
            src = socket.inet_ntoa(ip.src)
            # read the destination IP in dst
            dst = socket.inet_ntoa(ip.dst)

            # Print the source and destination IP
            print('Source: ' + src + ' Destination: ' + dst)

        except:
            pass


if __name__ == '__main__':
    # inputfile = str(sys.argv[1])
    inputfile = "arpspoofing.py"
    print("This is the filename : ", inputfile)
    parse_pcap(inputfile)
