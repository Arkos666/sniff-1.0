#! /usr/bin/env python3

# common libraries
from time import time
import json
import constants

# library to control signal from main code
from PyQt5.QtCore import pyqtSignal

# libraries to control ip traffic through scapy
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import getmacbyip, Ether
from scapy.sendrecv import sendp

# libraries used for ping part
from ping3 import ping, verbose_ping
import socket
import regex as re

'''
## SCANNING NETWORK ##
 1.- Scan TCP/IP protocol the seconds we select in the variable seconds
 2.- Include all MAC's scanned to a dictionary of dictionaries (MAC:{IP,VENDOR,NAME}) 

## MAC/VENDOR MATCHING ##
 3.- We're going to read MAC vendors from csv file to a dictionary
 4.- We will create a csv with MAC;IP;VENDOR; hostname (if it has hostname)
'''
JsonFile = "MacVendors.json"
filter_stopped = False


def ping_scan(sinout, ip_init, ip_dest):

    ip_init = ip_init.split(".", 3)
    ip_dest = ip_dest.split(".", 3)
    print(ip_init[3])
    print(ip_dest[3])
    dict_scan={}
    space_for_bar = (int(ip_dest[3]) - int(ip_init[3]))

    for i in range(int(ip_init[3]), int(ip_dest[3])):
        ip = ip_init[0] + "." + ip_init[1] + "." + ip_init[2] + "." + str(i)
        ping_ok = ping(ip, timeout=2, ttl=5)
        print(f"{ip} : {ping_ok}")
        if isinstance(ping_ok, float):
            dict_scan[getmacbyip(ip).replace(":", "").upper()] = ip
        loading_bar(sinout, 0, i * space_for_bar )
        if filter_stopped:
            break

    dict_vendor = read_json()
    dict_result = {}
    dict_result = search_mac(dict_vendor, dict_scan, dict_result)
    return dict_result


# we write in dict_result, the dict_scan result, adding vendor (from dict_vendor)
# and hostname if it has one (or IP) if it hasn't
def search_mac(dict_vendor, dict_scan, dict_result):
    # we're going to search for mac's results in vendors
    for mac_vendor in dict_vendor:
        for mac_scanned in dict_scan:
            # the start may be the same between mac_vendor and mac scanned
            if mac_scanned.startswith(mac_vendor):
                dict_summary = {constants.vendor(): dict_vendor[mac_vendor]}
                ip = dict_scan[mac_scanned]
                dict_summary[constants.ip()] = ip

                # if we don't find a name, we will return the IP
                try:
                    # gethostbyaddr return 3 names we check if one of them is a str
                    host = socket.gethostbyaddr(ip)
                    for hostname in host:
                        if isinstance(hostname, str):
                            dict_summary[constants.name()] = hostname
                    if not constants.name() in dict_summary:
                        dict_summary[constants.name()] = ip
                except:
                    dict_summary[constants.name()] = ip

                dict_result[mac_scanned] = dict_summary
    return dict_result


# packet scan
def packet_deploy(sinout: pyqtSignal, start_time: float, dict_scan: dict, sec: int):
    def upload_packet(packet):

        if packet.haslayer(constants.arp()):
            # upload packet, using passed arguments
            dict_scan[packet[constants.arp()].hwsrc.replace(":", "").upper()] = packet[constants.arp()].psrc
            loading_bar(sinout, start_time, sec)
            # print(dict_scan)
        elif packet.haslayer(constants.ip()):
            if packet[constants.ip()].dst == '127.0.0.1':
                global filter_stopped
                filter_stopped = True

            if not (getmacbyip(packet[0][1].src) is None):
                dict_scan[getmacbyip(packet[0][1].src).replace(":", "").upper()] = packet[0][1].src
                # loading()
                loading_bar(sinout, start_time, sec)
            if not (getmacbyip(packet[0][1].dst) is None):
                dict_scan[getmacbyip(packet[0][1].dst).replace(":", "").upper()] = packet[0][1].dst
                # loading()
            loading_bar(sinout, start_time, sec)
            # print(dict_scan)

    return upload_packet


def loading_bar(sinout, start_time, sec):
    if start_time == 0:
        ellapsed = sec
    else:
        ellapsed = int(((time() - start_time) * 100) / sec)
    sinout.emit(ellapsed)
    # ProgressBar.setValue(ellapsed)
    return


def read_json():
    f = open(JsonFile)
    data = json.load(f)
    f.close()
    dict_vendor = {}

    for vendor in data[constants.vendor().lower()]:
        for mac in data[constants.vendor().lower()][vendor]:
            dict_vendor[mac.upper()] = vendor
    return dict_vendor


def send_packet():
    packet_ = Ether() / IP(dst='127.0.0.1') / TCP(dport=53, flags='S')
    sendp(packet_)


def stopfilter(x):
    global filter_stopped
    if filter_stopped:
        filter_stopped = False
        return True
    else:
        return False


def scan_network(sinout, sec):
    dict_scan = {}
    start_time = time()

    # sniffing traffic from SCAPPY
    sniff(prn=packet_deploy(sinout, start_time, dict_scan, sec), timeout=sec, store=0, stop_filter=stopfilter)

    ''' now we have all the MACs and IP's in a dictionary, we're going to relation between vendors
     We're going to read JSON file which has the MAC Vendor that we want know'''
    dict_vendor = read_json()
    dict_result = {}
    dict_result = search_mac(dict_vendor, dict_scan, dict_result)

    return dict_result
