#! /usr/bin/env python3

from scapy.all import sniff, getmacbyip, ARP
#from PyQt5.QtWidgets import QProgressBar
from PyQt5 import QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from time import time, sleep
import json
import sys

from multiprocessing import Process


## SCANNING NETWORK ##
## 1.- Scan TCP/IP protocol the seconds we select in the variable seconds
## 2.- Scan from ARP packets the seconds we select in the variable seconds
## 3.- Include all MAC's scanned to a dictionary "MAC":"IP"

## MAC/VENDOR MATCHING ##
## 4.- We're going to read MAC vendors from csv file to a dictionary
## 5.- We will create a csv with MAC;IP;VENDOR; hostname (if it has hostname)

sec = 20
JsonFile = "MacVendors.json"

prev_MACs = 0
  
def search_mac(dict_vendor, dict_result, dict_scan):
  # we're going to search for mac's results in vendors
  for mac_vendor in dict_vendor:
    for mac_scanned in dict_scan:
     # the start may be the same between mac_vendor and mac scanned
      if mac_scanned.startswith(mac_vendor):
        dict_summary = {}
        dict_summary ["VENDOR"] = dict_vendor[mac_vendor]
        ip = dict_scan[mac_scanned]
        dict_summary ["IP"] = ip
        
        # if we don't find a name, we will return the IP
        try:
          # gethostbyaddr return 3 names we check if one of them is a str
          host = socket.gethostbyaddr(ip)
          for hostname in host:
            if isinstance(hostname, str):
              dict_summary ["NAME"] = hostname
          if not "NAME" in dict_summary:
            dict_summary ["NAME"] = ip
        except :
          dict_summary ["NAME"] = ip

        dict_result [mac_scanned] = dict_summary
  return dict_result
  
# packet scan
def packet_deploy(ProgressBar: QProgressBar, start_time: float, dict_scan: dict):
  def upload_packet(packet):
    if packet.haslayer("ARP"):
    # upload packet, using passed arguments
      dict_scan[(packet[ARP].hwsrc).replace(":", "").upper()] = packet[ARP].psrc
      LoadingBar(ProgressBar, start_time)
      # print(dict_scan)
    elif  packet.haslayer("IP"):
      if not (getmacbyip(packet[0][1].src) is None):
        dict_scan[getmacbyip(packet[0][1].src).replace(":", "").upper()] = packet[0][1].src
        #loading()
        LoadingBar(ProgressBar, start_time)
      if not (getmacbyip(packet[0][1].dst) is None):
        dict_scan[getmacbyip(packet[0][1].dst).replace(":", "").upper()] = packet[0][1].dst
        #loading()
      LoadingBar(ProgressBar, start_time)
      # print(dict_scan)
  return upload_packet
  
def LoadingBar(ProgressBar, start_time):
  ellapsed =  int(((time() - start_time)*100) / sec)
  ProgressBar.setValue(ellapsed)
  
def loading():
  global prev_MACs
  if prev_MACs < len(dict_scan):
    prev_MACs = len(dict_scan)
    print("Total MACs: " + str(prev_MACs))
  return
  
def read_json():
  f = open(JsonFile)
  data  = json.load(f)
  f.close()
  dict_vendor= {}
  
  for vendor in data["vendor"]:
    for mac in data["vendor"][vendor]:
      dict_vendor[mac.upper()] = vendor
  return dict_vendor
  
def scan_network(ProgressBar):

  dict_scan = {}
  start_time = time()
    
  # sniffing traffic from SCAPPY
  sniff(prn=packet_deploy(ProgressBar, start_time, dict_scan), timeout = (sec/2), store=0)
 
  ## now we have all the MACs and IP's in a dictionary, we're going to relation between vendors
  # We're going to read JSON file which has the MAC Vendor that we want know
  dict_vendor = read_json()
  dict_result = {}
  dict_result = search_mac(dict_vendor, dict_result, dict_scan)

  # filling progressBar
  for x in range(ProgressBar.value(), 101):
    sleep(0.02)
    ProgressBar.setValue(x)

  return dict_result