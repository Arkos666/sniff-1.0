#! /usr/bin/env python3
from scapy.all import sniff, getmacbyip, ARP
import json


## Primero vamos a escanear la red durante 60 segundos
## Intentaremos abrir 3 thread para trabajar en paralelo

## SCANNING NETWORK ##
## 1.- Scan TCP/IP protocol the seconds we select in the variable seconds
## 2.- Scan from ARP packets the seconds we select in the variable seconds
## 3.- Include all MAC's scanned to a dictionary "MAC":"IP"

## MAC/VENDOR MATCHING ##
## 4.- We're going to read MAC vendors from csv file to a dictionary
## 5.- We will create a csv with MAC;IP;VENDOR; hostname (if it has hostname)

sec = 5 # Seconds to scan the network
JsonFile = "MacVendors.json"


prev_MACs = 0
dict_scan = {}# This dict will give the IP from given MAC

def loading():
  global prev_MACs
  if prev_MACs < len(dict_scan):
    prev_MACs = len(dict_scan)
    print("Total MACs: " + str(prev_MACs))
  return

# IP packet scan
def ip_deploy(packet):    
  if not (getmacbyip(packet[0][1].src) is None):
    dict_scan[getmacbyip(packet[0][1].src)] = packet[0][1].src
    loading()
  if not (getmacbyip(packet[0][1].dst) is None):
    dict_scan[getmacbyip(packet[0][1].dst)] = packet[0][1].dst
    loading()
  return 

# ARP packet scan
def arp_deploy(pkt):
  dict_scan[pkt[ARP].hwsrc] = pkt[ARP].psrc
  loading()
  return
  
def read_json():
  f = open(JsonFile)
  data  = json.load(f)
  
  for i in data["vendor"]:
    print(i)
  
  f.close()
  
  return 

if __name__ == '__main__':
  
  print ("Scanning during " + str(sec) + " seconds")
  
  # sniffing ARP traffic from SCAPPY
  sniff(filter="arp", prn=arp_deploy, timeout = (sec/2), store=0)
  
  # sniffing IP traffic from SCAPPY
  sniff(filter="ip", prn=ip_deploy, timeout = (sec/2))
  
  # now we have all the MACs and IP's in a dictionary, we're going to relation between vendors
  print(dict_scan)
  
  # We're going to read JSON file which has the MAC Vendor that we want know
  read_json()