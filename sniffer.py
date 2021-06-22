#! /usr/bin/env python3
from scapy.all import sniff, getmacbyip, ARP
import json
import socket

import sys
from PyQt5.QtWidgets import QDialog, QApplication
from main_window import Ui_Dialog


## Primero vamos a escanear la red durante 60 segundos
## Intentaremos abrir 3 thread para trabajar en paralelo

## SCANNING NETWORK ##
## 1.- Scan TCP/IP protocol the seconds we select in the variable seconds
## 2.- Scan from ARP packets the seconds we select in the variable seconds
## 3.- Include all MAC's scanned to a dictionary "MAC":"IP"

## MAC/VENDOR MATCHING ##
## 4.- We're going to read MAC vendors from csv file to a dictionary
## 5.- We will create a csv with MAC;IP;VENDOR; hostname (if it has hostname)

sec = 10 # Seconds to scan the network
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
    dict_scan[getmacbyip(packet[0][1].src).replace(":", "").upper()] = packet[0][1].src
    loading()
  if not (getmacbyip(packet[0][1].dst) is None):
    dict_scan[getmacbyip(packet[0][1].dst).replace(":", "").upper()] = packet[0][1].dst
    loading()
  return 

# ARP packet scan
def arp_deploy(pkt):
  dict_scan[(pkt[ARP].hwsrc).replace(":", "").upper()] = pkt[ARP].psrc
  loading()
  return
  
def search_mac(dict_vendor, dict_result):
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
    
  
def read_json():
  f = open(JsonFile)
  data  = json.load(f)
  f.close()
  
  dict_vendor= {}
  
  for vendor in data["vendor"]:
    #print (data["vendor"][vendor])
    for mac in data["vendor"][vendor]:
      #print(mac)
      dict_vendor[mac.upper()] = vendor
  
  #print(dict_vendor)
  
  return dict_vendor
  
def create_windows():
  master = Tk()
  w = Canvas(master, width=40, height=60)
  w.pack()
  canvas_height=20
  canvas_width=200
  y = int(canvas_height / 2)
  w.create_line(0, y, canvas_width, y )
  mainloop()  

class AppWindow(QDialog):
  
  def __init__(self):
    super().__init__()
    self.ui = Ui_Dialog()
    self.ui.setupUi(self)
    
    def on_button_clicked():
      scan_network()
      
    self.ui.OK_button.clicked.connect(on_button_clicked)
    self.show() 
    
def scan_network():
      print ("Scanning during " + str(sec) + " seconds")
      # sniffing ARP traffic from SCAPPY
      sniff(filter="arp", prn=arp_deploy, timeout = (sec/2), store=0)
      # sniffing IP traffic from SCAPPY
      sniff(filter="ip", prn=ip_deploy, timeout = (sec/2))
      ## now we have all the MACs and IP's in a dictionary, we're going to relation between vendors
      # We're going to read JSON file which has the MAC Vendor that we want know
      dict_vendor = read_json()
      dict_result = {}
      dict_result = search_mac(dict_vendor, dict_result)
      #print(dict_result)
      
      for mac in dict_result:
        s = dict_result[mac]["IP"] + ":" + dict_result[mac]["VENDOR"]
        print (s)



if __name__ == '__main__':
  
  app = QApplication(sys.argv)
  w = AppWindow()
  
  #w.ui.OK_button.clicked.connect(on_button_clicked())
  w.show()
  sys.exit(app.exec_())
  
  
  

  
  