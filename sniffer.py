#! /usr/bin/env python3
#from scapy.all import sniff
#import socket
import sys
from PyQt5.QtWidgets import QDialog, QApplication, QProgressBar
from main_window import Ui_Dialog
from time import time
# from scapy_mod import ip_deploy, arp_deploy, scan_network, read_json, sniff_arp
from scapy_mod import *



sec = 10 # Seconds to scan the network

dict_scan = {}# This dict will give the IP from given MAC
     
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
      dict_result = scan_network(self.ui.progressBar)

      for mac in dict_result:
        s = dict_result[mac]["IP"] + ":" + dict_result[mac]["VENDOR"]
        self.ui.listResult.addItem(s)
      
    self.ui.OK_button.clicked.connect(on_button_clicked)
    self.show()


if __name__ == '__main__':
  app = QApplication(sys.argv)
  w = AppWindow()
  w.show()
  sys.exit(app.exec_())
  
  
  

  
  