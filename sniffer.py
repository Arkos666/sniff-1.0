#! /usr/bin/env python3
#from scapy.all import sniff
#import socket
import sys
from PyQt5.QtWidgets import QDialog, QApplication, QProgressBar, QRadioButton
from PyQt5.QtWidgets import QMessageBox

from main_window import Ui_Dialog
from time import time
from scapy_mod import scan_network
import constants


#sec = 10 # Seconds to scan the network

# dict_scan = {}# This dict will give the IP from given MAC
IP = constants.ip()
Vendor = constants.vendor()
  
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
    
    def check_Option():
      for item in self.ui.groupList:
        if item.isChecked():
          group_sel = item
          return  item
    
    def on_button_clicked():  
      
      if (check_Option() == self.ui.chk_Sniff):
        seconds = self.ui.txt_time.value()
        
        if seconds == 0:
          buttonReply = QMessageBox.information(self, "0 seconds message", "Time cannot be 0 seconds.", QMessageBox.Close)
        else:
          dict_result = scan_network(self.ui.progressBar, seconds)
          
          for mac in dict_result:
            line = dict_result[mac][IP] + ":" + dict_result[mac][Vendor]
            self.ui.lst_Result.addItem(line)
      elif (check_Option() == self.ui.chk_Sniff):
        buttonReply = QMessageBox.information(self, "Ping", "Ping", QMessageBox.Close)
        
    self.ui.btn_OK.clicked.connect(on_button_clicked)
    
    def sel_group():
      group_sel = QRadioButton()
      ## we're going to check wich button is selected
      for item in self.ui.groupList:
        l = self.ui.dict_check[item].setEnabled(item.isChecked())
        if item.isChecked():
          group_sel = item
    
    sel_group()
    
    self.ui.chk_Sniff.clicked.connect(sel_group)
    self.ui.chk_Ping.clicked.connect(sel_group)
    
    
     
    
    self.show()
    
    


if __name__ == '__main__':
  app = QApplication(sys.argv)
  w = AppWindow()
  w.show()
  sys.exit(app.exec_())
  
  
  

  
  