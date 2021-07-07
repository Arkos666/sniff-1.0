from PyQt5 import QtGui
from PyQt5.QtWidgets import * # QApplication, QDialog, QProgressBar, QPushButton, QVBoxLayout
import sys
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QRect
from scapy.all import sniff, getmacbyip, ARP, get_if_addr, sr
from time import time, sleep

def scan_network(ProgressBar, sec):

  dict_scan = {}
  start_time = time()
  print (dict_scan)
 
def packet_deploy(change_value: pyqtSignal, start_time: float, dict_scan: dict, sec: int):
  def upload_packet(packet):
    if packet.haslayer("ARP"):
    # upload packet, using passed arguments
      dict_scan[(packet[ARP].hwsrc).replace(":", "").upper()] = packet[ARP].psrc
      LoadingBar(change_value, start_time, sec)
  return upload_packet
  
def LoadingBar(change_value, start_time, sec):
  ellapsed =  int(((time() - start_time)*100) / sec)
  change_value.emit(ellapsed)
  
class MyThread(QThread):
    def __init__(self, myvar, parent = None):
        super(MyThread,self).__init__(parent)
        self.myvar = myvar[0]
        
    change_value = pyqtSignal(int)
    def run(self):
        seconds = self.myvar.txt_From.toPlainText()
        print (seconds)
        cnt = 0
        sec = 10
        dict_scan = {}
        start_time = time()
        sniff(prn=packet_deploy(self.change_value, start_time, dict_scan, sec), timeout = (sec), store=0)
        print (dict_scan)
        
class Window(QDialog):
    def __init__(self):
        super().__init__()
        self.title = "PyQt5 ProgressBar"
        self.top = 200
        self.left = 500
        self.width = 300
        self.height = 200
        self.setWindowIcon(QtGui.QIcon("icon.png"))
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        vbox = QVBoxLayout()
        self.progressbar = QProgressBar()
        self.progressbar.setMaximum(100)
        self.progressbar.setStyleSheet("QProgressBar {border: 2px solid grey;border-radius:8px;padding:1px}"
                                       "QProgressBar::chunk {background:yellow}")
        
        vbox.addWidget(self.progressbar)
        self.button = QPushButton("Start Progressbar")
        self.button.clicked.connect(self.startProgressBar)
        self.button.setStyleSheet('background-color:yellow')
        
        
        self.txt_From = QTextEdit()
        self.txt_From.setObjectName(u"txt_From")
        self.txt_From.setGeometry(QRect(0, 0, 151, 21))
        vbox.addWidget(self.txt_From)
        
        vbox.addWidget(self.button)
        self.setLayout(vbox)
        self.show()
 
    def startProgressBar(self):
        self.thread = MyThread(myvar=[self])
        self.thread.change_value.connect(self.setProgressVal)
        self.thread.start()
 
    def setProgressVal(self, val):
         self.progressbar.setValue(val)
 
 
App = QApplication(sys.argv)
window = Window()
sys.exit(App.exec())