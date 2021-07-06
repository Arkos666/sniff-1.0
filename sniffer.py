#! /usr/bin/env python3
import sys
from tkinter import Tk, Canvas, mainloop

from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtWidgets import QMessageBox, QTableWidgetItem

from main_window import Ui_Dialog
from time import sleep
from scapy_mod import scan_network
import constants

import regex as re

from PyQt5.QtCore import *

IP = constants.ip()
Vendor = constants.vendor()
g_dict_result = {}


def populate_table(table, dict_table):
    print(dict_table)

    row_count = (len(dict_table))
    column_count = 4

    table.setColumnCount(column_count)
    table.setRowCount(row_count)

    table.setHorizontalHeaderLabels((list(dict_table[0].keys())))

    for row in range(row_count):  # add items from array to QTableWidget
        for column in range(column_count):
            item = (list(dict_table[row].values())[column])
            table.setItem(row, column, QTableWidgetItem(item))
    return


class Worker(QThread):
    sinout = pyqtSignal(int)
    sintaable = pyqtSignal(dict)

    def __init__(self, myvar, parent=None):
        super(Worker, self).__init__(parent)
        self.working = True
        self.num = 0
        self.myvar = myvar[0]

    def __del__(self):
        self.working = False
        self.wait()

    def run(self):
        self.myvar.ui.btn_OK.setEnabled(False)
        seconds = self.myvar.ui.txt_time.value()

        global g_dict_result
        g_dict_result = {}
        g_dict_result = scan_network(self.sinout, seconds)

        for x in range(self.myvar.ui.progressBar.value(), 101):
            sleep(0.01)
            self.sinout.emit(x)

        if not (self.myvar.ui.progressBar.value() == 100):
            self.sinout.emit(100)

        self.myvar.ui.btn_OK.setEnabled(True)


def create_windows():
    master = Tk()
    canvas = Canvas(master, width=40, height=60)
    canvas.pack()
    canvas_height = 20
    canvas_width = 200
    y = int(canvas_height / 2)
    canvas.create_line(0, y, canvas_width, y)
    mainloop()


class AppWindow(QDialog):
    def slot_add(self, val_bar):

        self.ui.progressBar.setValue(val_bar)
        if val_bar == 100:
            global g_dict_result
            print(g_dict_result)

            row = 0

            table_widget = self.ui.lst_Result
            table_widget.setRowCount(len(g_dict_result))
            table_widget.setColumnCount(4)
            table_widget.setHorizontalHeaderLabels(["MAC", IP, Vendor, constants.name()])

            for mac in g_dict_result:
                table_widget.setItem(row, 0, QTableWidgetItem(mac))
                table_widget.setItem(row, 1, QTableWidgetItem(g_dict_result[mac][IP]))
                table_widget.setItem(row, 2, QTableWidgetItem(g_dict_result[mac][Vendor]))
                table_widget.setItem(row, 3, QTableWidgetItem(g_dict_result[mac][constants.name()]))
                row += 1

            self.ui.lst_Result.resizeColumnsToContents()

    def __init__(self):
        super().__init__()

        self.ui = Ui_Dialog()
        self.ui.setupUi(self)

        def check_option():
            for item in self.ui.groupList:
                if item.isChecked():
                    return item

        self.thread = Worker(myvar=[self])

        def on_cancel_clicked():
            print("CANCELLED")
            self.ui.btn_Cancel.setEnabled(False)
            self.thread.start()

        self.ui.btn_Cancel.clicked.connect(on_cancel_clicked)
        self.thread.sinout.connect(self.slot_add)

        def on_button_clicked():

            if check_option() == self.ui.chk_Sniff:
                seconds = self.ui.txt_time.value()

                if seconds == 0:
                    QMessageBox.information(self, "0 seconds message", "Time cannot be 0 seconds.",
                                            QMessageBox.Close)
                else:
                    self.thread.start()

                    '''
          dict_result = scan_network(self.ui.progressBar, seconds)
          
          
          for mac in dict_result:
            line = dict_result[mac][IP] + ":" + dict_result[mac][Vendor]
            self.ui.lst_Result.addItem(line)'''

            elif check_option() == self.ui.chk_Ping:
                # buttonReply = QMessageBox.information(self, "Ping", "Ping", QMessageBox.Close)
                pattern = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])\.){3}([1-9]|[1-9][0-9]|1[0-9]" \
                          r"{2}|2[0-4][0-9]|25[0-4])$"

                ip1 = self.ui.txt_From.toPlainText()
                ip2 = self.ui.txt_Dest.toPlainText()
                ip1 = "192.168.1.25"
                ip2 = "192.168.1.80"
                if re.match(pattern, ip1) is None:
                    QMessageBox.information(self, "Wrong IP", "First IP has not the right format",
                                            QMessageBox.Close)
                elif re.match(pattern, ip2) is None:
                    QMessageBox.information(self, "Wrong IP", "Second IP has not the right format",
                                            QMessageBox.Close)
                else:
                    # dict_result = r_ping(ip1, ip2, self.ui.progressBar)
                    dict_result = {}

                    for mac in dict_result:
                        line = dict_result[mac][IP] + ":" + dict_result[mac][Vendor]
                        self.ui.lst_Result.addItem(line)

        self.ui.btn_OK.clicked.connect(on_button_clicked)

        def sel_group():
            # we're going to check wich button is selected
            for item in self.ui.groupList:
                self.ui.dict_check[item].setEnabled(item.isChecked())

        sel_group()

        self.ui.chk_Sniff.clicked.connect(sel_group)
        self.ui.chk_Ping.clicked.connect(sel_group)

        self.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = AppWindow()
    w.show()
    sys.exit(app.exec_())
