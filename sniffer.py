#! /usr/bin/env python3
import pathlib
import sys
import csv
from tkinter import Tk, Canvas, mainloop

from PyQt5.QtWidgets import QDialog, QApplication, QTableWidget, QFileDialog
from PyQt5.QtWidgets import QMessageBox, QTableWidgetItem

from PyQt5.QtGui import *
from PyQt5.QtCore import *

from main_window import Ui_Dialog
from time import sleep
from scapy_mod import scan_network, send_packet, ping_scan
import constants

import regex as re

g_dict_result = {}


# worker for export
class ExportWorker(QThread):
    sinout_err = pyqtSignal(OSError)
    sinout_OK = pyqtSignal(str)

    def __init__(self, myvar, parent=None):
        super(ExportWorker, self).__init__(parent)
        self.myvar = myvar[0]
        self.file = ""

    def __del__(self):
        self.wait()

    def run(self):
        a = False
        try:
            file_name = self.file

            table = QTableWidget()
            if not a:
                table = self.myvar.ui.lst_Result

            with open(file_name, "w") as fileOutput:
                writer = csv.writer(fileOutput, delimiter=';')

                for row in range(table.rowCount()):
                    rowdata = []
                    for column in range(table.columnCount()):
                        item = table.item(row, column)
                        if item is not None:
                            rowdata.append(
                                item.text())
                        else:
                            rowdata.append('')
                    writer.writerow(rowdata)

            self.sinout_OK.emit("")

            if a:
                raise IOError("Error not defined")
        except IOError as e:
            self.sinout_err.emit(e)


# worker for sniffing
class Worker(QThread):
    # signal to fill progressbar
    sinout = pyqtSignal(int)

    def __init__(self, myvar, parent=None):
        super(Worker, self).__init__(parent)
        self.myvar = myvar[0]

    def __del__(self):
        self.wait()

    def run(self):
        seconds = self.myvar.ui.txt_time.value()

        # we fill g_dict_result inside scan_network
        # it also controls progressbass filling through sinout signal
        global g_dict_result
        g_dict_result = {}
        g_dict_result = scan_network(self.sinout, seconds)

        # we manual fill the rest of progressbar
        for x in range(self.myvar.ui.progressBar.value(), 100):
            sleep(0.01)
            self.sinout.emit(x)

        if not (self.myvar.ui.progressBar.value() == 100):
            self.sinout.emit(100)


# worker for sniffing
class WorkerPing(QThread):
    # signal to fill progressbar
    sinout = pyqtSignal(int)

    def __init__(self, myvar, parent=None):
        super(WorkerPing, self).__init__(parent)
        self.myvar = myvar[0]

    def __del__(self):
        self.wait()

    def run(self):

        # we fill g_dict_result inside scan_network
        # it also controls progressbass filling through sinout signal
        global g_dict_result
        g_dict_result = {}
        ip1 = self.myvar.ui.txt_From.toPlainText()
        ip2 = self.myvar.ui.txt_Dest.toPlainText()
        g_dict_result = ping_scan(self.sinout, ip1, ip2)

        # we manual fill the rest of progressbar
        for x in range(self.myvar.ui.progressBar.value(), 100):
            sleep(0.01)
            self.sinout.emit(x)

        if not (self.myvar.ui.progressBar.value() == 100):
            self.sinout.emit(100)


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
    def slot_export_error(self, e):
        QMessageBox.warning(self, "Text - Error",
                            "Failed to export\n\n%s" % e)

    def slot_export_ok(self, message):
        QMessageBox.information(self, "OK", "File is exported correctly")

    def slot_progress(self, val_bar):
        # we disable ok button at start
        if self.ui.btn_OK.isEnabled():
            self.ui.btn_OK.setEnabled(False)

            self.ui.lst_Result.clear()
            self.ui.lst_Result.setColumnCount(0)
            self.ui.lst_Result.setRowCount(0)
        self.ui.progressBar.setValue(val_bar)

        # if val_bar is 100% we populate de table with g_dict_result values
        if val_bar == 100:
            self.create_table()
            self.thread.__del__()

    def create_table(self):
        global g_dict_result

        row = 0
        table_widget = self.ui.lst_Result
        table_widget.setRowCount(len(g_dict_result))
        table_widget.setColumnCount(4)
        table_widget.setHorizontalHeaderLabels([constants.mac(), constants.ip(), constants.vendor(),
                                                constants.name()])
        for mac in g_dict_result:
            table_widget.setItem(row, 0, QTableWidgetItem(mac))
            table_widget.setItem(row, 1, QTableWidgetItem(g_dict_result[mac][constants.ip()]))
            table_widget.setItem(row, 2, QTableWidgetItem(g_dict_result[mac][constants.vendor()]))
            table_widget.setItem(row, 3, QTableWidgetItem(g_dict_result[mac][constants.name()]))
            row += 1

        self.ui.lst_Result.resizeColumnsToContents()
        self.ui.btn_OK.setEnabled(True)
        self.ui.btn_Cancel.setEnabled(True)
        if g_dict_result == {}:
            self.ui.btn_Export.setEnabled(False)
        else:
            g_dict_result = {}
            self.ui.btn_Export.setEnabled(True)

    def __init__(self):
        super().__init__()

        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.lst_Result.setRowCount(0)

        def check_option():
            for item in self.ui.groupList:
                if item.isChecked():
                    return item

        o_worker = Worker(myvar=[self])
        self.thread = o_worker
        o_worker_ping = WorkerPing(myvar=[self])

        def on_cancel_clicked():
            if self.thread.isRunning():
                self.ui.btn_Cancel.setEnabled(False)
                send_packet()
            else:
                self.close()

        self.ui.btn_Cancel.clicked.connect(lambda: on_cancel_clicked())
        self.thread.sinout.connect(self.slot_progress)
        o_worker_ping.sinout.connect(self.slot_progress)

        def on_button_clicked():
            if check_option() == self.ui.chk_Sniff:
                seconds = self.ui.txt_time.value()

                if seconds == 0:
                    QMessageBox.information(self, "0 seconds message", "Time cannot be 0 seconds.",
                                            QMessageBox.Close)
                else:
                    self.thread.start()

            elif check_option() == self.ui.chk_Ping:
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
                    o_worker_ping.start()

        self.ui.btn_OK.clicked.connect(on_button_clicked)

        worker_export = ExportWorker(myvar=[self])
        worker_export.sinout_err.connect(self.slot_export_error)
        worker_export.sinout_OK.connect(self.slot_export_ok)

        def on_btn_export_clicked():
            title = "Save CSV"
            directory = str(pathlib.Path(__file__).parent.resolve())
            filter_ = "CSV Files (*.csv)"
            file_tuple = QFileDialog.getSaveFileName(self, title, '', filter_ )
            filename = file_tuple[0]

            if filename == "":
                return
            else:
                worker_export.file = filename
                worker_export.start()

        self.ui.btn_Export.clicked.connect(on_btn_export_clicked)

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
    app.setWindowIcon(QIcon('bullet50.png'))

    w.show()
    sys.exit(app.exec_())
