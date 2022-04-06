# -*- coding: utf-8 -*-
from PyQt5.QtWidgets import *
from program_ui import *
from scapy.all import *
from scapy.layers import http
from datetime import datetime


class MainView(Ui_MainWindow, QtWidgets.QMainWindow):
    scapy_t = None
    filter = ""
    interface = ""
    catch_list = []
    count = 0
    to_show = 0

    def __init__(self):
        super(MainView, self).__init__()

    def setupUi(self, MainWindow):
        super(MainView, self).setupUi(MainWindow)

    def init_slot(self):
        self.count = 0
        self.to_show = 0

        self.comboBoxIface = QComboBox()
        self.toolBar.addWidget(self.comboBoxIface)
        self.get_interfaces()

        startAction = QAction('开始嗅探', self)
        startAction.triggered.connect(self.start_sniffer)
        self.toolBar.addAction(startAction)

        stopAction = QAction('停止嗅探', self)
        stopAction.triggered.connect(self.stop_sniffer)
        self.toolBar.addAction(stopAction)

    def get_interfaces(self):
        # TODO 展开网卡列表
        self.comboBoxIface.addItems(["Intel(R) Wi-Fi 6 AX201 160MHz"])

    def start_sniffer(self):
        global count
        global to_show
        count = 0
        to_show = 0
        self.catch_list = []
        self.tableWidget.removeRow(0)
        self.tableWidget.setRowCount(0)
        self.interface = self.comboBoxIface.currentText()
        self.scapy_t = ScapyThread(self.filter, self.interface)
        self.scapy_t.HandleSignal.connect(self.update_table)
        self.scapy_t.start()

    def update_table(self, packet):
        global count
        global to_show
        p_time = datetime.utcfromtimestamp(packet.time)
        p_type = packet.type

        if p_type == 0x800 :
            count += 1
            to_show = count
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(str(count)))
            self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(str(p_time)))
            self.tableWidget.setItem(row, 2, QtWidgets.QTableWidgetItem(packet[IP].src))
            self.tableWidget.setItem(row, 3, QtWidgets.QTableWidgetItem(packet[IP].dst))
            self.tableWidget.setItem(row, 5, QtWidgets.QTableWidgetItem(str(len(packet))))
            self.tableWidget.setItem(row, 7, QtWidgets.QTableWidgetItem(raw(packet).decode('Windows-1252', 'ignore')))

            if packet[IP].proto == 6:  #TCP
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:  #HTTP
                    self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('HTTP'))
                    if packet.haslayer('HTTPRequest'):
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s %s %s' % (packet.sprintf("{HTTPRequest:%HTTPRequest.Method%}").strip("'"),packet.sprintf("{HTTPRequest:%HTTPRequest.Path%}").strip("'"),packet.sprintf("{HTTPRequest:%HTTPRequest.Http-Version%}").strip("'"))))
                    elif packet.haslayer('HTTPResponse'):
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Status-Line%}").strip("'")))
                    else:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem(''))
                else:
                    self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('TCP'))
                    if packet.haslayer('TCP'):
                        flag = ''
                        if packet[TCP].flags.A:
                            if flag == '':
                                flag += 'ACK'
                            else:
                                flag += ',ACK'
                        if packet[TCP].flags.R:
                            if flag == '':
                                flag += 'RST'
                            else:
                                flag += ',RST'
                        if packet[TCP].flags.S:
                            if flag == '':
                                flag += 'SYN'
                            else:
                                flag += ',SYN'
                        if packet[TCP].flags.F:
                            if flag == '':
                                flag += 'FIN'
                            else:
                                flag += ',FIN'
                        if packet[TCP].flags.U:
                            if flag == '':
                                flag += 'URG'
                            else:
                                flag += ',URG'
                        if packet[TCP].flags.P:
                            if flag == '':
                                flag += 'PSH'
                            else:
                                flag += ',PSH'
                        if flag == '':
                            self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s Seq：%s Ack：%s Win：%s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack,packet[TCP].window)))
                        else:
                            self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s [%s] Seq：%s Ack：%s Win：%s' % (packet[TCP].sport,packet[TCP].dport,flag,packet[TCP].seq,packet[TCP].ack,packet[TCP].window)))
            elif packet[IP].proto == 17:  #UDP
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('UDP'))
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s 长度(len)：%s' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len)))
            elif packet[IP].proto == 1:   #ICMP
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('ICMP'))
                if packet.haslayer('ICMP'):
                    if packet[ICMP].type == 8:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Echo (ping) request id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq)))
                    elif packet[ICMP].type == 0:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Echo (ping) reply id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq)))
                    else:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('type：%s id：%s seq：%s' % (packet[ICMP].type,packet[ICMP].id,packet[ICMP].seq)))
            elif packet[IP].proto == 2:  #IGMP
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('IGMP'))
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem(''))
            else:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem(str(packet[IP].proto)))

        elif p_type == 0x806:  # ARP
            count += 1
            to_show = count
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(row,0, QtWidgets.QTableWidgetItem(str(count)))
            self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(str(p_time)))
            self.tableWidget.setItem(row,2, QtWidgets.QTableWidgetItem(packet[ARP].psrc))
            self.tableWidget.setItem(row,3, QtWidgets.QTableWidgetItem(packet[ARP].pdst))
            self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('ARP'))
            self.tableWidget.setItem(row,5, QtWidgets.QTableWidgetItem(str(len(packet))))
            if packet[ARP].op == 1:  #request
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Who has %s? Tell %s' % (packet[ARP].pdst,packet[ARP].psrc)))
            elif packet[ARP].op == 2:  #reply
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s is at %s' % (packet[ARP].psrc,packet[ARP].hwsrc)))
            self.tableWidget.setItem(row,7, QtWidgets.QTableWidgetItem(raw(packet).decode('Windows-1252','ignore')))

        self.catch_list.append(packet)

    def show_detail(self):
        # 展示包信息
        pass

    def save_to_cap(self):
        # 保存为cap文件
        pass

    def stop_sniffer(self):
        # 停止抓包
        self.scapy_t.terminate()


class ScapyThread(QtCore.QThread):
    HandleSignal = QtCore.pyqtSignal(scapy.layers.l2.Ether)
    filter = ""
    interface = ""

    def __init__(self, filter, interface):
        super().__init__()
        self.filter = filter
        self.interface = interface

    def run(self):
        sniff(filter=self.filter, iface=self.interface, prn=self.exception)

    def exception(self, signal):
        self.HandleSignal.emit(signal)


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = MainView()
    ui.setupUi(MainWindow)
    ui.init_slot()
    MainWindow.show()
    sys.exit(app.exec_())
