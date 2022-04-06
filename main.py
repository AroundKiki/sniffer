# from scapy.all import show_interfaces, sniff
# from scapy.arch.windows import *
# conf.prog.powershell = None  # Enable VBS fallback
from scapy.all import *
# import scapy.all as scapy
from PyQt5 import QtCore, QtGui, QtWidgets
from program_ui import *


class MainView(Ui_MainWindow, QtWidgets.QMainWindow):
    interface = ""
    filter = ""
    catchList = []

    def __init__(self):
        super().__init__()

    def init_ui(self, main_window):
        super().setupUi(main_window)
        ##TODO: configure after data transferred in
        pass

    def init_slot(self):
        self.tableWidget.itemClicked.connect(self.show_detail)  # tableWidget是显示抓到的包的信息的表格，单击展开内容

    def get_interfaces(self):
        # 获得网卡列表
        pass

    def start_sniffer(self):
        # 开始抓包
        pass

    def update_table(self):
        # 将抓到的包刷新到表格当中
        pass

    def show_detail(self):
        # 展示包信息
        pass

    def save_to_cap(self):
        # 保存为cap文件
        pass

    def stop_sniffer(self):
        # 停止抓包
        pass




if __name__ == '__main__':
    import sys


    # print('start')
    # show_interfaces()
    # result = sniff(iface='Intel(R) Wi-Fi 6 AX201 160MHz')
    # result.show()
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = MainView()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

