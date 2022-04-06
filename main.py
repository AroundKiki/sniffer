# from scapy.all import show_interfaces, sniff
# from scapy.arch.windows import *
# conf.prog.powershell = None  # Enable VBS fallback
from scapy.all import *
# import scapy.all as scapy
from PyQt5 import QtCore, QtGui, QtWidgets
from program_ui import *


if __name__ == '__main__':
    import sys


    # print('start')
    # show_interfaces()
    # result = sniff(iface='Intel(R) Wi-Fi 6 AX201 160MHz')
    # result.show()
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

