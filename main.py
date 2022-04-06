# from scapy.all import show_interfaces, sniff
# from scapy.arch.windows import *
# conf.prog.powershell = None  # Enable VBS fallback
from scapy.all import *
# import scapy.all as scapy



if __name__ == '__main__':
    print('start')
    show_interfaces()
    result = sniff(iface='Intel(R) Wi-Fi 6 AX201 160MHz')
    result.show()

