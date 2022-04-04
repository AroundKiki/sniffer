from scapy.all import show_interfaces, sniff


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


if __name__ == '__main__':
    show_interfaces()
    result = sniff(iface='Intel(R) Wi-Fi 6 AX201 160MHz', count=30)
    result.show()

