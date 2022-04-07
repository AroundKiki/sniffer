# -*- coding: utf-8 -*-
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from program_ui import *
from scapy.all import *
from scapy.layers import http
from datetime import datetime
from scapy.arch.windows import *


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
        #界面初始化
        super(MainView, self).setupUi(MainWindow)
        self.tableWidget.insertColumn(7)
        self.tableWidget.setColumnHidden(7, True)

    def init_slot(self):
        # 槽函数初始化
        self.count = 0
        self.to_show = 0

        self.tableWidget.itemClicked.connect(self.show_detail)
        self.comboBoxIface = QComboBox()
        self.toolBar.addWidget(self.comboBoxIface)
        self.get_interfaces()

        startAction = QAction('开始嗅探', self)
        startAction.triggered.connect(self.start_sniffer)
        self.toolBar.addAction(startAction)

        stopAction = QAction('停止嗅探', self)
        stopAction.triggered.connect(self.stop_sniffer)
        self.toolBar.addAction(stopAction)

        saveAction = QAction('保存到文件', self)
        saveAction.triggered.connect(self.save_to_cap)
        self.toolBar.addAction(saveAction)

    def get_interfaces(self):
        # 获得网卡列表
        interfaces = []
        for item in IFACES.data.values():
            interfaces.append(item.description)
        self.comboBoxIface.addItems(interfaces)

    def start_sniffer(self):
        # global count
        # global to_show
        self.count = 0
        self.to_show = 0
        self.catch_list = []
        self.tableWidget.removeRow(0)
        self.tableWidget.setRowCount(0)
        self.interface = self.comboBoxIface.currentText()
        self.scapy_t = ScapyThread(self.filter, self.interface)
        self.scapy_t.HandleSignal.connect(self.update_table)
        self.scapy_t.start()

    def update_table(self, packet):
        # 更新包列表
        self.count
        self.to_show
        p_time = datetime.utcfromtimestamp(packet.time)
        p_type = packet.type

        if p_type == 0x800:
            self.count += 1
            self.to_show = self.count
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(str(self.count)))
            self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(str(p_time)))
            self.tableWidget.setItem(row, 2, QtWidgets.QTableWidgetItem(packet[IP].src))
            self.tableWidget.setItem(row, 3, QtWidgets.QTableWidgetItem(packet[IP].dst))
            self.tableWidget.setItem(row, 5, QtWidgets.QTableWidgetItem(str(len(packet))))
            # self.tableWidget.setItem(row, 7, QtWidgets.QTableWidgetItem(raw(packet)))
            self.tableWidget.setItem(row, 7, QtWidgets.QTableWidgetItem(raw(packet).decode('windows-1252', 'ignore')))


            if packet[IP].proto == 6:  #TCP
                if packet.haslayer("TLS"):
                    self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('TLS'))
                    # if packet.haslayer('TLS'):
                    summary = packet[TLS].mysummary()
                    # else:
                    #     summary = ''
                    # print(summary)
                    self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem(summary))
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
                            self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s Seq=%s Ack=%s Win=%s' % (packet[TCP].sport, packet[TCP].dport, packet[TCP].seq, packet[TCP].ack, packet[TCP].window)))
                        else:
                            self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s [%s] Seq=%s Ack=%s Win=%s' % (packet[TCP].sport,packet[TCP].dport,flag,packet[TCP].seq,packet[TCP].ack,packet[TCP].window)))
            elif packet[IP].proto == 17:  #UDP
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('UDP'))
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s Len=%s' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len)))
            elif packet[IP].proto == 1:   #ICMP
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('ICMP'))
                if packet.haslayer('ICMP'):
                    if packet[ICMP].type == 8:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Echo (ping) request id=%s seq=%s' % (packet[ICMP].id,packet[ICMP].seq)))
                    elif packet[ICMP].type == 0:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Echo (ping) reply id=%s seq=%s' % (packet[ICMP].id,packet[ICMP].seq)))
                    else:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('type=%s id=%s seq=%s' % (packet[ICMP].type,packet[ICMP].id,packet[ICMP].seq)))
            elif packet[IP].proto == 2:  #IGMP
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('IGMP'))
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem(''))
            else:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem(str(packet[IP].proto)))

        elif p_type == 0x806:  # ARP
            self.count += 1
            self.to_show = self.count
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(row,0, QtWidgets.QTableWidgetItem(str(self.count)))
            self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(str(p_time)))
            self.tableWidget.setItem(row,2, QtWidgets.QTableWidgetItem(packet[ARP].psrc))
            self.tableWidget.setItem(row,3, QtWidgets.QTableWidgetItem(packet[ARP].pdst))
            self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('ARP'))
            self.tableWidget.setItem(row,5, QtWidgets.QTableWidgetItem(str(len(packet))))
            if packet[ARP].op == 1:  #request
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Who has %s? Tell %s' % (packet[ARP].pdst,packet[ARP].psrc)))
            elif packet[ARP].op == 2:  #reply
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s is at %s' % (packet[ARP].psrc,packet[ARP].hwsrc)))
            self.tableWidget.setItem(row,7, QtWidgets.QTableWidgetItem(raw(packet).decode('windows-1252','ignore')))

        self.catch_list.append(packet)

    def show_detail(self):
        # 展开包内容
        row = self.tableWidget.currentRow()  # 鼠标焦点
        r7 = self.tableWidget.item(row, 7)
        packet = scapy.layers.l2.Ether(r7.text().encode('windows-1252'))
        num = self.tableWidget.item(row, 0).text()
        Time = self.tableWidget.item(row, 1).text()
        length = self.tableWidget.item(row, 5).text()
        iface = self.interface
        import time
        timeformat = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))

        packet.show()
        self.treeWidget.clear()
        self.treeWidget.setColumnCount(1)

        # Frame
        Frame = QtWidgets.QTreeWidgetItem(self.treeWidget)
        Frame.setText(0, 'Frame %s：%s bytes on %s' % (num, length, iface))
        FrameIface = QtWidgets.QTreeWidgetItem(Frame)
        FrameIface.setText(0, '网卡设备：%s' % iface)
        FrameArrivalTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameArrivalTime.setText(0, '到达时间：%s' % timeformat)
        FrameTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameTime.setText(0, '距离第一帧时间：%s' % Time)
        FrameNumber = QtWidgets.QTreeWidgetItem(Frame)
        FrameNumber.setText(0, '序号：%s' % num)
        FrameLength = QtWidgets.QTreeWidgetItem(Frame)
        FrameLength.setText(0, '帧长度：%s' % length)

        # Ethernet
        Ethernet = QtWidgets.QTreeWidgetItem(self.treeWidget)
        Ethernet.setText(0, 'Ethernet，源MAC地址(src)：' + packet.src + '，目的MAC地址(dst)：' + packet.dst)
        EthernetDst = QtWidgets.QTreeWidgetItem(Ethernet)
        EthernetDst.setText(0, '目的MAC地址(dst)：' + packet.dst)
        EthernetSrc = QtWidgets.QTreeWidgetItem(Ethernet)
        EthernetSrc.setText(0, '源MAC地址(src)：' + packet.src)

        try:
            type = packet.type
        except:
            type = 0
        # IP
        if type == 0x800:
            EthernetType = QtWidgets.QTreeWidgetItem(Ethernet)
            EthernetType.setText(0, '协议类型(type)：IPv4(0x800)')

            IPv4 = QtWidgets.QTreeWidgetItem(self.treeWidget)
            IPv4.setText(0, 'IPv4，源地址(src)：' + packet[IP].src + '，目的地址(dst)：' + packet[IP].dst)
            IPv4Version = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Version.setText(0, '版本(version)：%s' % packet[IP].version)
            IPv4Ihl = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Ihl.setText(0, '包头长度(ihl)：%s' % packet[IP].ihl)
            IPv4Tos = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Tos.setText(0, '服务类型(tos)：%s' % packet[IP].tos)
            IPv4Len = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Len.setText(0, '总长度(len)：%s' % packet[IP].len)  # IP报文的总长度。报头的长度和数据部分的长度之和。
            IPv4Id = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Id.setText(0, '标识(id)：%s' % packet[
                IP].id)  # 唯一的标识主机发送的每一分数据报。通常每发送一个报文，它的值加一。当IP报文长度超过传输网络的MTU（最大传输单元）时必须分片，这个标识字段的值被复制到所有数据分片的标识字段中，使得这些分片在达到最终目的地时可以依照标识字段的内容重新组成原先的数据。
            IPv4Flags = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Flags.setText(0, '标志(flags)：%s' % packet[
                IP].flags)  # R、DF、MF三位。目前只有后两位有效，DF位：为1表示不分片，为0表示分片。MF：为1表示“更多的片”，为0表示这是最后一片。
            IPv4Frag = QtWidgets.QTreeWidgetItem(IPv4)

            IPv4FlagsDF = QtWidgets.QTreeWidgetItem(IPv4Flags)
            IPv4FlagsDF.setText(0, '不分段(DF)：%s' % packet[IP].flags.DF)
            IPv4FlagsMF = QtWidgets.QTreeWidgetItem(IPv4Flags)
            IPv4FlagsMF.setText(0, '更多分段(MF)：%s' % packet[IP].flags.MF)

            IPv4Frag.setText(0, '片位移(frag)：%s ' % packet[IP].frag)  # 本分片在原先数据报文中相对首位的偏移位。（需要再乘以8）
            IPv4Ttl = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Ttl.setText(0, '生存时间(ttl)：%s' % packet[IP].ttl)

            # TCP
            if packet[IP].proto == 6:
                if packet.haslayer('TCP'):
                    IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                    IPv4Proto.setText(0, '协议类型(proto)：TCP(6)')
                    tcp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                    tcp.setText(0, 'TCP，源端口(sport)：%s，目的端口(dport)：%s，Seq：%s，Ack：%s' % (
                    packet[TCP].sport, packet[TCP].dport, packet[TCP].seq, packet[TCP].ack))
                    tcpSport = QtWidgets.QTreeWidgetItem(tcp)
                    tcpSport.setText(0, '源端口(sport)：%s' % packet[TCP].sport)
                    tcpDport = QtWidgets.QTreeWidgetItem(tcp)
                    tcpDport.setText(0, '目的端口(dport)：%s' % packet[TCP].dport)
                    tcpSeq = QtWidgets.QTreeWidgetItem(tcp)
                    tcpSeq.setText(0, '序号(Seq)：%s' % packet[TCP].seq)
                    tcpAck = QtWidgets.QTreeWidgetItem(tcp)
                    tcpAck.setText(0, '确认号(Ack)：%s' % packet[TCP].ack)
                    tcpDataofs = QtWidgets.QTreeWidgetItem(tcp)
                    tcpDataofs.setText(0, '数据偏移(dataofs)：%s' % packet[TCP].dataofs)
                    tcpReserved = QtWidgets.QTreeWidgetItem(tcp)
                    tcpReserved.setText(0, '保留(reserved)：%s' % packet[TCP].reserved)
                    tcpFlags = QtWidgets.QTreeWidgetItem(tcp)
                    tcpFlags.setText(0, '标志(flags)：%s' % packet[TCP].flags)
                    '''
                    ACK 置1时表示确认号（为合法，为0的时候表示数据段不包含确认信息，确认号被忽略。
                    RST 置1时重建连接。如果接收到RST位时候，通常发生了某些错误。
                    SYN 置1时用来发起一个连接。
                    FIN 置1时表示发端完成发送任务。用来释放连接，表明发送方已经没有数据发送了。
                    URG 紧急指针，告诉接收TCP模块紧要指针域指着紧要数据。注：一般不使用。
                    PSH 置1时请求的数据段在接收方得到后就可直接送到应用程序，而不必等到缓冲区满时才传送。注：一般不使用。
                    '''
                    tcpFlagsACK = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsACK.setText(0, '确认(ACK)：%s' % packet[TCP].flags.A)
                    tcpFlagsRST = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsRST.setText(0, '重新连接(RST)：%s' % packet[TCP].flags.R)
                    tcpFlagsSYN = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsSYN.setText(0, '发起连接(SYN)：%s' % packet[TCP].flags.S)
                    tcpFlagsFIN = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsFIN.setText(0, '释放连接(FIN)：%s' % packet[TCP].flags.F)
                    tcpFlagsURG = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsURG.setText(0, '紧急指针(URG)：%s' % packet[TCP].flags.U)
                    tcpFlagsPSH = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsPSH.setText(0, '非缓冲区(PSH)：%s' % packet[TCP].flags.P)
                    tcpWindow = QtWidgets.QTreeWidgetItem(tcp)
                    tcpWindow.setText(0, '窗口(window)：%s' % packet[TCP].window)
                    tcpChksum = QtWidgets.QTreeWidgetItem(tcp)
                    tcpChksum.setText(0, '校验和(chksum)：0x%x' % packet[TCP].chksum)
                    tcpUrgptr = QtWidgets.QTreeWidgetItem(tcp)
                    tcpUrgptr.setText(0, '紧急指针(urgptr)：%s' % packet[
                        TCP].urgptr)  # 只有当U R G标志置1时紧急指针才有效。紧急指针是一个正的偏移量，和序号字段中的值相加表示紧急数据最后一个字节的序号。
                    tcpOptions = QtWidgets.QTreeWidgetItem(tcp)
                    tcpOptions.setText(0, '选项(options)：%s' % packet[TCP].options)
                    '''
                    通常为空，可根据首部长度推算。用于发送方与接收方协商最大报文段长度（MSS），或在高速网络环境下作窗口调节因子时使用。首部字段还定义了一个时间戳选项。
                    最常见的可选字段是最长报文大小，又称为MSS (Maximum Segment Size)。每个连接方通常都在握手的第一步中指明这个选项。它指明本端所能接收的最大长度的报文段。1460是以太网默认的大小。
                  '''
                    # HTTP
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        # HTTP Request
                        if packet.haslayer('HTTPRequest'):
                            http = QtWidgets.QTreeWidgetItem(self.treeWidget)
                            http.setText(0, 'HTTP Request')
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Method%}") != 'None':
                                httpMethod = QtWidgets.QTreeWidgetItem(http)
                                httpMethod.setText(0, 'Method：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Method%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Path%}") != 'None':
                                httpPath = QtWidgets.QTreeWidgetItem(http)
                                httpPath.setText(0,
                                                 'Path：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Path%}").strip(
                                                     "'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Http-Version%}") != 'None':
                                httpHttpVersion = QtWidgets.QTreeWidgetItem(http)
                                httpHttpVersion.setText(0, 'Http-Version：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Http-Version%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Host%}") != 'None':
                                httpHost = QtWidgets.QTreeWidgetItem(http)
                                httpHost.setText(0,
                                                 'Host：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Host%}").strip(
                                                     "'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.User-Agent%}") != 'None':
                                httpUserAgent = QtWidgets.QTreeWidgetItem(http)
                                httpUserAgent.setText(0, 'User-Agent：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.User-Agent%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Accept%}") != 'None':
                                httpAccept = QtWidgets.QTreeWidgetItem(http)
                                httpAccept.setText(0, 'Accept：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Accept%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Accept-Language%}") != 'None':
                                httpAcceptLanguage = QtWidgets.QTreeWidgetItem(http)
                                httpAcceptLanguage.setText(0, 'Accept-Language：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Accept-Language%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Accept-Encoding%}") != 'None':
                                httpAcceptEncoding = QtWidgets.QTreeWidgetItem(http)
                                httpAcceptEncoding.setText(0, 'Accept-Encoding：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Accept-Encoding%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Accept-Charset%}") != 'None':
                                httpAcceptCharset = QtWidgets.QTreeWidgetItem(http)
                                httpAcceptCharset.setText(0, 'Accept-Charset：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Accept-Charset%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Referer%}") != 'None':
                                httpReferer = QtWidgets.QTreeWidgetItem(http)
                                httpReferer.setText(0, 'Referer：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Referer%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Authorization%}") != 'None':
                                httpAuthorization = QtWidgets.QTreeWidgetItem(http)
                                httpAuthorization.setText(0, 'Authorization：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Authorization%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Expect%}") != 'None':
                                httpExpect = QtWidgets.QTreeWidgetItem(http)
                                httpExpect.setText(0, 'Expect：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Expect%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.From%}") != 'None':
                                httpFrom = QtWidgets.QTreeWidgetItem(http)
                                httpFrom.setText(0,
                                                 'From：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.From%}").strip(
                                                     "'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.If-Match%}") != 'None':
                                httpIfMatch = QtWidgets.QTreeWidgetItem(http)
                                httpIfMatch.setText(0, 'If-Match：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.If-Match%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.If-Modified-Since%}") != 'None':
                                httpIfModifiedSince = QtWidgets.QTreeWidgetItem(http)
                                httpIfModifiedSince.setText(0, 'If-Modified-Since：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.If-Modified-Since%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.If-None-Match%}") != 'None':
                                httpIfNoneMatch = QtWidgets.QTreeWidgetItem(http)
                                httpIfNoneMatch.setText(0, 'If-None-Match：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.If-None-Match%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.If-Range%}") != 'None':
                                httpIfRange = QtWidgets.QTreeWidgetItem(http)
                                httpIfRange.setText(0, 'If-Range：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.If-Range%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.If-Unmodified-Since%}") != 'None':
                                httpIfUnmodifiedSince = QtWidgets.QTreeWidgetItem(http)
                                httpIfUnmodifiedSince.setText(0, 'If-Unmodified-Since：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.If-Unmodified-Since%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Max-Forwards%}") != 'None':
                                httpMaxForwards = QtWidgets.QTreeWidgetItem(http)
                                httpMaxForwards.setText(0, 'Max-Forwards：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Max-Forwards%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Proxy-Authorization%}") != 'None':
                                httpProxyAuthorization = QtWidgets.QTreeWidgetItem(http)
                                httpProxyAuthorization.setText(0, 'Proxy-Authorization：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Proxy-Authorization%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Range%}") != 'None':
                                httpRange = QtWidgets.QTreeWidgetItem(http)
                                httpRange.setText(0, 'Range：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Range%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.TE%}") != 'None':
                                httpTE = QtWidgets.QTreeWidgetItem(http)
                                httpTE.setText(0, 'TE：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.TE%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Cache-Control%}") != 'None':
                                httpCacheControl = QtWidgets.QTreeWidgetItem(http)
                                httpCacheControl.setText(0, 'Cache-Control：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Cache-Control%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Connection%}") != 'None':
                                httpConnection = QtWidgets.QTreeWidgetItem(http)
                                httpConnection.setText(0, 'Connection：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Connection%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Date%}") != 'None':
                                httpDate = QtWidgets.QTreeWidgetItem(http)
                                httpDate.setText(0,
                                                 'Date：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Date%}").strip(
                                                     "'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Pragma%}") != 'None':
                                httpPragma = QtWidgets.QTreeWidgetItem(http)
                                httpPragma.setText(0, 'Pragma：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Pragma%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Trailer%}") != 'None':
                                httpTrailer = QtWidgets.QTreeWidgetItem(http)
                                httpTrailer.setText(0, 'Trailer：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Trailer%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Transfer-Encoding%}") != 'None':
                                httpTransferEncoding = QtWidgets.QTreeWidgetItem(http)
                                httpTransferEncoding.setText(0, 'Transfer-Encoding：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Transfer-Encoding%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Upgrade%}") != 'None':
                                httpUpgrade = QtWidgets.QTreeWidgetItem(http)
                                httpUpgrade.setText(0, 'Upgrade：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Upgrade%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Via%}") != 'None':
                                httpVia = QtWidgets.QTreeWidgetItem(http)
                                httpVia.setText(0,
                                                'Via：%s' % packet.sprintf("{HTTPRequest:%HTTPRequest.Via%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Warning%}") != 'None':
                                httpWarning = QtWidgets.QTreeWidgetItem(http)
                                httpWarning.setText(0, 'Warning：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Warning%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Keep-Alive%}") != 'None':
                                httpKeepAlive = QtWidgets.QTreeWidgetItem(http)
                                httpKeepAlive.setText(0, 'Keep-Alive：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Keep-Alive%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Allow%}") != 'None':
                                httpAllow = QtWidgets.QTreeWidgetItem(http)
                                httpAllow.setText(0, 'Allow：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Allow%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Encoding%}") != 'None':
                                httpContentEncoding = QtWidgets.QTreeWidgetItem(http)
                                httpContentEncoding.setText(0, 'Content-Encoding：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Content-Encoding%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Language%}") != 'None':
                                httpContentLanguage = QtWidgets.QTreeWidgetItem(http)
                                httpContentLanguage.setText(0, 'Content-Language：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Content-Language%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Length%}") != 'None':
                                httpContentLength = QtWidgets.QTreeWidgetItem(http)
                                httpContentLength.setText(0, 'Content-Length：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Content-Length%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Location%}") != 'None':
                                httpContentLocation = QtWidgets.QTreeWidgetItem(http)
                                httpContentLocation.setText(0, 'Content-Location：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Content-Location%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-MD5%}") != 'None':
                                httpContentMD5 = QtWidgets.QTreeWidgetItem(http)
                                httpContentMD5.setText(0, 'Content-MD5：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Content-MD5%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Range%}") != 'None':
                                httpContentRange = QtWidgets.QTreeWidgetItem(http)
                                httpContentRange.setText(0, 'Content-Range：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Content-Range%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Content-Type%}") != 'None':
                                httpContentType = QtWidgets.QTreeWidgetItem(http)
                                httpContentType.setText(0, 'Content-Type：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Content-Type%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Expires%}") != 'None':
                                httpExpires = QtWidgets.QTreeWidgetItem(http)
                                httpExpires.setText(0, 'Expires：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Expires%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Last-Modified%}") != 'None':
                                httpLastModified = QtWidgets.QTreeWidgetItem(http)
                                httpLastModified.setText(0, 'Last-Modified：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Last-Modified%}").strip("'"))
                            if packet.sprintf("{HTTPRequest:%HTTPRequest.Cookie%}") != 'None':
                                httpCookie = QtWidgets.QTreeWidgetItem(http)
                                httpCookie.setText(0, 'Cookie：%s' % packet.sprintf(
                                    "{HTTPRequest:%HTTPRequest.Cookie%}").strip("'"))
                        # HTTP Response
                        if packet.haslayer('HTTPResponse'):
                            http = QtWidgets.QTreeWidgetItem(self.treeWidget)
                            http.setText(0, 'HTTP Response')
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Status-Line%}") != 'None':
                                httpStatusLine = QtWidgets.QTreeWidgetItem(http)
                                httpStatusLine.setText(0, 'Status-Line：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Status-Line%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Accept-Ranges%}") != 'None':
                                httpAcceptRanges = QtWidgets.QTreeWidgetItem(http)
                                httpAcceptRanges.setText(0, 'Accept-Ranges：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Accept-Ranges%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Age%}") != 'None':
                                httpAge = QtWidgets.QTreeWidgetItem(http)
                                httpAge.setText(0, 'Age：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Age%}").strip(
                                    "'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.E-Tag%}") != 'None':
                                httpETag = QtWidgets.QTreeWidgetItem(http)
                                httpETag.setText(0, 'E-Tag：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.E-Tag%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Location%}") != 'None':
                                httpLocation = QtWidgets.QTreeWidgetItem(http)
                                httpLocation.setText(0, 'Location：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Location%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Proxy-Authenticate%}") != 'None':
                                httpProxyAuthenticate = QtWidgets.QTreeWidgetItem(http)
                                httpProxyAuthenticate.setText(0, 'Proxy-Authenticate：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Proxy-Authenticate%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Retry-After%}") != 'None':
                                httpRetryAfter = QtWidgets.QTreeWidgetItem(http)
                                httpRetryAfter.setText(0, 'Retry-After：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Retry-After%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Server%}") != 'None':
                                httpServer = QtWidgets.QTreeWidgetItem(http)
                                httpServer.setText(0, 'Server：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Server%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Vary%}") != 'None':
                                httpVary = QtWidgets.QTreeWidgetItem(http)
                                httpVary.setText(0,
                                                 'Vary：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Vary%}").strip(
                                                     "'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.WWW-Authenticate%}") != 'None':
                                httpWWWAuthenticate = QtWidgets.QTreeWidgetItem(http)
                                httpWWWAuthenticate.setText(0, 'WWW-Authenticate：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.WWW-Authenticate%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Cache-Control%}") != 'None':
                                httpCacheControl = QtWidgets.QTreeWidgetItem(http)
                                httpCacheControl.setText(0, 'Cache-Control：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Cache-Control%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Connection%}") != 'None':
                                httpConnection = QtWidgets.QTreeWidgetItem(http)
                                httpConnection.setText(0, 'Connection：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Connection%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Date%}") != 'None':
                                httpDate = QtWidgets.QTreeWidgetItem(http)
                                httpDate.setText(0,
                                                 'Date：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Date%}").strip(
                                                     "'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Pragma%}") != 'None':
                                httpPragma = QtWidgets.QTreeWidgetItem(http)
                                httpPragma.setText(0, 'Pragma：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Pragma%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Trailer%}") != 'None':
                                httpTrailer = QtWidgets.QTreeWidgetItem(http)
                                httpTrailer.setText(0, 'Trailer：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Trailer%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Transfer-Encoding%}") != 'None':
                                httpTransferEncoding = QtWidgets.QTreeWidgetItem(http)
                                httpTransferEncoding.setText(0, 'Transfer-Encoding：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Transfer-Encoding%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Upgrade%}") != 'None':
                                httpUpgrade = QtWidgets.QTreeWidgetItem(http)
                                httpUpgrade.setText(0, 'Upgrade：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Upgrade%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Via%}") != 'None':
                                httpVia = QtWidgets.QTreeWidgetItem(http)
                                httpVia.setText(0, 'Via：%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Via%}").strip(
                                    "'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Warning%}") != 'None':
                                httpWarning = QtWidgets.QTreeWidgetItem(http)
                                httpWarning.setText(0, 'Warning：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Warning%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Keep-Alive%}") != 'None':
                                httpKeepAlive = QtWidgets.QTreeWidgetItem(http)
                                httpKeepAlive.setText(0, 'Keep-Alive：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Keep-Alive%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Allow%}") != 'None':
                                httpAllow = QtWidgets.QTreeWidgetItem(http)
                                httpAllow.setText(0, 'Allow：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Allow%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Encoding%}") != 'None':
                                httpContentEncoding = QtWidgets.QTreeWidgetItem(http)
                                httpContentEncoding.setText(0, 'Content-Encoding：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Content-Encoding%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Language%}") != 'None':
                                httpContentLanguage = QtWidgets.QTreeWidgetItem(http)
                                httpContentLanguage.setText(0, 'Content-Language：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Content-Language%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Length%}") != 'None':
                                httpContentLength = QtWidgets.QTreeWidgetItem(http)
                                httpContentLength.setText(0, 'Content-Length：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Content-Length%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Location%}") != 'None':
                                httpContentLocation = QtWidgets.QTreeWidgetItem(http)
                                httpContentLocation.setText(0, 'Content-Location：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Content-Location%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-MD5%}") != 'None':
                                httpContentMD5 = QtWidgets.QTreeWidgetItem(http)
                                httpContentMD5.setText(0, 'Content-MD5：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Content-MD5%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Range%}") != 'None':
                                httpContentRange = QtWidgets.QTreeWidgetItem(http)
                                httpContentRange.setText(0, 'Content-Range：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Content-Range%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Content-Type%}") != 'None':
                                httpContentType = QtWidgets.QTreeWidgetItem(http)
                                httpContentType.setText(0, 'Content-Type：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Content-Type%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Expires%}") != 'None':
                                httpExpires = QtWidgets.QTreeWidgetItem(http)
                                httpExpires.setText(0, 'Expires：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Expires%}").strip("'"))
                            if packet.sprintf("{HTTPResponse:%HTTPResponse.Last-Modified%}") != 'None':
                                httpLastModified = QtWidgets.QTreeWidgetItem(http)
                                httpLastModified.setText(0, 'Last-Modified：%s' % packet.sprintf(
                                    "{HTTPResponse:%HTTPResponse.Last-Modified%}").strip("'"))
            if packet.haslayer('TLS'):
                tls = QtWidgets.QTreeWidgetItem(self.treeWidget)
                if packet[TLS].version == 769:
                    version = "TLS 1.0"
                elif packet[TLS].version == 770:
                    version = "TLS 1.1"
                elif packet[TLS].version == 771:
                    version = "TLS 1.2"
                elif packet[TLS].version == 772:
                    version = "TLS 1.3"
                tls.setText(0, 'Transport Layer Security')
                tlsVersion = QtWidgets.QTreeWidgetItem(tls)
                tlsVersion.setText(0, '版本：%s' % version)
                tlsType = QtWidgets.QTreeWidgetItem(tls)
                tlsType.setText(0, '内容种类：%s' % packet[TLS].type)
                tlsLen = QtWidgets.QTreeWidgetItem(tls)
                tlsLen.setText(0, '长度：%s' % packet[TLS].len)
                if packet[TLS].haslayer("TLSClientHello") or packet[TLS].haslayer("TLSServerHello"):
                    tlsHello = QtWidgets.QTreeWidgetItem(tls)
                    if packet[TLS].haslayer("TLSClientHello"):
                        tlsHello.setText(0, 'Handshake Type：%s' % 'Client Hello')
                        print('1')
                    else:
                        tlsHello.setText(0, 'Handshake Type：%s' % 'Server Hello')
                        print('2')

            # UDP
            elif packet[IP].proto == 17:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0, '协议类型(proto)：UDP(17)')
                udp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                udp.setText(0, 'UDP，源端口(sport)：%s，目的端口(dport)：%s' % (packet[UDP].sport, packet[UDP].dport))
                udpSport = QtWidgets.QTreeWidgetItem(udp)
                udpSport.setText(0, '源端口(sport)：%s' % packet[UDP].sport)
                udpDport = QtWidgets.QTreeWidgetItem(udp)
                udpDport.setText(0, '目的端口(dport)：%s' % packet[UDP].dport)
                udpLen = QtWidgets.QTreeWidgetItem(udp)
                udpLen.setText(0, '长度(len)：%s' % packet[UDP].len)
                udpChksum = QtWidgets.QTreeWidgetItem(udp)
                udpChksum.setText(0, '校验和(chksum)：0x%x' % packet[UDP].chksum)
                # DNS
                if packet.haslayer('DNS'):
                    pass
                    # nds = QtWidgets.QTreeWidgetItem(self.treeWidget)
                    # nds.setText(0,'DNS')
            # ICMP
            elif packet[IP].proto == 1:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0, '协议类型(proto)：ICMP(1)')

                '''
                8位类型和8位代码字段一起决定了ICMP报文的类型。
                    类型8，代码0：表示回显请求(ping请求)。
                    类型0，代码0：表示回显应答(ping应答)
                    类型11，代码0：超时
               '''
                icmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                icmp.setText(0, 'ICMP')
                icmpType = QtWidgets.QTreeWidgetItem(icmp)
                if packet[ICMP].type == 8:
                    icmpType.setText(0, '类型(type)：%s (Echo (ping) request)' % packet[ICMP].type)
                elif packet[ICMP].type == 0:
                    icmpType.setText(0, '类型(type)：%s (Echo (ping) reply)' % packet[ICMP].type)
                else:
                    icmpType.setText(0, '类型(type)：%s' % packet[
                        ICMP].type)  # 占一字节，标识ICMP报文的类型，目前已定义了14种，从类型值来看ICMP报文可以分为两大类。第一类是取值为1~127的差错报文，第2类是取值128以上的信息报文。
                icmpCode = QtWidgets.QTreeWidgetItem(icmp)
                icmpCode.setText(0, '代码(code)：%s' % packet[ICMP].code)  # 占一字节，标识对应ICMP报文的代码。它与类型字段一起共同标识了ICMP报文的详细类型。
                icmpChksum = QtWidgets.QTreeWidgetItem(icmp)
                icmpChksum.setText(0, '校验和(chksum)：0x%x' % packet[ICMP].chksum)
                icmpId = QtWidgets.QTreeWidgetItem(icmp)
                icmpId.setText(0, '标识(id)：%s' % packet[
                    ICMP].id)  # 占两字节，用于标识本ICMP进程，但仅适用于回显请求和应答ICMP报文，对于目标不可达ICMP报文和超时ICMP报文等，该字段的值为0。
                icmpSeq = QtWidgets.QTreeWidgetItem(icmp)
                icmpSeq.setText(0, 'seq：%s' % packet[ICMP].seq)
                icmpTs_ori = QtWidgets.QTreeWidgetItem(icmp)
                icmpTs_ori.setText(0, 'ts_ori：%s' % packet[ICMP].ts_ori)
                icmpTs_rx = QtWidgets.QTreeWidgetItem(icmp)
                icmpTs_rx.setText(0, 'ts_rx：%s' % packet[ICMP].ts_rx)
                icmpTs_tx = QtWidgets.QTreeWidgetItem(icmp)
                icmpTs_tx.setText(0, 'ts_tx：%s' % packet[ICMP].ts_tx)
                icmpGw = QtWidgets.QTreeWidgetItem(icmp)
                icmpGw.setText(0, 'gw：%s' % packet[ICMP].gw)
                icmpPtr = QtWidgets.QTreeWidgetItem(icmp)
                icmpPtr.setText(0, 'ptr：%s' % packet[ICMP].ptr)
                icmpReserved = QtWidgets.QTreeWidgetItem(icmp)
                icmpReserved.setText(0, 'reserved：%s' % packet[ICMP].reserved)
                icmpLength = QtWidgets.QTreeWidgetItem(icmp)
                icmpLength.setText(0, 'length：%s' % packet[ICMP].length)
                icmpAddr_mask = QtWidgets.QTreeWidgetItem(icmp)
                icmpAddr_mask.setText(0, 'addr_mask：%s' % packet[ICMP].addr_mask)
                icmpnexthopmtu = QtWidgets.QTreeWidgetItem(icmp)
                icmpnexthopmtu.setText(0, 'nexthopmtu：%s' % packet[ICMP].nexthopmtu)
            # IGMP
            elif packet[IP].proto == 2:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0, '协议类型(proto)：IGMP(2)')

                igmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                igmp.setText(0, 'IGMP')
                igmpCopy_flag = QtWidgets.QTreeWidgetItem(igmp)
                igmpCopy_flag.setText(0, 'copy_flag：%s' % packet[IPOption_Router_Alert].copy_flag)
                igmpOptclass = QtWidgets.QTreeWidgetItem(igmp)
                igmpOptclass.setText(0, 'optclass：%s' % packet[IPOption_Router_Alert].optclass)
                igmpOption = QtWidgets.QTreeWidgetItem(igmp)
                igmpOption.setText(0, 'option：%s' % packet[IPOption_Router_Alert].option)
                igmpLength = QtWidgets.QTreeWidgetItem(igmp)
                igmpLength.setText(0, 'length：%s' % packet[IPOption_Router_Alert].length)
                igmpAlert = QtWidgets.QTreeWidgetItem(igmp)
                igmpAlert.setText(0, 'alert：%s' % packet[IPOption_Router_Alert].alert)
            else:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0, '协议类型(proto)：%s' % packet[IP].proto)

            IPv4Chksum = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Chksum.setText(0, '校验和(chksum)：0x%x' % packet[IP].chksum)
            IPv4Src = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Src.setText(0, '源IP地址(src)：%s' % packet[IP].src)
            IPv4Dst = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Dst.setText(0, '目的IP地址(dst)：%s' % packet[IP].dst)
            IPv4Options = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Options.setText(0, '可选部分(options)：%s' % packet[IP].options)

        # ARP
        elif type == 0x806:
            EthernetType = QtWidgets.QTreeWidgetItem(Ethernet)
            EthernetType.setText(0, '协议类型(type)：ARP(0x806)')

            arp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            arp.setText(0, 'ARP')
            arpHwtype = QtWidgets.QTreeWidgetItem(arp)
            arpHwtype.setText(0, '硬件类型(hwtype)：0x%x' % packet[ARP].hwtype)  # 1代表是以太网。
            arpPtype = QtWidgets.QTreeWidgetItem(arp)
            arpPtype.setText(0, '协议类型(ptype)：0x%x' % packet[ARP].ptype)  # 表明上层协议的类型,这里是0x0800,表示上层协议是IP协议
            arpHwlen = QtWidgets.QTreeWidgetItem(arp)
            arpHwlen.setText(0, '硬件地址长度(hwlen)：%s' % packet[ARP].hwlen)
            arpPlen = QtWidgets.QTreeWidgetItem(arp)
            arpPlen.setText(0, '协议长度(plen)：%s' % packet[ARP].plen)
            arpOp = QtWidgets.QTreeWidgetItem(arp)
            if packet[ARP].op == 1:  # request
                arpOp.setText(0, '操作类型(op)：request (%s)' % packet[ARP].op)
            elif packet[ARP].op == 2:
                arpOp.setText(0, '操作类型(op)：reply (%s)' % packet[ARP].op)
            else:
                arpOp.setText(0, '操作类型(op)：%s' % packet[ARP].op)  # 在报文中占2个字节,1表示ARP请求,2表示ARP应答,3表示RARP请求,4表示RARP应答
            arpHwsrc = QtWidgets.QTreeWidgetItem(arp)
            arpHwsrc.setText(0, '源MAC地址(hwsrc)：%s' % packet[ARP].hwsrc)
            arpPsrc = QtWidgets.QTreeWidgetItem(arp)
            arpPsrc.setText(0, '源IP地址(psrc)：%s' % packet[ARP].psrc)
            arpHwdst = QtWidgets.QTreeWidgetItem(arp)
            arpHwdst.setText(0, '目的MAC地址(hwdst)：%s' % packet[ARP].hwdst)
            arpPdst = QtWidgets.QTreeWidgetItem(arp)
            arpPdst.setText(0, '目的IP地址(pdst)：%s' % packet[ARP].pdst)

        self.textBrowserRaw.clear()
        if packet.haslayer('Raw'):
            # raw = QtWidgets.QTreeWidgetItem(self.treeWidget)
            # raw.setText(0,'Raw：%s' % packet[Raw].load.decode('utf-8','ignore'))
            self.textBrowserRaw.append('Raw：%s' % packet[Raw].load.decode('utf-8', 'ignore'))

        if packet.haslayer('Padding'):
            # padding = QtWidgets.QTreeWidgetItem(self.treeWidget)
            # padding.setText(0,'Padding：%s' % packet[Padding].load.decode('utf-8','ignore'))
            self.textBrowserRaw.append('Padding：%s' % packet[Padding].load.decode('utf-8', 'ignore'))

        self.textBrowserDump.clear()
        f = open('hexdump.tmp', 'w')
        old = sys.stdout  # 将当前系统输出储存到临时变量
        sys.stdout = f  # 输出重定向到文件
        hexdump(packet)
        sys.stdout = old
        f.close()
        f = open('hexdump.tmp', 'r')
        content = f.read()
        self.textBrowserDump.append(content)
        f.close()
        os.remove('hexdump.tmp')

    def save_to_cap(self):
        # 保存为cap文件
        path, filetype = QFileDialog.getSaveFileName(None,
                                                     "选择保存路径",
                                                     "./",
                                                     "pcap文件(*.cap);;全部(*)")
        try:
            packets = scapy.plist.PacketList(self.catch_list)
            wrpcap(path, packets)
            QtWidgets.QMessageBox.information(None, "成功", "保存成功")
        except:
            QtWidgets.QMessageBox.information(None, "失败", "保存失败")

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
        sniff(session=TLSSession, filter=self.filter, iface=self.interface, prn=self.exception)

    def exception(self, signal):
        self.HandleSignal.emit(signal)


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    load_layer("tls")
    ui = MainView()
    ui.setupUi(MainWindow)
    ui.init_slot()
    MainWindow.show()
    sys.exit(app.exec_())

sniff()