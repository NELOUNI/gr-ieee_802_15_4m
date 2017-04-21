#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: IEEE 802.15.4m Slave Node Transceiver using OQPSK 
# Generated: Tue Mar 21 16:13:54 2017
##################################################

# Kill eventual Zombie process
import subprocess, os, sys
try:
        subprocess.call('ps auxw | grep -ie \'listenSlave\' | awk \'{print $2}\' | xargs sudo kill -9', shell=True) 
        subprocess.call('sudo ip link delete tap1', shell=True) 
except OSError as e:
    print >>sys.stderr, "Execution failed:", e

if __name__ == '__main__':
    import ctypes
    if sys.platform.startswith('linux'):
        try:
            x11 = ctypes.cdll.LoadLibrary('libX11.so')
            x11.XInitThreads()
        except:
            print "Warning: failed to XInitThreads()"

sys.path.append(os.environ.get('GRC_HIER_PATH', os.path.expanduser('~/.grc_gnuradio')))
sys.path.append("./WSDB")
sys.path.append("../python") #FIXME Ignored after adding mac and packet py files under python

from gnuradio import uhd, digital
from multiprocessing import  Pipe
import json, pycurl, StringIO, time, select, psutil, atexit
import threading, signal, string, socket, random, struct, fcntl
import webServerWSDB
from fcntl import ioctl
import mac_15_4m
from mac_15_4m import *
from packet import Packet
import TVWS_channelmap
from PyQt4 import Qt
from PyQt4.QtCore import QObject, pyqtSlot
from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio import qtgui
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from gnuradio.qtgui import Range, RangeWidget
from ieee802_15_4_oqpsk_phy import ieee802_15_4_oqpsk_phy  # grc-generated hier_block
from optparse import OptionParser
import foo
import ieee802_15_4
import ieee802_11 #FIXME
import pmt
import sip

class broadcastScript():

    def __init__(self, myWord, myPort, mySlot, myInterval):
         self.myWord	= myWord
         self.myPort 	= myPort	
         self.mySlot	= mySlot
	 self.myInterval= myInterval
         size = 80 	   
         #Opening socket
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
         # bind it
         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
         #Sending loop
	 start_time = time.time()  # remember when we started
	 print "Data randomly sent to master: "
	 while (time.time() - start_time) < self.mySlot:
             #Adding timestamp and seq number to the data to be sent
             if (size > 0) :
                 #Filling the data with spaces until it reaches the requested size
                 self.myWord = self.myWord + (size - len(self.myWord)) * " "
             	 print self.myWord
             s.sendto(self.myWord, ("localhost", int(self.myPort)))	
             time.sleep(self.myInterval)
         s.close()

class transceiver_OQPSK_Slave(gr.top_block, Qt.QWidget):

    def __init__(self, addr, no_usrp, initialFreq, otw, source, no_self_loop, debug_MAC, wireshark):
        gr.top_block.__init__(self, "IEEE 802.15.4m Slave Node Transceiver using OQPSK")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("IEEE 802.15.4m Slave Node Transceiver using OQPSK")
        qtgui.util.check_set_qss()
        try:
            self.setWindowIcon(Qt.QIcon.fromTheme('gnuradio-grc'))
        except:
            pass
        self.top_scroll_layout = Qt.QVBoxLayout()
        self.setLayout(self.top_scroll_layout)
        self.top_scroll = Qt.QScrollArea()
        self.top_scroll.setFrameStyle(Qt.QFrame.NoFrame)
        self.top_scroll_layout.addWidget(self.top_scroll)
        self.top_scroll.setWidgetResizable(True)
        self.top_widget = Qt.QWidget()
        self.top_scroll.setWidget(self.top_widget)
        self.top_layout = Qt.QVBoxLayout(self.top_widget)
        self.top_grid_layout = Qt.QGridLayout()
        self.top_layout.addLayout(self.top_grid_layout)

        self.settings = Qt.QSettings("GNU Radio", "transceiver_OQPSK_Slave")
        self.restoreGeometry(self.settings.value("geometry").toByteArray())

        ##################################################
        # Variables
        ##################################################
        self.addr 	  = addr
	self.no_usrp	  = no_usrp
	self.freq	  = initialFreq
	self.otw	  = otw
        self.no_self_loop = no_self_loop	
	self.debug_MAC	  = debug_MAC
	self.source	  = source
	self.wireshark	  = wireshark
	self.tx_gain = tx_gain = 0.25
        self.rx_gain = rx_gain = 0.25
        ##################################################
        # Blocks
        ##################################################
	if self.no_usrp:
	   	self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, 4*1e6,True)
		## Using files instead of USRPs
	        self.blocks_file_source_slave = blocks.file_source(gr.sizeof_gr_complex*1, (os.getcwd()+"/utils/masterFileSink"), True)
	        self.blocks_file_sink_slave = blocks.file_sink(gr.sizeof_gr_complex*1, (os.getcwd()+"/utils/slaveFileSink"), False)
	        self.blocks_file_sink_slave.set_unbuffered(False)
	else:
	        ## usrp_source
                self.uhd_usrp_source_0 = uhd.usrp_source(
                ",".join((self.addr, "")),
                uhd.stream_args(
                        cpu_format="fc32",
                        channels=range(1),),  )
	        ## usrp_sink
                self.uhd_usrp_sink_0 = uhd.usrp_sink(
                        ",".join((self.addr, "")),
                        uhd.stream_args(
                                cpu_format="fc32",
                                channels=range(1),),)

		# TODO Explain the usage 
        	self.uhd_usrp_source_0.set_time_now(uhd.time_spec(time.time()), uhd.ALL_MBOARDS)
                self.uhd_usrp_sink_0.set_time_now(uhd.time_spec(time.time()), uhd.ALL_MBOARDS)
		self.uhd_usrp_source_0.set_normalized_gain(rx_gain, 0)
                self.uhd_usrp_sink_0.set_normalized_gain(tx_gain, 0)


        self._tx_gain_range = Range(0, 1, 0.01, 0.75, 200)
        self._tx_gain_win = RangeWidget(self._tx_gain_range, self.set_tx_gain, "tx_gain", "counter_slider", float)
        self.top_layout.addWidget(self._tx_gain_win)
        self._rx_gain_range = Range(0, 1, 0.01, 0.75, 200)
        self._rx_gain_win = RangeWidget(self._rx_gain_range, self.set_rx_gain, "rx_gain", "counter_slider", float)
        self.top_layout.addWidget(self._rx_gain_win)
        self.qtgui_freq_sink_x_0 = qtgui.freq_sink_c(
        	1024, #size
        	firdes.WIN_BLACKMAN_hARRIS, #wintype
        	0, #fc
        	4e6, #bw
        	"", #name
        	1 #number of inputs
        )
        self.qtgui_freq_sink_x_0.set_update_time(0.10)
        self.qtgui_freq_sink_x_0.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_0.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_0.enable_autoscale(False)
        self.qtgui_freq_sink_x_0.enable_grid(False)
        self.qtgui_freq_sink_x_0.set_fft_average(1.0)
        self.qtgui_freq_sink_x_0.enable_axis_labels(True)
        self.qtgui_freq_sink_x_0.enable_control_panel(False)

        if not True:
          self.qtgui_freq_sink_x_0.disable_legend()

        if "complex" == "float" or "complex" == "msg_float":
          self.qtgui_freq_sink_x_0.set_plot_pos_half(not True)

        labels = ['', '', '', '', '',
                  '', '', '', '', '']
        widths = [1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1]
        colors = ["blue", "red", "green", "black", "cyan",
                  "magenta", "yellow", "dark red", "dark green", "dark blue"]
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
                  1.0, 1.0, 1.0, 1.0, 1.0]
        for i in xrange(1):
            if len(labels[i]) == 0:
                self.qtgui_freq_sink_x_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_0.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_0.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_0.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_0.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_0_win = sip.wrapinstance(self.qtgui_freq_sink_x_0.pyqwidget(), Qt.QWidget)
        self.top_layout.addWidget(self._qtgui_freq_sink_x_0_win)

        self.ieee802_15_4_rime_stack_0 = ieee802_15_4.rime_stack(([129]), ([131]), ([132]), ([23,42]))
	self.ieee802_15_4_oqpsk_phy_0 = ieee802_15_4_oqpsk_phy()
        # 802.15.4m MAC layer #
        #self.ieee802_15_4_mac_0 = ieee802_15_4.mac(True)
        self.ieee802_15_4_mac_0 = mac_15_4m(self.debug_MAC, self.no_self_loop)
        # Ethernet Encapsulation #TODO explain its usage, Specific to 802.11 ? 
        self.ieee802_11_ether_encap_0 = ieee802_11.ether_encap(True)

        self._freq_options = [TVWS_channelmap.get_TVWS_freq(i) for i in range(2, 69)]
        self._freq_labels = [str(i) for i in range(2, 69)]
        self._freq_tool_bar = Qt.QToolBar(self)
        self._freq_tool_bar.addWidget(Qt.QLabel('Channel'+": "))
        self._freq_combo_box = Qt.QComboBox()
        self._freq_tool_bar.addWidget(self._freq_combo_box)
        for label in self._freq_labels: self._freq_combo_box.addItem(label)
        self._freq_callback = lambda i: Qt.QMetaObject.invokeMethod(self._freq_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._freq_options.index(i)))
        self._freq_callback(self.freq)
        self._freq_combo_box.currentIndexChanged.connect(
        	lambda i: self.set_freq(self._freq_options[i]))

        self.top_layout.addWidget(self._freq_tool_bar)

        ##################################################
        # Asynch Message Connections
        ##################################################
	if self.source == "tuntap": # Tuntap Block to quantify the achievable throughput
		print "TUNTAP"
        	self.blocks_tuntap_pdu_0 = blocks.tuntap_pdu("tap1", 440)
        	self.msg_connect(self.ieee802_11_ether_encap_0, "to tap", self.blocks_tuntap_pdu_0, "pdus")
        	self.msg_connect(self.blocks_tuntap_pdu_0, "pdus", self.ieee802_11_ether_encap_0, "from tap")

        	self.msg_connect(self.ieee802_15_4_rime_stack_0, "bcout", self.ieee802_11_ether_encap_0, "from wifi")
        	self.msg_connect(self.ieee802_11_ether_encap_0,  "to wifi" , self.ieee802_15_4_rime_stack_0, "bcin") 

	elif self.source == "socket":   #using PDU Sockets instead #TODO Test ME ! 
		self.blocks_socket_pdu_0_Tx = blocks.socket_pdu("UDP_SERVER", "localhost", "52004", 10000)
		self.blocks_socket_pdu_0_Rx = blocks.socket_pdu("UDP_CLIENT", "localhost", "3333", 10000)

        	self.msg_connect(self.ieee802_15_4_rime_stack_0, "bcout", self.blocks_socket_pdu_0_Rx, "pdus")
        	self.msg_connect(self.blocks_socket_pdu_0_Tx,    "pdus" , self.ieee802_15_4_rime_stack_0, "bcin") 

	elif self.source == "strobe":
        	self.blocks_message_strobe_0 = blocks.message_strobe(pmt.intern("Hello World!\n"), 1000)
        	self.msg_connect((self.blocks_message_strobe_0, 'strobe'), (self.ieee802_15_4_rime_stack_0, 'bcin'))

	if self.wireshark:
		self.foo_wireshark_connector_0 = foo.wireshark_connector(127, True)

        	self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_char*1, "/tmp/ofdm.pcap", True)
        	self.blocks_file_sink_0.set_unbuffered(True)

        	self.connect((self.foo_wireshark_connector_0, 0), (self.blocks_file_sink_0, 0)) 

        	self.msg_connect(self.ieee802_15_4_mac_0, "PHY", self.foo_wireshark_connector_0, "in")
        	self.msg_connect(self.ieee802_15_4_oqpsk_phy_0, "mac_out", self.foo_wireshark_connector_0, "in")
	
        self.msg_connect((self.ieee802_15_4_mac_0, 'pdu out'), (self.ieee802_15_4_oqpsk_phy_0, 'txin'))
        self.msg_connect((self.ieee802_15_4_mac_0, 'app out'), (self.ieee802_15_4_rime_stack_0, 'fromMAC'))
        self.msg_connect((self.ieee802_15_4_oqpsk_phy_0, 'rxout'), (self.ieee802_15_4_mac_0, 'pdu in'))
        self.msg_connect((self.ieee802_15_4_rime_stack_0, 'toMAC'), (self.ieee802_15_4_mac_0, 'app in'))

        ##################################################
        # Connections
        ##################################################
        self.connect((self.ieee802_15_4_oqpsk_phy_0, 0), (self.qtgui_freq_sink_x_0, 0))
        if self.no_usrp:
                self.connect((self.ieee802_15_4_oqpsk_phy_0, 0), ((self.blocks_file_sink_slave, 0))) 
                self.connect((self.blocks_file_source_slave, 0), (self.ieee802_15_4_oqpsk_phy_0, 0)) 
        else:
                self.connect((self.ieee802_15_4_oqpsk_phy_0, 0), ((self.uhd_usrp_sink_0, 0))) 
                self.connect((self.uhd_usrp_source_0, 0), (self.ieee802_15_4_oqpsk_phy_0, 0)) 

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "transceiver_OQPSK_Slave")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
	self.uhd_usrp_sink_0.set_normalized_gain(self.tx_gain, 0)


    def get_rx_gain(self):
        return self.rx_gain
	self.uhd_usrp_source_0.set_normalized_gain(self.rx_gain, 0)

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain


    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq
        self._freq_callback(self.freq)
	self.uhd_usrp_source_0.set_center_freq(self.freq, 0)
        self.uhd_usrp_sink_0.set_center_freq(self.freq, 0)

    def set_samp_rate(self, rate):	
	self.rate = rate
	self.uhd_usrp_source_0.set_samp_rate(self.rate)
	self.uhd_usrp_sink_0.set_samp_rate(self.rate)

def generator(size=56, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def sync(no_usrp, tunnel, scan, dwell, slot, period, interval):

    global tb, gotSync, frequencies, i, Lines, actualFreq#, tunName 
    global word, port, subp_listenSlave, tun

    data = generator()	
    gotSync = False
    if not no_usrp:
  	#if (i == len(Lines)):
  	if (i == len(frequencies)):
  	    print ("All available frequencies have been scanned. \n ...Looping again ")
  	    i = 1
	print "\n Trying frequency:", frequencies[i]/1e6, "MHz. Retuning ..."
	tb.set_freq(frequencies[i]) 
    with open("utils/listenSlave", "r") as flistenSlave:	
          time.sleep(dwell)
          for line in flistenSlave:
                        if ('BBBBBBBB' in line):
                                print "\n \nSync done.....\nBegin Transmitting for 1 minute... "
                                gotSync = True
				actualFreq = frequencies[i]
    flistenSlave.close()
    i += 1
    if (gotSync == False):
        threading.Timer(scan,sync, [no_usrp, tunnel, scan, dwell, slot, period, interval]).start()
    if (gotSync == True):
	print "ActualFreq = ", actualFreq, "\n"
	subp_listenSlave.kill()
	if (tunnel):	tun.run()
	else:		broadcastScript(generator(),port,slot, interval)
	threading.Timer(period, periodCheck, [no_usrp, tunnel, scan, dwell, slot, period, interval]).start()	

def periodCheck(no_usrp, tunnel, scan, dwell, slot, period, interval):

   global i, port, tun
   subp_periodListen = subprocess.Popen('ncat -u -l -p 3333 > utils/listenSlave', shell=True) 
   gotBeacon = False	
   with open("utils/listenSlave", "r") as flistenSlave:	
          time.sleep(dwell)
          for line in flistenSlave:
                        if ('BBBBBBBB' in line):
                                print "\n \nGot beacon...\nKeep trasmitting for another 1 minute...\n\n"
                                gotBeacon = True
        			subp_periodListen.kill() 
   flistenSlave.close()	
   if gotBeacon:
	if (tunnel):	tun.run()
	else:		broadcastScript(generator(),port,slot, interval)
        threading.Timer(period,periodCheck, [no_usrp, tunnel, scan, dwell, slot, period, interval]).start() 
   else:
	i = 1	
	print "\n\nConnection Lost...\nSynching again...."	
	subp_periodListen.kill() 
	subp_periodListen = subprocess.Popen('ncat -u -l -p 3333 > utils/listenSlave', shell=True) 
	threading.Timer(period,sync,[no_usrp, tunnel, scan, dwell, slot, period, interval]).start() 


def main(top_block_cls=transceiver_OQPSK_Slave):
    if gr.enable_realtime_scheduling() != gr.RT_OK:
        print "Error: failed to enable real-time scheduling."
    from distutils.version import StrictVersion
    if StrictVersion(Qt.qVersion()) >= StrictVersion("4.5.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    global tb, usrp_addr, gotSync, frequencies, i, Lines#, tunName
    global word, port, p_listenSlave, subp_listenSlave, tun	

    parser = OptionParser(option_class=eng_option, usage="%prog: [options]")

    parser.add_option("-u","--usrp-addr", default="addr = 192.168.10.2",
			   help="IP address of the USRP without \"addr=\"")
    parser.add_option("-f", "--init-freq", type="eng_float", default=174,
		           help="initial frequency in MHz [default=%default]")
    parser.add_option("-o", "--otw", default="sc16",
		           help="select over the wire data format (sc16 or sc8) [default=%default]")
    parser.add_option("-l", "--no-self-loop", action="store_false", default=True,
                           help="enable mechanism of avoiding self-routed packets [default=%default]")
    parser.add_option("", "--source", type="choice", choices=['socket', 'tuntap', 'strobe'], default='tuntap',
                           help="'tuntap' interface, 'socket' or 'strobe' [default=%default]")  
    parser.add_option("-y", "--bytes", type="eng_float", default=256,
                           help="Number of bytes to read/write from/to filedescriptors (for debug purpose) [default=%default]")
    parser.add_option("-t", "--tunnel",  action="store_true", default=False,
                       	   help="enable tunnel mode or send random data generated locally at slave node [default=%default]")
    parser.add_option("-i", "--interval", type="eng_float", default=0.2,
                           help="interval in seconds between two packets being sent [default=%default]")
    parser.add_option("-S", "--scan-interv", type="eng_float", default=2,
                           help="interval in sec between every scan for frequency to sync with the master node [default=%default]")
    parser.add_option("-w", "--dwell", type="eng_float", default=2,
                           help="dwell time in each center frequency in the sync phase [default=%default]")
    parser.add_option("-p", "--period-check",type="eng_float", default=1,
                           help="interval in sec for period check of beacon [default=%default]")
    parser.add_option("", "--slot",type="eng_float", default=60,
                           help="duration in sec of the slave given slot to communicate data [default=%default]")

    ## Debugging and Verbose options	
    parser.add_option("", "--debug-MAC", action="store_true", default=False,
                           help="Debugging the MAC Layer [default=%default]")
    parser.add_option("-W", "--wireshark", action="store_true", default=False,
                           help="Enable Wireshark capture[default=%default]")
    parser.add_option("-v", "--verbose",action="store_true", default=False, 
			   help="verbose mode [default=%default]")
    parser.add_option("","--no-usrp", action="store_true", default=False,
			   help="Using file sink and source instead of USRPs")

    (options, args) = parser.parse_args()

    usrp_addr	= "addr="+options.usrp_addr
    word = "FFFFFFFF"
    port = "52004"
    i = 1
    initialFreq = 1e6 * float(options.init_freq)
    CE_channels_indices = (36, 37, 38, 39, 40, 41, 42, 43, 44)
    TVWS_CE_channels = {x: TVWS_channelmap.Channels[x] for x in CE_channels_indices}
    #frequencies = [x * 1e6 for x in (TVWS_channelmap.Channels).values()]
    frequencies = [x * 1e6 for x in TVWS_CE_channels.values()]
    open('utils/listenSlave', 'w').close()
    tb = top_block_cls(options.usrp_addr, 
		       options.no_usrp, 
		       initialFreq, 
		       options.otw, 
		       options.source, 
		       options.no_self_loop, 
		       options.debug_MAC,
		       options.wireshark)

    if not options.no_usrp:	
	from gnuradio import uhd, digital
    	print "\n Initial frequency: ", initialFreq/1e6, "MHz"
	tb.set_samp_rate(4e6)
    	tb.set_freq(initialFreq)

    subp_listenSlave = subprocess.Popen("ncat -u -l -p 3333 > utils/listenSlave",  shell=True)

    ### Frequency Sweep procedure ##   	
    threading.Timer(2,
		    sync,
		    [options.no_usrp, options.tunnel, options.scan_interv, options.dwell, options.slot, options.period_check, options.interval]).start()

    if (options.tunnel):
        parent_conn, child_conn = Pipe()		
    	tun = tunnel(tb.ieee802_15_4_mac_0, port, options.slot, child_conn.fileno(), options.interval, options.verbose)	
    try:    
            subprocess.call("""sudo tunctl -d tap1 -f /dev/net/tun
                               sudo tunctl -t tap1 -u $USER -f /dev/net/tun 
                               sudo ip addr add 10.0.1.8/24 dev tap1
                               sudo ip link set tap1 up""", shell=True)
    except OSError as e:
            print >>sys.stderr, "Execution failed:", e

    tb.start()
    tb.show()

    def quitting():
        tb.stop()
        tb.wait()
    qapp.connect(qapp, Qt.SIGNAL("aboutToQuit()"), quitting)
    qapp.exec_()

def open_tun_interface(tun_device_filename):

    IFF_TUN         = 0x0001   # tunnel IP packets
    IFF_TAP         = 0x0002   # tunnel ethernet frames
    IFF_NO_PI       = 0x1000   # don't pass extra packet info
    IFF_ONE_QUEUE   = 0x2000   # beats me ;)
    TUNSETIFF       = 0x400454ca

    mode = IFF_TAP | IFF_NO_PI

    tun = os.open(tun_device_filename, os.O_RDWR)
    ifs = ioctl(tun, TUNSETIFF, struct.pack("16sH", "gr%d", mode))
    ifname = ifs[:16].strip("\x00")
    return (tun, ifname)

class tunnel():

    def __init__ (self, myMac, myPort, mySlot, myPipe, interval, verbose):
	
	self.mac	= myMac
        self.myPort 	= myPort	
        self.mySlot 	= mySlot
	self.pipe_fd	= myPipe
	self.interval	= interval
	self.verbose	= verbose

        # open the TUN/TAP interface
	(self.tun_fd, self.tun_ifname) = open_tun_interface("/dev/net/tun")
	print "tun_fd: ", self.tun_fd
	print "ifname: ", self.tun_ifname

    def run(self) :
	print "Testing 509"
	if self.verbose: print "Running the tunnel main function ..."
        try :
	    listen = subprocess.Popen("ncat -u -l -p 3333 > utils/listenSlave", shell=True)
	    print "Testing 512"
	    try:
	    	sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		# bind it
	        sendSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	    except socket.error , msg:
	    	print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	    	sys.exit()

	    #Sending loop
            start_time = time.time()  
            while (time.time() - start_time) < self.mySlot:
		print "Testing 518"
		(inputready,outputready,exceptionready)= select.select([self.tun_fd,self.pipe_fd],[],[])
		print "Testing 520"
                if self.tun_fd in inputready :
		    print "Testing 522"
		    if self.verbose: Packet.printIpHeader(payload)
                    ip_header = payload[0:20]
                    (iph, protocol,iph_length,ip_length, src_ip,dst_ip) = Packet.unpackIpHeader(ip_header)

                    if protocol == 1: #deal with ICMP echo request
			print "protocol == 1"	
                        packet = payload
                        icmp_type,icmp_code,icmp_identifier,icmp_sequence = Packet.unpackIcmpHeader(packet,iph_length)
                        if icmp_type == 8 : # type 8 is echo request
                            reply = Packet.createIcmpReply(packet)
			    if self.verbose: 
				#print "got an echo request replying with echo response"
                            	Packet.printIpHeader(reply)
                        #os.write(self.tun_fd,reply) 
			self.mac.app_in(pmt.cons(pmt.PMT_NIL, pmt.to_pmt(packet)))
                    else:
			print "Testing 401"
			if self.verbose: print "Not an ICMP Packet"
			bytes = map(ord,payload)
			print "bytes @ 398", bytes
			self.mac.app_in(pmt.cons(pmt.PMT_NIL, pmt.to_pmt(bytes)))
			print "\n \n Passed 411"

                elif self.pipe_fd in inputready:
		    print "self.pipe_fd in inputready"	
                    payload = os.read(self.pipe_fd, 256)
                    nwritten = os.write(self.tun_fd,payload)
                    if self.verbose: print " tunnel.run: write nbytes ", nwritten
		print "Sleeping for a minute"
                time.sleep(self.interval)
	    print "Testing 552"	
            listen.kill()
  	    sendSock.close()

        finally:
            print "Exitting LOOP !!"

if __name__ == '__main__':
  os.setpgrp() # create new process group, become its leader
  try:
    main()
  except KeyboardInterrupt:
	subprocess.Popen('ps auxw | grep -ie \'slave_transceiver_OQPSK.py\' | awk \'{print $2}\' | xargs sudo kill -', shell=True)
	subprocess.Popen('sudo ip link delete tap1', shell=True)
        print "Bye"
        sys.exit(0)
  finally:
	try:
	    os.remove("utils/listenSlave")
	except OSError:
	    pass
	    os.killpg(0, signal.SIGKILL) # kill all processes in my group
