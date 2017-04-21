#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: IEEE 802.15.4m Master Node Transceiver using OQPSK
# Generated: Tue Mar 21 16:13:54 2017
##################################################

import subprocess, os, sys
try:
        subprocess.call('ps auxw | grep -ie \'listenMaster ncat tee\' | awk \'{print $2}\' | xargs sudo kill -9', shell=True) 
	subprocess.Popen('sudo ip link delete tap0', shell=True)
except OSError as e:
    print >>sys.stderr, "Execution failed:", e

if __name__ == '__main__':
    import ctypes
    import sys
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
import json, pycurl, StringIO, time, select, psutil
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
from gnuradio import qtgui

class transceiver_OQPSK_Master(gr.top_block, Qt.QWidget):

    def __init__(self, addr, no_usrp, initialFreq, otw, source, no_self_loop, debug_MAC, wireshark):
        gr.top_block.__init__(self, "IEEE 802.15.4m Master Node Transceiver using OQPSK")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("IEEE 802.15.4m Master Node Transceiver using OQPSK")
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

        self.settings = Qt.QSettings("GNU Radio", "transceiver_OQPSK_Master")
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
	   	self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, 4e6,True)
		## Using files instead of USRPs
	        self.blocks_file_source_Master = blocks.file_source(gr.sizeof_gr_complex*1, (os.getcwd()+"/utils/masterFileSource"), True)
	        self.blocks_file_sink_Master = blocks.file_sink(gr.sizeof_gr_complex*1, (os.getcwd()+"/utils/masterFileSink"), False)
	        self.blocks_file_sink_Master.set_unbuffered(False)
	else:
	        ## usrp_source
 		self.uhd_usrp_source_0 = uhd.usrp_source(",".join((self.addr, "")),
                					uhd.stream_args(
                        				cpu_format="fc32",
                        				channels=range(1),),)
	        ## usrp_sink
        	self.uhd_usrp_sink_0 = uhd.usrp_sink(",".join((self.addr, "")),
        	        			    uhd.stream_args(
        	                		    cpu_format="fc32",
        	                		    channels=range(1),),)
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
        	self.blocks_tuntap_pdu_0 = blocks.tuntap_pdu("tap0", 440)
        	self.msg_connect(self.ieee802_11_ether_encap_0, "to tap", self.blocks_tuntap_pdu_0, "pdus")
        	self.msg_connect(self.blocks_tuntap_pdu_0, "pdus", self.ieee802_11_ether_encap_0, "from tap")

        	self.msg_connect(self.ieee802_15_4_rime_stack_0, "bcout", self.ieee802_11_ether_encap_0, "from wifi")
        	self.msg_connect(self.ieee802_11_ether_encap_0,  "to wifi" , self.ieee802_15_4_rime_stack_0, "bcin") 

	elif self.source == "socket":   #using PDU Sockets instead #TODO Test ME ! 
		self.blocks_socket_pdu_0_Tx = blocks.socket_pdu("UDP_SERVER", "localhost", "52002", 10000)
		self.blocks_socket_pdu_0_Rx = blocks.socket_pdu("UDP_CLIENT", "localhost", "3334", 10000)

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
                self.connect((self.ieee802_15_4_oqpsk_phy_0, 0), ((self.blocks_file_sink_Master, 0))) 
                self.connect((self.blocks_file_source_Master, 0), (self.ieee802_15_4_oqpsk_phy_0, 0)) 
        else:
                self.connect((self.ieee802_15_4_oqpsk_phy_0, 0), ((self.uhd_usrp_sink_0, 0))) 
                self.connect((self.uhd_usrp_source_0, 0), (self.ieee802_15_4_oqpsk_phy_0, 0)) 

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "transceiver_OQPSK_Master")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
	self.uhd_usrp_sink_0.set_normalized_gain(self.tx_gain, 0)

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
	self.uhd_usrp_source_0.set_normalized_gain(self.rx_gain, 0)

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

def getFreqMap(spec_dB, remote_dB):

     if(spec_dB == "google"):
	url = 'https://www.googleapis.com/rpc'
     elif(spec_dB == "local"):
	url = 'http://127.0.0.1:9001/'
     elif(spec_dB == "remote"):  
        url = 'https://'+remote_dB+':9001'

     postdata = []
     buf = StringIO.StringIO()
     with open("utils/postdata.txt", "r") as fpostdata:
           while True:
                c = fpostdata.read(1)
                postdata.append(c) 
                if not c:
                        break
     fpostdata.close()    
     postdata_str = ''.join(postdata)
     c = pycurl.Curl()
     c.setopt(c.HTTPHEADER, ['Accept: application/json', 'Content-Type: application/json','charsets: utf-8'])
     c.setopt(c.URL, url) 

     if(spec_dB == "remote"):
     	c.setopt(pycurl.SSLCERT, "utils/keys/rsa.crt")		
     	c.setopt(pycurl.SSLKEY, "utils/keys/rsa.pem")		

     	c.setopt(pycurl.SSL_VERIFYPEER, 0)
     	c.setopt(pycurl.SSL_VERIFYHOST, 2)
	c.setopt(pycurl.CONNECTTIMEOUT, 2)
    	c.setopt(pycurl.TIMEOUT, 2)

     # send all data to this function
     c.setopt(c.WRITEFUNCTION, buf.write)
     # some servers don't like requests that are made without a user-agent field, so we provide one
     c.setopt(c.USERAGENT,'libcurl-agent/1.0')
     c.setopt(c.POSTFIELDS, postdata_str)
     # if we don't provide POSTFIELDSIZE, libcurl will strlen() by itself
     c.setopt(c.POSTFIELDSIZE, len(postdata_str))
     try:
        # Perform the request
        c.perform()
     except pycurl.error as e:    # This is the correct syntax
        print e, "\n\n**** Please start the WSDB and/or make sure you set appropriate configuration (host/port/authentication)\n\n"
     json = buf.getvalue()
     buf.close()
     c.close()
     return json

def parseJSON(n, spec_dB):
	global centerFreqs
        local_n = n
        objs = json.loads(local_n)
        frequencyRanges = objs["result"]["spectrumSchedules"][0]["spectra"][0]["frequencyRanges"]
        nbr_frequencies = len(frequencyRanges)
	centerFreqs = []
        for i in range (0, nbr_frequencies):
		centerFreqs.append(0.5*(frequencyRanges[i]["startHz"] + frequencyRanges[i]["stopHz"]))
	if (spec_dB == "google"): centerFreqs = [x / 1000000 for x in centerFreqs]
	print "There are",nbr_frequencies, "frequencies available:", centerFreqs, "MHz"

def process(no_usrp, beacon_interv, spec_dB, remote_dB):
    global tb, word, centerFreqs, actualFreq, port, tun	
    global tun_device_filename, subp_ListenMaster
 	
    size 	  = 80    
    beacon        = "B" * 8

    #Opening socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # bind it
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #Sending loop
    while True:
	#beacon = beacon + (size - len(beacon)) * " " 
        print "Sending beacon: ", beacon
    	s.sendto(beacon, ("localhost", int(port)))    
	#tun.run()
    	time.sleep(float(beacon_interv))
	print "Querying WSDB for available TV channels ..."
	n = getFreqMap(spec_dB, remote_dB)
        parseJSON(n, spec_dB)
	print "Actual frequency: ", actualFreq/1e6, "MHz"
        print "#######################################################################"
        word = actualFreq
	if ((actualFreq / 1000000) not in centerFreqs) or (actualFreq < 400000000):
		word = 1000000 * random.choice(centerFreqs)
		if (word < 400000000): print "Frequency chosen not supported with SBX daughterboard"
		else: 
	        	actualFreq = word
	        	# Need to handle the 200kHz channel BW assignement 
			if not no_usrp:
    		        	newFreq = int(word)
    		        	tb.set_freq(newFreq)
    		        	print "\n\n\nSwitching to new Frequency: ", actualFreq / 1000000
	        	print "*********************************************************************"

def main(top_block_cls=transceiver_OQPSK_Master):
    if gr.enable_realtime_scheduling() != gr.RT_OK:
        print "Error: failed to enable real-time scheduling."
    from distutils.version import StrictVersion
    if StrictVersion(Qt.qVersion()) >= StrictVersion("4.5.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    global tb, usrp_addr, actualFreq, centerFreqs
    global getAck, word, port, subp_AssociateReq, n, VERBOSE, tun
    global subp_broadNewFreq, subp_periodListen, subp_slaveRespReq, tun_device_filename, subp_ListenMaster
	 
    parser = OptionParser(option_class=eng_option, usage="%prog: [options]")

    parser.add_option("-u","--usrp-addr", default="addr = 192.168.10.2",
			   help="IP address of the USRP without \"addr=\"")
    parser.add_option("-f", "--init-freq", type="eng_float", default=716,
		           help="initial frequency in MHz [default=%default]")
    parser.add_option("-o", "--otw", default="sc16",
		           help="select over the wire data format (sc16 or sc8) [default=%default]")
    parser.add_option("-l", "--no-self-loop", action="store_false", default=True,
                           help="enable mechanism of avoiding self-routed packets [default=%default]")
    parser.add_option("", "--source", type="choice", choices=['socket', 'tuntap', 'strobe'], default='tuntap',
                           help="'tuntap' interface, 'socket' or 'strobe' [default=%default]")  
    parser.add_option("-B", "--beacon-interv", type="eng_float", default=1,
                           help="interval in sec between every beacon transmission [default=%default]")
    parser.add_option("-G", "--spec-dB", type="choice", choices=['local', 'google', 'remote'], default='google',
                           help="choice of the spectrum database: local dB or google dB or on remote host [default=%default]")
    parser.add_option("-a", "--remote-dB", default='pwct3.antd.nist.gov',
			   help="Adress of the remote host of the Spectrum Database, [default=%default]")
    parser.add_option("-y", "--bytes", type="eng_float", default=256,
                           help="Number of bytes to read/write from/to filedescriptors (for debug purpose) [default=%default]")
    parser.add_option("-i", "--interval", type="eng_float", default=0.2,
                           help="interval in seconds between two packets being sent [default=%default]")
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

    getAck	= False
    usrp_addr   = "addr="+options.usrp_addr
    initialFreq	= 1e6 * float(options.init_freq)

    tb = top_block_cls(options.usrp_addr, 
		       options.no_usrp, 
		       initialFreq, 
		       options.otw, 
		       options.source, 
		       options.no_self_loop, 
		       options.debug_MAC,
		       options.wireshark)

    if not options.no_usrp:	
	tb.set_samp_rate(4e6)
	tb.set_freq(initialFreq)
        if options.verbose:	
    	    print "usrp_addr = ", options.usrp_addr
	    print " \n Initial frequency: ", tb.get_freq()/1e6, "MHz"
    actualFreq = initialFreq	
    word = "FFFFFFFF"
    port = 52002
    subp_ListenMaster =  subprocess.Popen('ncat -u -l -p 3334 > utils/listenMaster', shell=True)

#    if options.source == "tuntap":
#	try:
#	    subprocess.call("sudo ifconfig tap0 192.168.100.1", shell=True)
#	except OSError as e:
#	    print "Execution failed: ", e

    try :    
            subprocess.call("""sudo tunctl -d tap0 -f /dev/net/tun
                               sudo tunctl -t tap0 -u $USER -f /dev/net/tun 
                               sudo ip addr add 10.0.0.9/24 dev tap0
                               sudo ip link set tap0 up""", shell=True)
    
    except OSError as e:
            print >>sys.stderr, "Execution failed:", e

    threading.Timer(2, process, (options.no_usrp, options.beacon_interv, options.spec_dB, options.remote_dB)).start()	
   	
    ## open the TUN/TAP interface
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    parent_conn, child_conn = Pipe()
    tun = tunnel(child_conn.fileno(), tun_fd, options.verbose, options.bytes, options.interval)
    tun.start()
    
    tb.start()
    tb.show()

    def quitting():
        tb.stop()
        tb.wait()
    qapp.connect(qapp, Qt.SIGNAL("aboutToQuit()"), quitting)
    qapp.exec_()

class tunnel(threading.Thread):

    def __init__ (self, myPipe, tun_interface, verbose, bytes, interval):	
    #def __init__ (self, myPipe, verbose, bytes, interval):	
	print "TEST Tunnel"
	threading.Thread.__init__(self)

	self.verbose 	   = verbose 
        #self.tun_interface = tun_interface
	self.bytes	   = bytes
        self.interval	   = interval
	
	open("utils/listenMaster", "w+").close
	self.fd = open("utils/listenMaster", 'r+b')
	self.pipe_fd = myPipe
         
    def run(self) :
	if self.verbose: print "Running the tunnel main function ..."
        try :
            #Opening socket
  	    sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
#  	    udpSock = socket.socket(socket.AF_INET,  socket.SOCK_DGRAM)
            # bind it
            sendSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#            udpSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  
            while 1:
	    	(inputready,outputready,exceptionready)= select.select([self.fd,self.pipe_fd],[],[])
            	if self.fd in inputready :
	    	    #payload = list(os.read(self.fd.fileno(), self.bytes))
	            payload = os.read(self.fd.fileno(), self.bytes)
	    	    if payload:
			     print "payload at Master: ", payload	
			     #payload = "".join(payload)	
	    	             #if self.verbose: print "type(payload): ", type(payload)
	    		     ip_header = payload[0:20]
            		     (iph, protocol,iph_length,ip_length, src_ip,dst_ip) = Packet.unpackIpHeader(ip_header)
			     #destIpAddr = str(socket.inet_ntoa(iph[9]))	
	    	             if protocol == 1:
				 if self.verbose: Packet.printIpHeader(payload)
	    	    	 	 packet = payload  	
	    	    	 	 icmp_type,icmp_code,icmp_identifier,icmp_sequence = Packet.unpackIcmpHeader(packet,iph_length)
            		         # type 8 is echo request
            		         if icmp_type == 8 : 
            		             reply = Packet.createIcmpReply(packet)
				     #if self.verbose: 
					#print "got an echo request replying with echo response"
		            		#Packet.printIpHeader(reply)
	    		     	     #os.write(self.tun_interface, reply)
	    	         	     destIpAddr = str(socket.inet_ntoa(iph[9]))
	    	         	     srcIpAddr = str(socket.inet_ntoa(iph[8])) 	
	    	         	     #if self.verbose: print "destIpAddr = str(socket.inet_ntoa(iph[9])) : ", destIpAddr			
			     	 sendSock.sendto(reply, (destIpAddr, 55555))
	      		     else:
	    	          	 payload = 'E' + payload			
				 ip_header = payload[0:20]
                                 (iph, protocol,iph_length,ip_length, src_ip,dst_ip) = Packet.unpackIpHeader(ip_header)
				 Packet.printIpHeader(payload)
				 destIpAddr = str(socket.inet_ntoa(iph[9]))
				 #os.write(self.tun_interface, payload) 	
	    	     	     	 sendSock.sendto(payload, (destIpAddr, 5001))	
				 #udpSock.sendto(payload, (destIpAddr, 5008))	
		    time.sleep(self.interval)
#	    udpSock.close()
            sendSock.close()
        finally:
            print "Exitting LOOP !!"
    
if __name__ == '__main__':
  os.setpgrp() # create new process group, become its leader
  try:
    main()
  except KeyboardInterrupt:
	subprocess.Popen('ps auxw | grep -ie \'master_transceiver_OQPSK.py\' | awk \'{print $2}\' | xargs sudo kill -', shell=True) 
	subprocess.Popen('sudo ip link delete tap0', shell=True)
        print "Bye"
        sys.exit()
  finally:
	try:
		os.remove("utils/listenMaster")	
	except OSError:
		pass	
	#os.killpg(0, signal.SIGKILL) # kill all processes in my group
