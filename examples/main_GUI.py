#!/usr/bin/python
# -*- coding: utf-8 -*-

import os, subprocess
#subprocess.Popen("sudo xauth add $(xauth -f ~/.Xauthority list|tail -1)", shell=True) 
from PyQt4 import QtGui, QtCore

class main_GUI(QtGui.QWidget):

    def __init__(self):

        super(main_GUI, self).__init__()
        self.initUI()

    def initUI(self):

	self.col = QtGui.QColor(0, 0, 0)

	exitAction = QtGui.QAction(QtGui.QIcon('exit.png'), '&Exit', self)        
        exitAction.setShortcut('Ctrl+Q')
        exitAction.setStatusTip('Exit application')
        exitAction.triggered.connect(QtGui.qApp.quit)

	grid = QtGui.QGridLayout()
        self.setLayout(grid)
 
        names = ['tvClient', 'WSDB', 'master', 'slave']
	
    	QtGui.QToolTip.setFont(QtGui.QFont('SansSerif', 10))

        self.setToolTip('This is a <b>QWidget</b> widget')

        self.tvClient = QtGui.QPushButton('Turn ON Tv Client', self)
	self.tvClient.setCheckable(True)
        self.tvClient.clicked[bool].connect(self.handle_tvClient)
        #self.tvClient.clicked[bool].connect(self.process)
	self.tvClient.setToolTip('This launches the <b>TV Client</b> emulating the incumbent')
        self.tvClient.resize(self.tvClient.sizeHint())
        grid.addWidget(self.tvClient, *(1,1))

        self.wsdb = QtGui.QPushButton('Run the WSDB', self)
	self.wsdb.setCheckable(True)
        self.wsdb.clicked[bool].connect(self.handle_wsdb)
	self.wsdb.setToolTip('This runs the <b>TV White Space Database</b>')
        self.wsdb.resize(self.wsdb.sizeHint())
        grid.addWidget(self.wsdb, *(1,2))

        self.master = QtGui.QPushButton('Turn ON 802.15.4m Master Node', self)
	self.master.setCheckable(True)
        self.master.clicked[bool].connect(self.handle_master)
	self.master.setToolTip('This launches the <b>Master Node</b> of the 802.15.4m framework')
        self.master.resize(self.master.sizeHint())
        grid.addWidget(self.master, *(2,1))

        self.slave = QtGui.QPushButton('Turn ON 802.15.4m Slave Node', self)
	self.slave.setCheckable(True)
        self.slave.clicked[bool].connect(self.handle_slave)
	self.slave.setToolTip('This launches a <b>Slave Node</b> of the 802.15.4m framework')
        self.slave.resize(self.slave.sizeHint())
        grid.addWidget(self.slave, *(2,2))

	self.setGeometry(600, 600, 350, 350)
        self.move(300, 150)
    	self.setWindowTitle('WSDB coordinated 802.15.4m 2 tiered communication setup')
	self.center()
	self.show()
#"""
#Attempt to process the 4 buttons in one function
#"""
#    def process(self, pressed):	
#	source = self.sender()
#	if source.text() == "Turn ON Tv Client":
#        	if pressed:
#		    self.tvClient.setText('TV Client ON')
#		    print "\n##########################"
#		    print " Turning TV Client ON ... "
#		    print "##########################"
#		    subprocess.Popen("ssh -Y nae@pwct5.ctl.nist.gov 'bash -s' < tvClient.sh", shell=True)
#        	else:	
#		    self.tvClient.setText('TV Client OFF')
#		    print "\n##########################"
#		    print " Turning TV Client OFF ... "
#		    print "##########################"
#		    subprocess.Popen("ssh -Y nae@pwct5.ctl.nist.gov 'bash -s' < kill_tvClient.sh", shell=True) 

    def handle_tvClient(self, pressed):
        if pressed:
	    self.tvClient.setText('TV Client ON')
	    print "\n##########################"
	    print " Turning TV Client ON ... "
	    print "##########################"
	    subprocess.Popen("ssh -Y nae@pwct5.ctl.nist.gov 'bash -s' < tvClient.sh", shell=True)
        else:	
	    self.tvClient.setText('TV Client OFF')
	    print "\n##########################"
	    print " Turning TV Client OFF ... "
	    print "##########################"
    	    subprocess.Popen("ssh -Y nae@pwct5.ctl.nist.gov 'bash -s' < kill_tvClient.sh", shell=True) 

    def handle_wsdb(self, pressed):
        if pressed:
	    self.wsdb.setText('WSDB ON')
	    print "\n##################"
	    print " Running WSDB ... "
	    print "####################"
	    subprocess.Popen("wsdb.sh", shell=True)
        else:	
	    self.wsdb.setText('WSDB OFF')
	    print "\n#####################"
	    print " Turning WSDB OFF ... "
	    print "#######################"
    	    #subprocess.Popen("cat .wsdb.pid | xargs sudo kill -9 && rm .wsdb.pid", shell=True) 
	    subprocess.call('ps auxw | grep -ie \'webServerWSDB.py\' | awk \'{print $2}\' | xargs sudo kill -9', shell=True)

    def handle_master(self, pressed):
        if pressed:
	    self.master.setText('Master ON')
	    print "\n######################################"
	    print " Turning 802.15.4m Master Node ON ... "
	    print "######################################"
	    subprocess.Popen("master.sh", shell=True)
        else:	
	    self.master.setText('Master OFF')
	    print "\n######################################"
	    print " Turning 802.15.4m Master Node OFF ... "
	    print "######################################"
	    subprocess.call('ps auxw | grep -ie \'master_transceiver_OQPSK.py\' | awk \'{print $2}\' | xargs sudo kill -9', shell=True)

    def handle_slave(self, pressed):
        if pressed:
	    self.slave.setText('Slave ON')
	    print "\n######################################"
	    print " Turning 802.15.4m Slave Node ON ... "
	    print "######################################"
	    subprocess.Popen("slave.sh", shell=True)
        else:	
	    self.slave.setText('Slave OFF')
	    print "\n#####################################"
	    print " Turning 802.15.4m Slave Node OFF ... "
	    print "######################################"
    	    subprocess.Popen("cat .slave.pid | xargs sudo kill -9 && rm .slave.pid", shell=True) 
	    subprocess.call('ps auxw | grep -ie \'slave_transceiver_OQPSK.py\' | awk \'{print $2}\' | xargs sudo kill -9', shell=True)

    def center(self):
        frameGm = self.frameGeometry()
        screen = QtGui.QApplication.desktop().screenNumber(QtGui.QApplication.desktop().cursor().pos())
        centerPoint = QtGui.QApplication.desktop().screenGeometry(screen).center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

def main():
    import sys
    app = QtGui.QApplication(sys.argv)
    GUI = main_GUI()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
