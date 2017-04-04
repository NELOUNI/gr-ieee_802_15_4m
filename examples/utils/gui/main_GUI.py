#!/usr/bin/python
# -*- coding: utf-8 -*-

import os 
from PyQt4 import QtGui, QtCore

class Window(QtGui.QWidget):
    def __init__(self):
        QtGui.QWidget.__init__(self)
        self.tvClient = QtGui.QPushButton('Turn ON Tv Client', self)
        self.tvClient.clicked.connect(self.handle_tvClient)
        self.master = QtGui.QPushButton('Turn ON 802.15.4m Master Node', self)
        self.master.clicked.connect(self.handle_master)
        self.slave = QtGui.QPushButton('Turn ON 802.15.4m Slave Node', self)
        self.slave.clicked.connect(self.handle_slave)
        self.wsdb = QtGui.QPushButton('Run the WSDB', self)
        self.wsdb.clicked.connect(self.handle_wsdb)
        layout = QtGui.QVBoxLayout(self)
        layout.addWidget(self.tvClient)
        layout.addWidget(self.master)
        layout.addWidget(self.slave)
        layout.addWidget(self.wsdb)

    	w = QtGui.QWidget()
    	w.resize(250, 150)
    	w.move(300, 300)
    	w.setWindowTitle('WSDB coordinated 802.15.4m 2 tiered communication setup')
	w.show()

    def center(self):
        frameGm = self.frameGeometry()
        screen = QtGui.QApplication.desktop().screenNumber(QtGui.QApplication.desktop().cursor().pos())
        centerPoint = QtGui.QApplication.desktop().screenGeometry(screen).center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def handle_tvClient(self):
	print "##########################"
	print " Turning TV Client ON ... "
	print "##########################"
	#os.system("xterm -hold -e tvClient.sh")
	os.system("tvClient.sh")

    def handle_master(self):
	print "######################################"
	print " Turning 802.15.4m Master Node ON ... "
	print "######################################"
	os.system("xterm -hold -e master.sh")

    def handle_slave(self):
	print "#####################################"
	print " Turning 802.15.4m Slave Node ON ... "
	print "#####################################"
	os.system("xterm -hold -e slave.sh")

    def handle_wsdb(self):
	print "###################"
	print " Running WSDB ... "
	print "###################"
	os.system("xterm -hold -e wsdb.sh")

if __name__ == '__main__':

    import sys
    app = QtGui.QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec_())
