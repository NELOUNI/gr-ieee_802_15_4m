#!/usr/bin/python
# -*- coding: utf-8 -*-

import os 
from PyQt4 import QtGui, QtCore

#class Window(QtGui.QWidget):
class Window(QtGui.QMainWindow):

    def __init__(self):

        super(Window, self).__init__()
        self.initUI()

    def initUI(self):

        self.tvClient = QtGui.QPushButton('Turn ON Tv Client', self)
        self.tvClient.clicked.connect(self.handle_tvClient)
        self.master = QtGui.QPushButton('Turn ON 802.15.4m Master Node', self)
        self.master.clicked.connect(self.handle_master)
        self.slave = QtGui.QPushButton('Turn ON 802.15.4m Slave Node', self)
        self.slave.clicked.connect(self.handle_slave)
        self.wsdb = QtGui.QPushButton('Run the WSDB', self)
        self.wsdb.clicked.connect(self.handle_wsdb)

        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.tvClient)
        layout.addWidget(self.master)
        layout.addWidget(self.slave)
        layout.addWidget(self.wsdb)

        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&File')
        fileMenu.addAction(exitAction)
        self.setGeometry(300, 300, 300, 200)

    	w = QtGui.QWidget()
    	w.resize(250, 150) #w.
    	w.move(300, 300)   #w.
    	self.setWindowTitle('WSDB coordinated 802.15.4m 2 tiered communication setup')
	self.show()
        
    def center(self):
        frameGm = self.frameGeometry()
        screen = QtGui.QApplication.desktop().screenNumber(QtGui.QApplication.desktop().cursor().pos())
        centerPoint = QtGui.QApplication.desktop().screenGeometry(screen).center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def handle_tvClient(self):
	print "\n##########################"
	print " Turning TV Client ON ... "
	print "##########################"
	#os.system("xterm -hold -e tvClient.sh")
	os.system("tvClient.sh")

    def handle_master(self):
	print "\n######################################"
	print " Turning 802.15.4m Master Node ON ... "
	print "######################################"
	os.system("xterm -hold -e master.sh")

    def handle_slave(self):
	print "\n#####################################"
	print " Turning 802.15.4m Slave Node ON ... "
	print "#####################################"
	os.system("xterm -hold -e slave.sh")

    def handle_wsdb(self):
	print "\n###################"
	print " Running WSDB ... "
	print "###################"
	os.system("xterm -hold -e wsdb.sh")
	#os.system("wsdb.sh")

def main():

    import sys
    app = QtGui.QApplication(sys.argv)
    window = Window()
    #window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
