from winpcapy import WinPcapUtils
from winpcapy import WinPcapDevices
from winpcapy import WinPcap

import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QMainWindow, 
	QComboBox, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, 
	QGridLayout)
from PyQt5.QtCore import QObject, QThread, pyqtSignal

from parse import parsePkt

class Worker(QObject):
	finished = pyqtSignal()
	received = pyqtSignal(bytes)
	def __init__(self, deviceName):
		super().__init__()
		self.deviceName = deviceName
	def run(self):
		with WinPcap(self.deviceName) as capture:
			self.win_pcap = capture
			capture.run(callback=self.packet_callback)
	def packet_callback(self, win_pcap, param, header, pkt_data):
		self.received.emit(pkt_data)
	def stop(self):
		self.win_pcap.stop()

class SnifferUI(QWidget):#QMainWindow):
	def __init__(self, deviceList = []):
		super().__init__()
		self.deviceList = list(deviceList.items())
		self.on = False
		self.pktCnt = 0
		self.initUI()
	def initDeviceSelector(self):
		deviceSelector = QComboBox()
		for name, desciption in self.deviceList:
			deviceSelector.addItem(desciption)
		deviceSelector.resize(deviceSelector.sizeHint())
		self.deviceSelector = deviceSelector
	def initStartButton(self):
		startButton = QPushButton('Start')
		startButton.clicked.connect(self.buttonClicked)#(self.startSniff)
		startButton.resize(startButton.sizeHint())
		self.startButton = startButton
	def initPackageTable(self):
		packageTable = QTableWidget()
		packageTable.setRowCount(0)
		packageTable.setColumnCount(5)
		
		packageTable.setHorizontalHeaderLabels(['id', 'srcAddr', 'dstAddr', 'type', 'info'])
		packageTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
		packageTable.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
		packageTable.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
		packageTable.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
		packageTable.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
		packageTable.verticalHeader().setHidden(True)

		packageTable.resize(packageTable.sizeHint())
		packageTable.setGeometry(0, 150, 1000, 400)
		
		self.packageTable = packageTable
	def initLayout(self):
		layout = QGridLayout()
		layout.setSpacing(10)
		
		layout.addWidget(self.deviceSelector, 1, 1, 1, 2)
		layout.addWidget(self.startButton, 1, 0, 1, 1)
		layout.addWidget(self.packageTable, 3, 0, 5, 3)
		
		self.layout = layout
		self.setLayout(self.layout)
	def initUI(self):
		self.initDeviceSelector()
		self.initStartButton()
		self.initPackageTable()
		self.initLayout()
		
		self.setGeometry(150, 150, 1000, 500)
		self.setWindowTitle('Sniffer')
		self.show()
	def addPacket(self, layers):
		self.pktCnt += 1
		curRow = self.packageTable.rowCount()
		nLayer = 0
		for pkt in layers:
			if pkt:
				src, dst, type, info = pkt[0], pkt[1], pkt[2], pkt[3]
				rowCnt = self.packageTable.rowCount()
				self.packageTable.insertRow(rowCnt)
			
				self.packageTable.setItem(rowCnt, 1, QTableWidgetItem(src))
				self.packageTable.setItem(rowCnt, 2, QTableWidgetItem(dst))
				self.packageTable.setItem(rowCnt, 3, QTableWidgetItem(type))
				self.packageTable.setItem(rowCnt, 4, QTableWidgetItem(info))
				
				nLayer += 1
		
		self.packageTable.setSpan(curRow, 0, nLayer, 1);
		self.packageTable.setItem(curRow, 0, QTableWidgetItem(str(self.pktCnt)))
	
	def receivePacket(self, pkt_data):
		layers = parsePkt(pkt_data)
		self.addPacket(layers)
	def buttonClicked(self):
		if self.on:
			#stop sniff
			self.on = False
			self.startButton.setText('Start')
			self.deviceSelector.setEnabled(True)
			self.worker.stop()
			self.thread.quit()
			self.thread.wait()
			self.worker.deleteLater()
			self.thread.deleteLater()
		else:
			#start sniff
			self.on = True
			self.pktCnt = 0
			self.startButton.setText('Stop')
			self.packageTable.setRowCount(0)
			self.deviceSelector.setEnabled(False)
			self.startSniff()
	
	def startSniff(self):
		print('Start Sniff')
		
		idx = self.deviceSelector.currentIndex()
		currentDevice = self.deviceList[idx][0]
		print(currentDevice)
		
		self.thread = QThread()
		self.worker = Worker(currentDevice)
		
		self.worker.moveToThread(self.thread)
		
		self.thread.started.connect(self.worker.run)
		self.worker.received.connect(self.receivePacket)
		
		self.thread.start()
		
if __name__ == '__main__':
	app = QApplication([])
	deviceList = WinPcapDevices.list_devices()
	mainWD = SnifferUI(deviceList)
	sys.exit(app.exec_())
