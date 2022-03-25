from winpcapy import WinPcapUtils
from winpcapy import WinPcapDevices
from winpcapy import WinPcap
import dpkt
from dpkt.compat import compat_ord
import socket

def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)
def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QMainWindow, 
	QComboBox, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, 
	QGridLayout)
from PyQt5.QtCore import QObject, QThread, pyqtSignal

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
		packageTable.setColumnCount(4)
		
		packageTable.setHorizontalHeaderLabels(['srcAddr', 'dstAddr', 'type', 'content'])
		packageTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
		packageTable.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
		packageTable.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
		packageTable.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
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
	def addPacket(self, src, dst, type, content):
		rowCnt = self.packageTable.rowCount()
		self.packageTable.insertRow(rowCnt)
	
		self.packageTable.setItem(rowCnt, 0, QTableWidgetItem(src))
		self.packageTable.setItem(rowCnt, 1, QTableWidgetItem(dst))
		self.packageTable.setItem(rowCnt, 2, QTableWidgetItem(type))
		self.packageTable.setItem(rowCnt, 3, QTableWidgetItem(content.hex()))
		
	def receivePacket(self, pkt_data):
		print(pkt_data)
		eth = dpkt.ethernet.Ethernet(pkt_data)
		srcMac = mac_addr(eth.src)
		dstMac = mac_addr(eth.dst)
		type = 'Ethernet'
		content = pkt_data
		self.addPacket(srcMac, dstMac, type, content)
		
		if isinstance(eth.data, dpkt.ip.IP):
			ip = eth.data
			srcIp = inet_to_str(ip.src)
			dstIp = inet_to_str(ip.dst)
			type = 'IP'
			content = ip.__bytes__()
			print(dir(ip))
			self.addPacket(srcIp, dstIp, type, content)
		else:
			type = eth.data.__class__.__name__
			content = eth.data
			self.addPacket(srcMac, dstMac, type, content)
			'''curp = ip
			while hasattr(curp, 'data'):
				print(curp.data.__class__.__name__)
				print(curp.data)
				curp = curp.data
				if curp.__class__.__name__ == 'bytes':
					try:
						request = dpkt.http.Request(curp)
						print('HTTP')
						print(request)
					except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
						pass
			'''
	def buttonClicked(self):
		if self.on:
			self.on = False
			self.startButton.setText('Start')
			self.deviceSelector.setEnabled(True)
			self.worker.stop()
			self.thread.quit()
			self.thread.wait()
			self.worker.deleteLater()
			self.thread.deleteLater()
		else:
			self.on = True
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
		#self.worker.finished.connect(self.thread.quit)
		#self.worker.finished.connect(self.worker.deleteLater)
		#self.thread.finished.connect(self.thread.deleteLater)
		#self.worker.progress.connect(self.reportProgress)
		# Step 6: Start the thread
		self.thread.start()

        # Final resets
		self.thread.finished.connect(
            lambda: self.startButton.setEnabled(True)
        )
		
if __name__ == '__main__':
	app = QApplication([])
	deviceList = WinPcapDevices.list_devices()
	mainWD = SnifferUI(deviceList)
	sys.exit(app.exec_())
	
	'''deviceList = WinPcapDevices.list_devices()
	
	deviceList = list(deviceList.items())
		
	for i in deviceList:
		print(i)
	
	idx = 4
	currentDevice = deviceList[idx][0]
	print(currentDevice)
	#currentDevice = '\\Dvice\\NPF_{E3CB3C30-7976-4A08-90AC-656FDF499F1C}'
	with WinPcap(currentDevice) as win_pcap:
		win_pcap.run(callback=packet_callback)'''