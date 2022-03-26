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

AppLayer_Protocols = [
	dpkt.http.Request,
	dpkt.http.Response,
	dpkt.dhcp.DHCP,
	dpkt.ssl.TLS,
	dpkt.dns.DNS,
	dpkt.icmp.ICMP
]

def getAppProtocol(buf):
	for protocol in AppLayer_Protocols:
		try:
			pkt = protocol(buf)
			if isinstance(pkt, dpkt.dhcp.DHCP):
				assert(pkt.op == 1 or pkt.op == 2)
			elif isinstance(pkt, dpkt.ssl.TLS):
				assert(pkt.version == 771)
			elif isinstance(pkt, dpkt.icmp.ICMP):
				assert(pkt.type == 0 \
						or pkt.type == 3\
						or pkt.type == 5\
						or pkt.type in range(8, 15))
			return pkt
		except Exception:
			pass
	
	return None

def printAttr(pkt):
	for attr in dir(pkt):
		if attr[:2] != '__':
			res = getattr(pkt, attr)
			if not callable(res):
				print(attr, res)
	input()

def parseAppLayer(buf):
	pkt = getAppProtocol(buf)
	
	if isinstance(pkt, dpkt.http.Request):
		print('HTTP Request: ', pkt.method, pkt.version, pkt.uri)
		dct = {'type': 'Request',
				'method': pkt.method,
				'version': pkt.version,
				'uri': pkt.uri
				}
		for hd, ctt in pkt.headers.items():
			print(hd, ctt)
			dct[hd] = ctt
		return ('', '', 'HTTP', 'Request ' + pkt.method + ' ' + pkt.uri, dct)
	elif isinstance(pkt, dpkt.http.Response):
		print('HTTP Response: ', pkt.status, pkt.reason, pkt.version)
		dct = {'type': 'Response',
				'status': str(pkt.status),
				'reason': pkt.reason,
				'version': pkt.version
				}
		for hd, ctt in pkt.headers.items():
			print(hd, ctt)
			dct[hd] = ctt
		print(pkt.body)
		return ('', '', 'HTTP', 'Response ' + str(pkt.status) + ' ' + pkt.reason, dct)
	elif isinstance(pkt, dpkt.dhcp.DHCP):
		dct = {}
		print('DHCP:', pkt.xid, end = ' ')
		pktType = 'Request' if pkt.op else 'Response'
		castType = 'BroadCast' if pkt.flags else 'UniCast'
		
		dct['xid'] = pkt.xid
		dct['type'] = pktType
		dct['cast'] = castType
		
		print(pktType, castType)
		if not pkt.op:
			print('Allocated IP:', inet_to_str(pkt.yiaddr))
			dct['Allocated IP'] = inet_to_str(pkt.yiaddr)
		
		packetTypes = {
			b'\x01': 'Discover',
			b'\x02': 'Offer',
			b'\x03': 'Request',
			b'\x04': 'Decline',
			b'\x05': 'ACK',
			b'\x06': 'NAK',
			b'\x07': 'Release',
			b'\x08': 'Inform',
		}
		for i, (code, ctt) in enumerate(pkt.opts):
			if code == 53:
				print('Packet Type:', packetTypes[ctt])
				dct['Packet Type'] = packetTypes[ctt]
			elif code == 12:
				print('Host Name:', ctt)
				dct['Host Name:'] = str(ctt)
			elif code == 50:
				print('Requeseted IP:', inet_to_str(ctt))
				dct['Requeseted IP'] = inet_to_str(ctt)
		return ('', '', 'DHCP', pktType + ' ' + castType, dct)
	elif isinstance(pkt, dpkt.ssl.TLS):
		tlsTypes = {
			20: 'Change Cipher Spec',
			21: 'Alert',
			22: 'Handshake',
			23: 'Application Data'
		}
		
		dct = {}
		
		if pkt.type in tlsTypes:
			tlsType = tlsTypes[pkt.type]
		else:
			tlsType = 'unknown'
		dct['type'] = tlsType
		dct['len'] = str(pkt.len)
		
		print('TLS:', pkt.len, tlsType)
		for i, rcd in enumerate(pkt.records):
			info = ''
			
			if rcd.type in tlsTypes:
				rcdType = tlsTypes[pkt.type]
			else:
				rcdType = 'unknown'
			info += ' type: ' + rcdType
			info += ' length: ' + str(rcd.length)
			
			print('TLSRecord: ', rcdType, rcd.length, end = ' ')
			if rcd.compressed:
				print('Compressed', end = '')
				info += ' Compressed '
			if rcd.encrypted:
				print('Encrypted', end = '')
				info += ' Encrypted '
			print()
			
			dct['TLSRecord' + str(i)] = info
		
		dct['data'] = buf
		return ('', '', 'TLS', tlsType, dct)
	elif isinstance(pkt, dpkt.dns.DNS):
		#printAttr(pkt)
		dnsType = 'Query' if not pkt.qr else 'Response'
		print('DNS: ', dnsType)
		dct = {'type': dnsType}
		
		if not pkt.qr:
			for i, qd in enumerate(pkt.qd):
				print(qd.name)
				dct['query' + str(i)] = qd.name
		else:
			for i, an in enumerate(pkt.an):
				#print(an)
				info = ''
				if hasattr(an, 'name'):
					print(an.name, end = ' ')
					info += ' name: ' + an.name
				if hasattr(an, 'cname'):
					print(an.cname, end = ' ')
					info += ' cname: ' + an.cname
				if hasattr(an, 'ip'):
					print(inet_to_str(an.ip), end = ' ')
					info += ' ip: ' + inet_to_str(an.ip)
				if hasattr(an, 'ip6'):
					print(inet_to_str(an.ip6), end = ' ')
					info += ' ip6: ' + inet_to_str(an.ip6)
				print()
				
				dct['response' + str(i)] = info
		dct['data'] = buf
		return ('', '', 'DNS', dnsType, dct)
	elif isinstance(pkt, dpkt.icmp.ICMP):
		icmpTypes = {
			0: 'Echo Reply',
			3: 'Unreachable',
			5: 'Redirect',
			8: 'Echo',
			11: 'Timeout',
			13: 'TimeStamp Request',
			14: 'TimeStamp Response'
		}
		if pkt.type in icmpTypes:
			icmpType = icmpTypes[pkt.type]
		else:
			icmpType = 'unknown'
		print('ICMP: ', icmpType , pkt.code)
		
		return ('', '', 'ICMP', 'type: ' + icmpType + ' ' + 'code: ' + str(pkt.code), 
				{'type': icmpType,
				'code': str(pkt.code),
				'data': buf.hex()
				})
	else:
		return None
def parseTransLayer(data):
	if isinstance(data, dpkt.tcp.TCP):
		print('TCP: ', data.sport, ' -> ', data.dport, data.seq, len(data.data))
		#print(data.seq, data.ack)
		FIN = bool(data.flags & (1 << 0))
		SYN = bool(data.flags & (1 << 1))
		RST = bool(data.flags & (1 << 2))
		ACK = bool(data.flags & (1 << 4))
		
		info = ''
		if SYN and not ACK:
			print('Three-way Handshake: Connect 1: SYN',  data.seq)
			info += 'Three-way Handshake: Connect 1: SYN ' + 'seq=' + str(data.seq) + ' '
		elif SYN and ACK:
			print('Three-way Handshake: Connect 2: SYN ', data.seq, 'ACK', data.ack)
			info += 'Three-way Handshake: Connect 2: SYN ACK ' + 'seq=' + str(data.seq) + ' ack=' + str(data.ack) + ' '
		elif ACK:
			print('ACK', data.ack)
			info += 'ACK ' + 'ack=' + str(data.ack) + ' '
		else:
			info += 'seq=' + str(data.seq) + ' ack=' + str(data.ack) + ' '
		if FIN:
			print('disconnect', data.seq)
			info += 'disconnect, '
		if len(data.data):
			print('Data Transfer:')
			info += 'Data Transfer'
			AppLayer = parseAppLayer(data.data)
		else:
			AppLayer = None
		
		TransLayer = (str(data.dport), str(data.sport), 'TCP', info,
					{'sport': data.sport,
					'dport': data.dport,
					'len': str(len(data.data)),
					'seqno': str(data.seq),
					'ackno': str(data.ack),
					'SYN': str(SYN),
					'ACK': str(ACK),
					'FIN': str(FIN),
					'data': data.__bytes__().hex()
					})
		return TransLayer, AppLayer
		
	elif isinstance(data, dpkt.udp.UDP):
		print('UDP: ', data.sport, ' -> ', data.dport)
		print(data.ulen)
		if data.ulen:
			AppLayer = parseAppLayer(data.data)
		else:
			AppLayer = None
		TransLayer = (str(data.dport), str(data.sport), 'UDP', '',
					{'sport': data.sport,
					'dport': data.dport,
					'len': str(data.ulen),
					'data': data.__bytes__().hex()
					})
		return TransLayer, AppLayer
	elif isinstance(data, dpkt.icmp6.ICMP6):
		icmpv6Types = {
			1: 'Destination unreachable',
			2: 'Packet too big',
			3: 'Time exceeded',
			4: 'Parameter problem',
			128: 'Echo Request',
			129: 'Echo Reply',
			133: 'Router Solicitation',
			134: 'Router Advertisement',
			135: 'Neighbor Solicitation',
			136: 'Neighbor Advertisement',
			143: 'Multicast Listener Discovery'
		}
		print('ICMPv6:', icmpv6Types[data.type], data.code)
		TransLayer = ('', '', 'ICMPv6', icmpv6Types[data.type] + ' ' + str(data.code),
					{'type': icmpv6Types[data.type],
					'code': str(data.code),
					'data': data.__bytes__().hex()
					})
		return TransLayer, None
	elif isinstance(data, dpkt.igmp.IGMP):
		igmpTypes = {
			17: 'Membership Query',
			34: 'Membership Report'
		}
		if data.type in igmpTypes:
			igmpType = igmpTypes[data.type]
		else:
			igmpType = ''
		print('IGMP: ', igmpType, inet_to_str(data.group))
		TransLayer = ('', '', 'IGMP', igmpType+ ' ' + inet_to_str(data.group),
					{'type': igmpType,
					'group': inet_to_str(data.group),
					'data': data.__bytes__().hex()
					})
		return TransLayer, None
	else:
		print(data.__class__.__name__)
		return None, None
def parseNetLayer(data):
	if isinstance(data, dpkt.ip.IP):
		print('IP: ', inet_to_str(data.src), ' -> ', inet_to_str(data.dst), data.len)
		TransLayer, AppLayer = parseTransLayer(data.data)
		NetLayer = (inet_to_str(data.src), inet_to_str(data.dst), 'IP', '', 
				{'src': inet_to_str(data.src),
				'dst': inet_to_str(data.dst),
				'len': str(data.len),
				'data': data.__bytes__().hex()
				})
		return NetLayer, TransLayer, AppLayer
	elif isinstance(data, dpkt.ip6.IP6):
		print('IPv6: ', inet_to_str(data.src), ' -> ', inet_to_str(data.dst), data.plen)
		TransLayer, AppLayer = parseTransLayer(data.data)
		NetLayer = (inet_to_str(data.src), inet_to_str(data.dst), 'IPv6', '', 
				{'src': inet_to_str(data.src),
				'dst': inet_to_str(data.dst),
				'len': str(data.plen),
				'data': data.__bytes__().hex()
				})
		return NetLayer, TransLayer, AppLayer
	elif isinstance(data, dpkt.arp.ARP):
		print('ARP: ')
		if data.op == 1:
			arpType = 'Request'
		elif data.op == 2:
			arpType = 'Response'
		else:
			arpType = ''
		print(arpType)
		print('Sender Mac', mac_addr(data.sha))
		print('Sender Ip', inet_to_str(data.spa))
		print('Target Mac', mac_addr(data.tha))
		print('Target Ip', inet_to_str(data.tpa))
		#printAttr(data)
		NetLayer = (mac_addr(data.sha), mac_addr(data.tha), 'ARP', arpType, 
				{'type': arpType, 
				'Sender Mac': mac_addr(data.sha),
				'Sender Ip': inet_to_str(data.spa),
				'Target Mac': mac_addr(data.tha),
				'Target Ip': inet_to_str(data.tpa),
				'data': data.__bytes__().hex()
				})
		return NetLayer, None, None
	else:
		print(data.__class__.__name__)
		return None, None, None
cnt = 1
def parsePkt(buf):
	global cnt
	print('#' * 50)
	print(cnt)
	
	cnt += 1
	eth = dpkt.ethernet.Ethernet(buf)
	print('Ethernet: ', mac_addr(eth.src), ' -> ', mac_addr(eth.dst))
	
	LinkLayer = (mac_addr(eth.src), mac_addr(eth.dst), 'Ethernet', '', {'data': buf.hex()})
	
	NetLayer, TransLayer, AppLayer = parseNetLayer(eth.data)
	
	return LinkLayer, NetLayer, TransLayer, AppLayer

if __name__ == '__main__':
	pcap = dpkt.pcap.Reader(open('c.pcap', 'rb'))
	for t, buf in pcap:
		parsePkt(buf)
