# a simple socks 5 server
# python 3
# currently no authentication is required

import socketserver
import threading
import socket
import ipaddress
import selectors

udp_bind_port = 10000
udp_associate_support = False

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	pass

def print_auth_method(method):
	if method == 0x00:
		print('no authentication required')
	elif method == 0x01:
		print('gssapi')
	elif method == 0x02:
		print('username password')
	elif 0x03 <= method and method <= 0x7f:
		print('IANA assigned')
	elif 0x80 <= method and method <= 0xfe:
		print('reserved for private methods')
	else:
		print ('no acceptable methods')

def parse_method_selection_msg(msg):
	version = msg[0]
	number_of_methods = msg[1]
	print('version = ', version)
	print('number of authentication methods = ', number_of_methods)

	i = 0
	while i < number_of_methods:
		print_auth_method(msg[i + 2])
		i = i + 1

def forward_data(request, sock):
	request.setblocking(False)
	sock.setblocking(False)
	sel = selectors.DefaultSelector()
	sel.register(request, selectors.EVENT_READ)
	sel.register(sock, selectors.EVENT_READ)
	while True:
		events = sel.select()
		for key, mask in events:
			if key.fileobj == sock:
				data = sock.recv(2048)
				request.sendall(data)
			else:
				data = request.recv(2048)
				sock.sendall(data)

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
	def handle(self):
		# receive version and authentication methods
		data = self.request.recv(1024)
		parse_method_selection_msg(data)
		# currently only support no authentication, send selected authentication method
		self.request.sendall(b'\x05\x00')

		# receive request details
		data = self.request.recv(1024)
		version_number = data[0]
		cmd = data[1]
		address_type = data[3]
		requested_address = b''
		requested_port = 0

		if cmd == 0x01:
			if address_type == 0x01:
				# ipv4 address, the next 4 bytes are address
				requested_address = data[4:8]
				# the next 2 bytes are port number in big endian
				requested_port = int.from_bytes(data[8:10], byteorder = 'big')
			elif address_type == 0x03:
				# domain name, the first byte contains the domain name length
				address_len = data[4]
				requested_address = data[5: 5 + address_len]
				# the next 2 bytes are port number in big endian
				requested_port = int.from_bytes(data[5 + address_len: 5 + address_len + 2], byteorder = 'big')
			elif address_type == 0x04:
				# ipv6 address, the next 16 bytes are address
				requested_address = data[4: 20]
				requested_port = int.from_bytes(data[20:22], byteorder = 'big')
			else:
				print('error: unexpected address type')

			# try to establish a connection with the requested address and port, and send reply to client
			# currently does not support ipv6
			if address_type == 0x01:
				requested_addr = ipaddress.IPv4Address(requested_address)
				print('trying to connect to: ', requested_addr.exploded)
				connected = True
				try:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.connect((requested_addr.exploded, requested_port))
				except socket.error as e:
					connected = False
					print('socket error: ', str(e))
				except socket.gaierror as e:
					connected = False
					print('address related error: ', str(e))

				if connected:
					# send succeeded reply
					succeeded_reply = b''
					succeeded_reply = succeeded_reply + b'\x05' # version number
					succeeded_reply = succeeded_reply + b'\x00' # succeeded
					succeeded_reply = succeeded_reply + b'\x00' # reserved
					succeeded_reply = succeeded_reply + b'\x01' # address type, ipv4 address
					bind_address, bind_port = sock.getsockname()
					succeeded_reply = succeeded_reply + ipaddress.IPv4Address(bind_address).packed
					succeeded_reply = succeeded_reply + bind_port.to_bytes(2, byteorder = 'big')
					self.request.sendall(succeeded_reply)
					# forward data
					forward_data(self.request, sock)
				else:
					# send failed reply
					failed_reply = b''
					failed_reply = failed_reply + b'\x05' # version number
					failed_reply = failed_reply + b'\x01' # general SOCKS server failure
					failed_reply = failed_reply + b'\x00' # reserved
					failed_reply = failed_reply + b'\x01' + b'\x00' * 6
					self.request.sendall(failed_reply)
					self.request.close()
			elif address_type == 0x04:
				# ipv6 address, currently does not support, send failed reply
				failed_reply = b''
				failed_reply = failed_reply + b'\x05' # version number
				failed_reply = failed_reply + b'\x08' # address type not supported
				failed_reply = failed_reply + b'\x00' # reserved
				failed_reply = failed_reply + b'\x01' + b'\x00' * 6
				self.request.sendall(failed_reply)
				self.request.close()
			else:
				# domain name address
				print('trying to connect to host:', requested_address)
				connected = True
				try:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.connect((requested_address, requested_port))
				except socket.error as e:
					connected = False
					print('socket error: ', str(e))
				except socket.gaierror as e:
					connected = False
					print('address related error: ', str(e))

				if connected:
					# send succeed reply
					succeeded_reply = b''
					succeeded_reply = succeeded_reply + b'\x05' # version number
					succeeded_reply = succeeded_reply + b'\x00' # succeeded
					succeeded_reply = succeeded_reply + b'\x00' # reserved
					succeeded_reply = succeeded_reply + b'\x01' # address type, ipv4 address
					bind_address, bind_port = sock.getsockname()
					succeeded_reply = succeeded_reply + ipaddress.IPv4Address(bind_address).packed
					succeeded_reply = succeeded_reply + bind_port.to_bytes(2, byteorder = 'big')
					self.request.sendall(succeeded_reply)
					# forward data
					forward_data(self.request, sock)
				else:
					# send failed reply
					failed_reply = b''
					failed_reply = failed_reply + b'\x05' # version number
					failed_reply = failed_reply + b'\x01' # general SOCKS server failure
					failed_reply = failed_reply + b'\x00' # reserved
					failed_reply = failed_reply + b'\x01' + b'\x00' * 6
					self.request.sendall(failed_reply)
					self.request.close()
		elif cmd == 0x02:
			# currently does not support bind, send failed reply to client
			# to support bind command, the proxy server needs to first create a server listening socket,
			# send the first reply to the client, then send the second reply when a connection is established

			failed_reply = b''
			failed_reply = failed_reply + b'\x05' # version number
			failed_reply = failed_reply + b'\x07' # command not supported
			failed_reply = failed_reply + b'\x00' # reserved
			failed_reply = failed_reply + b'\x01' + b'\x00' * 6
			self.request.sendall(failed_reply)
			self.request.close()
		else:
			# udp associate
			if udp_associate_support:
				if address_type == 0x04:
					# currently does not support ipv6, send failed reply
					failed_reply = b''
					failed_reply = failed_reply + b'\x05' # version number
					failed_reply = failed_reply + b'\x08' # address type not supported
					failed_reply = failed_reply + b'\x00' # reserved
					failed_reply = failed_reply + b'\x01' + b'\x00' * 6
					self.request.sendall(failed_reply)
					self.request.close()
				else:
					# create a udp socket for the client
					udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					udp_sock.bind(('localhost', udp_bind_port))
					udp_bind_port = udp_bind_port + 1

					succeeded_reply = b''
					succeeded_reply = succeeded_reply + b'\x05' # version number
					succeeded_reply = succeeded_reply + b'\x00' # succeeded
					succeeded_reply = succeeded_reply + b'\x00' # reserved
					succeeded_reply = succeeded_reply + b'\x01' # address type, ipv4 address
					bind_address, bind_port = udp_sock.getsockname()
					succeeded_reply = succeeded_reply + ipaddress.IPv4Address(bind_address).packed
					succeeded_reply = succeeded_reply +  bind_port.to_bytes(2, byteorder = 'big')
					self.request.sendall(succeeded_reply)
					# forward data
					data, client_addr = udp_sock.recvfrom(2048)
					# blablabla, to do
			else:
				failed_reply = b''
				failed_reply = failed_reply + b'\x05' # version number
				failed_reply = failed_reply + b'\x07' # command not supported
				failed_reply = failed_reply + b'\x00' # reserved
				failed_reply = failed_reply + b'\x01' + b'\x00' * 6
				self.request.sendall(failed_reply)
				self.request.close()

if __name__ == '__main__':
	server = ThreadedTCPServer(('localhost', 10000), ThreadedTCPRequestHandler)
	server_thread = threading.Thread(target = server.serve_forever)
	server_thread.daemon = True
	server_thread.start()
	while True:
		pass
