# a simple socks 5 server
# python 3
# currently no authentication is required

import socketserver
import threading
import socket

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
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((requested_address, requested_port))
		
if __name__ == '__main__':
