#python3

import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Util import Padding
from hybrid import load_keypair, load_publickey

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 0
		self.version_minor = 5
		self.msg_hdr_ver = b'\x01\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		self.hdr_rsv = b'\x00\x00'
		self.size_msg_mac = 12
		self.size_msg_etk = 256
		self.keypair_path = "../server/keypair.pem"
		self.publickey_path = "pubkey.pem"
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.hdr_sqn_snd = b'\x00\x00'
		self.hdr_sqn_rcv = b'\x00\x00'
		self.transfer_key = b'\x00' * 32

	
	def setTransferKey(self, transferKey):
		self.transfer_key = transferKey

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]
		return parsed_msg_hdr


	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')
		
		try:
			received_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
			current_sqn = int.from_bytes(self.hdr_sqn_rcv, byteorder='big')
			if received_sqn <= current_sqn:
				raise SiFT_MTP_Error('')
		except:
			raise SiFT_MTP_Error('Invalid SQN format in header')



		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')	

		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body received')

		size_enc_plaintext = len(msg_body) - self.size_msg_mac

		# handle login_req
		if parsed_msg_hdr['typ'] == self.type_login_req:
			size_enc_plaintext -= self.size_msg_etk
			# decrypt etk
			try: 
				etk = msg_body[-256:]
			except:
				raise SiFT_MTP_Error('Incomplete message received')
			try:
				keypair = load_keypair(self.keypair_path)
				RSAcipher = PKCS1_OAEP.new(keypair)
				self.transfer_key = RSAcipher.decrypt(etk)
				print("DECRYPTED TRANSFER: " + self.transfer_key.hex())
			except:
				raise SiFT_MTP_Error('Error decrypting temporary transfer key')

		# parse mac
		msg_enc_payload = msg_body[:size_enc_plaintext]
		msg_body_mac = msg_body[size_enc_plaintext:size_enc_plaintext+self.size_msg_mac]

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(msg_enc_payload)) + '): ')
			print(msg_enc_payload.hex())
			print('MAC (' + str(len(msg_body_mac)) + '): ')
			print(msg_body_mac.hex())
			print('TK (' + str(len(self.transfer_key)) + '): ')
			print(self.transfer_key.hex())
			print('------------------------------------------')
		# DEBUG 

		# verify MAC
		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
		AE = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
		# do I need this??
		AE.update(msg_hdr)
		try:
			payload = AE.decrypt_and_verify(msg_enc_payload, msg_body_mac)
		except Exception as e:
			raise SiFT_MTP_Error('Invalid message construction')
		
		self.hdr_sqn_rcv = parsed_msg_hdr['sqn']

		return parsed_msg_hdr['typ'], payload


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):

		# grab transfer key
		tk = self.transfer_key

		# build header
		header_rnd = Random.get_random_bytes(6)
		msg_size = self.size_msg_hdr + len(msg_payload) + self.size_msg_mac
		
		# additional for login_req
		if msg_type == self.type_login_req:
			tk = Random.get_random_bytes(32)
			self.transfer_key = tk
			msg_size += self.size_msg_etk
			
			# encrypt tk with RSA
			pubkey = load_publickey(self.publickey_path)
			RSAcipher = PKCS1_OAEP.new(pubkey)
			etk = RSAcipher.encrypt(tk)


		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')

		# bigger SQN
		biggerInt = int.from_bytes(self.hdr_sqn_snd, byteorder='big') + 1
		biggerSQN = biggerInt.to_bytes(self.size_msg_hdr_sqn, byteorder='big')
		# concatenate header
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + biggerSQN + header_rnd + self.hdr_rsv

		# encrypt payload and generate MAC
		nonce = biggerSQN + header_rnd
		AE = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
		AE.update(msg_hdr)
		encrypted_payload, authtag = AE.encrypt_and_digest(msg_payload)

		# build message
		msg_body = encrypted_payload + authtag
		# add etk for login_req
		if msg_type == self.type_login_req:
			msg_body += etk
		msg = msg_hdr + msg_body
		
		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(encrypted_payload)) + '): ')
			print(encrypted_payload.hex())
			print('MAC (' + str(len(authtag)) + '): ')
			print(authtag.hex())
			if msg_type == self.type_login_req:
				print('ETK (' + str(len(etk)) + '): ')
				print(etk.hex())
			print('TK (' + str(len(self.transfer_key)) + '): ')
			print(self.transfer_key.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(msg)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
		
		# store higher sqn_snd
		self.hdr_sqn_snd = biggerSQN