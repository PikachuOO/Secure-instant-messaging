
# Network Security PS4
# Ali Aminian, Tien Vo Huu
# Secure Instant Chat Application, Server side.

import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac, serialization
import os, sys, getopt, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from fcrypt import *
import random, json



# users: list of (username, addr)
users = []
server_addr = ('127.0.0.1', 8000)

#list of (users, public_key)
pub_keys = []

#Remembering values
proof_hash = ''
last_REQSTART = ''


def create_proof(length):
	nonce = ''
	for i in range(0, length):
		x = random.randint(1,9)
		nonce = nonce + str(x)
	global proof_hash
	proof_hash = nonce
	return Hash(nonce), nonce[:length-5] #-5 is the number of digits that we want endpoint to find out.

def authenticate_talkto(s, addr, step, data):
	if(step == 2):
		#recv REQSTART
		#send msg 2(hash) PROOF
		hash_of_nonce, sub_nonce = create_proof(32)

		global last_REQSTART
		#des_username = data['des_username'].encode()
		last_REQSTART = data

		msg = {
			'type': 'PROOF',
			'hash_of_nonce': base64.b64encode(hash_of_nonce),
			'sub_nonce': sub_nonce,
		}
		s.sendto(json.dumps(msg).encode(), addr)


	if(step == 3):
		#recv msg 3(proof) PROOFBACK, verify initiator, verify signature

		#validate proofback regarding proof
		proof_back = data['proof_back'].encode()

		if(proof_back != proof_hash):
			print("Proofback not valid! You are probably trying to DOS attack me...")
			return

		#validate sender based on previous msg
		initiator_username = data['initiator_username']

		if(initiator_username != initiator_username):
			print("You are not" + username)
			return
		

		#find address of stored des_username
		des_addr = None
		for i in users:
			if(last_REQSTART['des_username'].encode() == i[0]):
				des_addr = i[1]


		if(des_addr is not None):
			#send msg 4 PUBKEY
			receiver_username = data['receiver_username']

			NA = os.urandom(16)
			NA = base64.b64encode(NA).decode()
			NB = os.urandom(16)
			NB = base64.b64encode(NB).decode()

			g = 'g'
			p = 'p'
			#create TTB#
			inner_TTB = {
				'NA': NA,
				'NB': NB,
				
				'initiator': initiator_username,
				'pubkey_initiator': 'pubkey_initiator',
				'g': g,
				'p': p,
				
			}
			ENC_inner_TTB = inner_TTB
			TTB = {
				'ENC': ENC_inner_TTB,
				'signature': 'signature'
	
			}
			############
			inner_msg = {

				'NA': NA,
				'NB': NB,

				'TTB': TTB,

				'PUBKEY': 'PUBKEY_receiver',

				'g': g,
				'p': p,

			}
			ENC_inner_msg = inner_msg
			msg = {
				'type': 'PUBKEY',

				'ENCA': ENC_inner_msg,

				'des_addr': des_addr,
				
				'signature': 'signature',
			}
		else:
			msg = {
				'type': 'Error',
				'error': 'User not found'
			}

		s.sendto(json.dumps(msg).encode(), addr)

def main():

  	public_key_file = sys.argv[1]
  	private_key_file = sys.argv[2]	

	
  	#Load keys
  	public_key, private_key = LoadKeys(public_key_file, private_key_file)


	#create socket and bind ip,port to the socket with exception handling
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	except socket.error as msg:
		s = 'None'

	try:	
		s.bind(server_addr)
	except socket.error as msg:
		s.close
		s = 'None'
		

	#exception handling	
	if s is None:
		print('Could not initialize server, try again.')
		sys.exit(1)

	print('Server is Listening on Port', server_addr[1])


	


	

	while(1):
		#recive msg
		data, addr = s.recvfrom(2048)
		data = json.loads(data.decode())
		print(data['type'], data, addr)

		#msg type
		if(data['type'] == 'HI'):
			#if(user_not_found(data[2:]):
			users.append((data['username'].encode(), addr))

		elif(data['type'] == 'REQSTART'):
			authenticate_talkto(s, addr, 2, data)

		elif(data['type'] == 'PROOFBACK'):
			authenticate_talkto(s, addr, 3, data)


			

	conn.close()


if __name__ == "__main__":
	main()
