
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



# users is a list, each one is (username, addr)
users = []
server_addr = ('127.0.0.1', 8000)


proof_hash = ''
des_username = ''


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
		global proof_hash
		hash_of_nonce, sub_nonce = create_proof(32)

		global des_username
		des_username = data['des_username'].encode()

		msg = {
			'type': 'PROOF',
			'hash_of_nonce': base64.b64encode(hash_of_nonce),
			'sub_nonce': sub_nonce,
		}
		s.sendto(json.dumps(msg).encode(), addr)


	if(step == 3):
		#recv msg 3(proof) PROOFBACK
		#validate proofback regarding proof
		proof_back = data['proof_back'].encode()

		if(proof_back != proof_hash):
			print("You are probably trying to DOS attack me...")
			return


		#send msg 4 PUBKEY
		NA = os.urandom(16)
		NA = base64.b64encode(NA).decode()
		des_addr = None
		for i in users:
			if(des_username == i[0]):
				des_addr = i[1]
		if(des_addr is not None):
			#msg = str('PUBKEY' + NA + des_addr[0] + str(des_addr[1]))
			msg = {
				'type': 'PUBKEY',
				'NA': NA,
				'des_addr': des_addr
			}
		else:
			#msg = 'User not found!'
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
		print(data, addr)

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
