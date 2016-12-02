
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

#list of (username, public_key)
pub_keys = []

#Remembering values
proof_hash = ''
last_REQSTART = ''


def retrieve_pubkey(username):

	for i in pub_keys:
		if(i[0] == username):
  			public_key, temp = LoadKeys(i[1], None)
			return public_key
	return None

def retrieve_addr(username):

	for i in users:
		if(username == i[0]):
			return i[1]
	return None

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
		des_username = data['des_username']
		if(retrieve_addr(des_username) is None):
			msg = {
				'type': 'Error',
				'msg': 'User does not exist'
			}
		else:
			hash_of_nonce, sub_nonce = create_proof(32)

			global last_REQSTART
			last_REQSTART = data

			msg = {
				'type': 'PROOF',
				'hash_of_nonce': base64.b64encode(hash_of_nonce),
				'sub_nonce': sub_nonce,
			}

		s.sendto(json.dumps(msg).encode(), addr)


	if(step == 3):
		#recv msg3 PROOFBACK:

		#validate proofback regarding proof
		proof_back = data['proof_back'].encode()

		if(proof_back != proof_hash):
			print("Proofback not valid! You are probably trying to DOS attack me...")
			return

		#validate initiator based on previous msg
		initiator_username = data['initiator_username']

		if(initiator_username != last_REQSTART['initiator_username']):
			print("You are not" + initiator_username)
			return

		
		#verify signature
		pk = retrieve_pubkey(initiator_username)
		m = data['proof_back'] + data['initiator_username'] + data['receiver_username']
		
		
		sig = base64.b64decode(data['signature'])

		if( VerifySign(m.encode(), sig, pk) == False):
			print("Wrong signature!")
			return	


		#find address of stored des_username
		des_addr = retrieve_addr(last_REQSTART['des_username'].encode())

		if(des_addr is not None):
			#send msg 4 PUBKEY
			receiver_username = data['receiver_username']

			NA = os.urandom(16)
			NA = base64.b64encode(NA).decode()
			NB = os.urandom(16)
			NB = base64.b64encode(NB).decode()

			
			# Finding public keys of initiator and receiver
			pubkey_initiator = None
			pubkey_receiver = None
			for i in pub_keys:
				username = i[0]
				if(username == initiator_username):
					pubkey_initiator = i[1]
				if(username == receiver_username):
					pubkey_receiver = i[1]

			if(pubkey_initiator is None):
				print("Public key of " + initiator_username + " not found in the server")
				return 
			if(pubkey_receiver is None):
				print("Public key of " + receiver_username + " not found in the server")
				return 


			#create TTB#
			inner_TTB = {
				'NA': NA,
				'NB': NB,
				
				'initiator_username': initiator_username,
				'pubkey_initiator': pubkey_initiator,
				'g': gen,
				'p': prime,
				
			}
			#Encryption of TTB
			pk, temp = LoadKeys(pubkey_receiver, None)

			ENC_inner_TTB = Encrypt(str(inner_TTB), pk, private_key)
			ENC_inner_TTB = base64.b64encode(ENC_inner_TTB)

			#Signing
			signature = RSASign(ENC_inner_TTB, private_key)
			signature = base64.b64encode(signature)

			TTB = {
				'ENC': ENC_inner_TTB,
				'signature': signature
	
			}
			############
			inner_msg = {

				'NA': NA,
				'NB': NB,

				'TTB': TTB,

				'pubkey_receiver': pubkey_receiver,

				'g': gen,
				'p': prime,

			}


			#Encryption
			pk, temp = LoadKeys(pubkey_initiator, None)

			ENC_inner_msg = Encrypt(str(inner_msg), pk, private_key)
			ENC_inner_msg = base64.b64encode(ENC_inner_msg)


			#Signing
			signature = RSASign(ENC_inner_msg, private_key)
			signature = base64.b64encode(signature)

		
			#Create JSON
			msg = {
				'type': 'PUBKEY',

				'ENCA': ENC_inner_msg,

				'des_addr': des_addr,
				
				'signature': signature,
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
	global public_key
	global private_key
  	public_key, private_key = LoadKeys(public_key_file, private_key_file)
	#Load users' public_key
	number_of_public_keys = int(sys.argv[3])
	for i in range(0, number_of_public_keys):
		username = sys.argv[i*2+4]
		pk_file = sys.argv[i*2+5]
		pk, temp = LoadKeys(pk_file)
		pub_keys.append( (username, pk_file) )


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


	

	global gen
	gen = 2
	global prime
	prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
	

	while(1):
		#recive msg
		data, addr = s.recvfrom(8192)
		data = json.loads(data.decode())
		print(data['type'], data, addr)
		print('\n')
		#msg type
		if(data['type'] == 'HI'):
			user = (data['username'].encode(), addr)
			pubkey_find = False
			pubkey = retrieve_pubkey(user[0])
			if(pubkey_find is None):
				print('Server does not have public_key of ' + user[0])
			else:
				users.append(user)

		elif(data['type'] == 'REQSTART'):
			authenticate_talkto(s, addr, 2, data)

		elif(data['type'] == 'PROOFBACK'):
			authenticate_talkto(s, addr, 3, data)


			

	conn.close()


if __name__ == "__main__":
	main()
