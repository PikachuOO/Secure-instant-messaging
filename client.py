
# Network Security PS4
# Ali Aminian, Tien Vo Huu
# Secure Instant Chat Application, Client side.

import random
import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac, serialization
import os, sys, getopt, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import time, json
from fcrypt import *

#shared keys available to user in the list. Each one is:(session_key, des_user, expiration_time)

shared_keys_database = []
auth_users = []

server_addr = ('127.0.0.1', 8000)

#remembering values
last_PUBKEY = ''
last_REQSTART = ''
last_STARTTALKAUTH = ''
last_CONTINUETALKAUTH = ''

#Helper functions
def retrieve_auth_user(username):
	
	for u in auth_users:
		if(u[0] == username):
			return u
	return None

def retrieve_session_key(username):

	for i in shared_keys_database:
		user = i[1]
		if(user[0] == username):
			return i[0]
	return None

def retrieve_user(username):
	for i in shared_keys_database:
		user = i[1]
		if(user[0] == username):
			return user
	return None
#Send a msg to server to socket s
def SendMassage(conn):
	while(1):
		msg = raw_input('')

		if(msg.startswith('HI')):

			global username
			username = msg[3:]
			data = {'type': 'HI', 'username' :msg[3:]}
			conn.sendto(json.dumps(data).encode(), server_addr)

		if(msg == 'CONVERSATION'):
			print('Whom you want to talk?\n')
			des_username = raw_input('')

			
			talkto(conn, des_username)

			time.sleep(1.3)

			des_user = retrieve_auth_user(des_username)

			if(des_user != None):
				print('Enter your message:')
				m = raw_input('')
				send_conversation(conn, des_user, m)
					


#Receive a msg from socket s 
def ListenForMassage(conn):
	while(1):
		data, addr = conn.recvfrom(8192)
		data = json.loads(data.decode())
		print(data['type'], data)
		print('\n')
		if(data['type'] == 'Error'):
			print(data['msg'])

		elif(data['type'] == 'PROOF'):
			DH_key_establishment_server(conn, 'des_username_does_not_matter', 2, data)

		elif(data['type'] == 'PUBKEY'):
			des_addr = data['des_addr']
			inner_data, des_addr = DH_key_establishment_server(conn, des_addr[1], 4, data)
			DH_key_establishment_user(conn, des_addr, 1, inner_data)




		elif(data['type'] == 'DHSTARTREQ'):
			DH_key_establishment_recv_from_user(conn, addr, data)
		elif(data['type'] == 'DHCONTINUEREQ'):
			DH_key_establishment_user(conn, addr, 2, data)





		elif(data['type'] == 'STARTTALKAUTH'):
			username = data['initiator_username']
			recv_talk_to_user_authenticate(conn, (username, addr), 1, data)
		elif(data['type'] == 'CONTINUETALKAUTH'):
			username = data['receiver_username']
			send_talk_to_user_authenticate(conn, (username, addr), 2, data)
		elif(data['type'] == 'FINISHTALKAUTH'):
			username = data['initiator_username']
			recv_talk_to_user_authenticate(conn, (username, addr), 2, data)
		


		elif(data['type'] == 'CONVERSATION'):
			# check to see if sender is already authenticated or not
			find = False
			for u in auth_users:
				if(addr == u[1]):
					find = True

			if(find):
				recv_conversation(conn, data)
			else:
				print("I do not have established session key with you, or maybe it has expired!")



	

def recv_conversation(conn, data):
	# show message to the user
	session_key = retrieve_session_key(data['username'])

	enc_msg = data['message']
	enc_msg = base64.b64decode(enc_msg)

	msg = AESCTRDecrypt(enc_msg, session_key)

	print(data['username'] + ': ' + msg)


def send_conversation(conn, des_user, data):
	#send msg to des_user
	session_key = retrieve_session_key(des_user[0])



	enc_data = AESCTRDecrypt(data, session_key)
	enc_data = base64.b64encode(enc_data)

	msg = {
		'type': 'CONVERSATION',
		'username': username,
		'message': enc_data,

	}
	conn.sendto(json.dumps(msg).encode(), des_user[1])

	

def recv_talk_to_user_authenticate(conn, des_user, step, data):
	global last_CONTINUETALKAUTH
	if(step == 1):
		#recv msg 1, retrieve initiator, receiver, verify receiver, ENCNA
		initiator_username = data['initiator_username']
		receiver_username = data['receiver_username']
		ENCNA = data['ENCNA']
		#verify initiator and receiver
		if( des_user[0] != initiator_username):
			print("Initiator username does not match")
			return
		if( username != receiver_username):
			print("Receiver username is not me.")
			return
		#decrypt ENCNA and verify it
		session_key = retrieve_session_key(initiator_username)

		ENCNA = base64.b64decode(ENCNA)

		NA = AESCTRDecrypt(ENCNA, session_key)
		NA = base64.b64encode(NA)

		
		NB = os.urandom(16)
		
		ENC_NB = AESCTREncrypt(NB, session_key)
		ENC_NB = base64.b64encode(ENC_NB)

		NB = base64.b64encode(NB)

		#send msg 2 CONTINUETALKAUTH
		msg = {
			'type' : 'CONTINUETALKAUTH',
			'receiver_username' : username,
			'NA': NA,
			'ENC_NB': ENC_NB
		}


		last_CONTINUETALKAUTH = {
			'NB': NB,
			'session_key': session_key,
		}
		conn.sendto(json.dumps(msg).encode(), des_user[1])

	if(step == 2):
		#recv msg 3 FINISHTALKAUTH, verify NB with session key

		session_key = last_CONTINUETALKAUTH['session_key']

		if(data['NB'] != last_CONTINUETALKAUTH['NB']):
			print("Wrong encryption of my nonce NB in CONTINUETALKAUTH")

		#add username to authenticated users
		auth_users.append(des_user)

def send_talk_to_user_authenticate(conn, des_user, step, data = None):
	global last_STARTTALKAUTH
	if(step == 1):	
		#send msg 1 STARTTALKAUTH to username
		NA = os.urandom(16)

		session_key = retrieve_session_key(des_user[0])

		ENCNA = AESCTREncrypt(NA, session_key)
		ENCNA = base64.b64encode(ENCNA)

		NA = base64.b64encode(NA).decode()

		msg = {
			'type' : 'STARTTALKAUTH',
			'initiator_username' : username,
			'receiver_username': des_user[0],
			'ENCNA': ENCNA,
		}

		last_STARTTALKAUTH = {
			'NA': NA,
			'session_key': session_key,
		}
		conn.sendto(json.dumps(msg).encode(), des_user[1])

	if(step == 2):
		#recv msg 2 CONTINUETALKAUTH, verify NA with session key
		ENC_NB = data['ENC_NB']
		ENC_NB = base64.b64decode(ENC_NB)

		session_key = last_STARTTALKAUTH['session_key']

		NB = AESCTRDecrypt(ENC_NB, session_key)
		NB = base64.b64encode(NB)

		#verify NA
		if( data['NA'] != last_STARTTALKAUTH['NA']):
			print("Wrong encryption of my nonce NA in STARTTALKAUTH")


		#send msg 3 FINISHTALKAUTH
		msg = {
			'type' : 'FINISHTALKAUTH',
			'initiator_username' : username,
			'NB': NB,
		}			
		conn.sendto(json.dumps(msg).encode(), des_user[1])

		#add username to authenticated users
		auth_users.append(des_user)


def DH_key_establishment_recv_from_user(conn, des_addr, data):
	
	#recv DHSTARTREQ: 


	##########TTB###################
	TTB = data['TTB']
	STR_ENC_TTB = TTB['ENC'].encode()


	#verify signature TTB
	signature = base64.b64decode(TTB['signature'])
	if( VerifySign(STR_ENC_TTB, signature, public_key_server) ):
		print("Cannot verify TTB's signature from server")
		return


	#Decryption of TTB
	inner_TTB = Decrypt(base64.b64decode(STR_ENC_TTB), public_key_server, private_key)
	#convert str to dict
	inner_TTB = eval(inner_TTB)
	################################



	#retrieving values from TTB
	g = inner_TTB['g']
	p = inner_TTB['p']
	
	pubkey_initiator = inner_TTB['pubkey_initiator']
	NA = inner_TTB['NA']
	NB = inner_TTB['NB']
	initiator_username = inner_TTB['initiator_username']


	#verify NA and A
	if(NA != data['NA']):
		print("Nonce does not match to what is inside my TTB")
		return
	if(data['initiator_username'] != initiator_username):
		print("You are not the one I see in my TTB")
		return

	#verify signature
	m = data['NA'] + str(data['G_A_mod_P'])
	signature = base64.b64decode(data['signature'])
	pk, temp = LoadKeys(pubkey_initiator, None)
	if(VerifySign( m.encode(), signature, pk)):
		print("Signature from initiator can not be verified")
		return


	
	#send msg 2: DHCONTINUEREQ to initiator
	G_A_mod_P = data['G_A_mod_P']
	b = 15
	G_B_mod_P = pow(g, b, p)

	#sign
	m = NB + str(G_B_mod_P)
	signature = RSASign(m.encode(), private_key)
	signature = base64.b64encode(signature)

	msg = {
		'type' : 'DHCONTINUEREQ',
		'receiver_username' : username,
		'NB': NB,
		'G_B_mod_P': G_B_mod_P,
		'signature': signature
	}

	conn.sendto(json.dumps(msg).encode(), des_addr)

	#build shared_key and add it to the list shared_keys_database
	des_username = data['initiator_username']
	#auth_users.append((des_username, des_addr))
	session_key = Hash(str(pow(G_A_mod_P, b, p)))

	shared_keys_database.append((session_key, (des_username, des_addr), 1000))
	print(shared_keys_database)

def DH_key_establishment_user(conn, des_addr, step, data):
	global last_DHSTARTREQ_DH
	if(step == 1): 	
		#send msg1 DHSTARTREQ:
		
		#retrieve values from data(PUBKEY)
		g = data['g']
		p = data['p']
		a = 12
		
		G_A_mod_P = pow(g, a, p)

		m = data['NA'] + str(G_A_mod_P)
		signature = RSASign(m.encode(), private_key)
		signature = base64.b64encode(signature)

		msg = {
			'type' : 'DHSTARTREQ',
			'initiator_username' : username,

			'TTB': data['TTB'],
			'NA': data['NA'],
			'G_A_mod_P': G_A_mod_P,
			'signature': signature

		}

		last_DHSTARTREQ_DH = {
			'a': a,
			'p': p
		}
		conn.sendto(json.dumps(msg).encode(), des_addr)

	if(step == 2):
		#recv msg 2 DHCONTINUEREQ: verify NB, verify signature
		des_username = data['receiver_username']
		NB = data['NB']
		G_B_mod_P = data['G_B_mod_P']

		#verify NB
		if( NB != last_PUBKEY['NB']):
			print("Your nonce does not match with my PUBKEY data")
			return
		#verify signature
		m = NB + str(G_B_mod_P)
		signature = data['signature']
		signature = base64.b64decode(signature)
		pubkey_receiver = last_PUBKEY['pubkey_receiver']
		pk, temp = LoadKeys(pubkey_receiver, None)

		if( VerifySign(m.encode(), signature, pk) == False):
			print("Cannot verify your signature from DHCONTINUEREQ")
			return

		#build shared_key and add it to the list shared_keys_database
		#auth_users.append((des_username, des_addr))
		session_key = Hash(str(pow(G_B_mod_P, last_DHSTARTREQ_DH['a'], last_DHSTARTREQ_DH['p'])))
		shared_keys_database.append((session_key, (des_username, des_addr), 1000))
		print(shared_keys_database)

def DH_key_establishment_server(conn, des_username, step = 1, data = ''):
	if(step == 1):
		#send msg1 REQSTART
		msg = { 'type': 'REQSTART',
			'des_username': des_username,
			'initiator_username': username				
		}
		global last_REQSTART
		last_REQSTART = msg

		conn.sendto(json.dumps(msg).encode(), server_addr)

	if(step == 2):
		#recv msg2 PROOF
		hash_of_nonce = data['hash_of_nonce']
		sub_nonce = data['sub_nonce']

		#send msg3 PROOFBACK
		proof_back = find_proof_back(hash_of_nonce, sub_nonce)
		msg = proof_back + username + last_REQSTART['des_username']

		signature = RSASign(msg.encode(), private_key)
		

		msg = { 'type': 'PROOFBACK',
			'proof_back': proof_back,
			'initiator_username': username,
			'receiver_username': last_REQSTART['des_username'],
			'signature': base64.b64encode(signature),
		}
		conn.sendto(json.dumps(msg).encode(), server_addr)



	if(step == 4):
		#recv msg 4 PUBKEY
		des_addr = data['des_addr']
		des_addr = (des_addr[0], des_addr[1])

		
		STR_ENCA = data['ENCA'].encode()

		#verify signature
		signature = base64.b64decode(data['signature'])
		if( VerifySign(STR_ENCA, signature, public_key_server)):
			print("Wrong signature on message 4(PUBKEY)")
			return
		

		#Decryption
		DECA = Decrypt(base64.b64decode(STR_ENCA), public_key_server, private_key)
		#convert str to dict
		DECA = eval(DECA)


		global last_PUBKEY
		last_PUBKEY = DECA

		#return msg4 PUBKEY
		return (DECA, des_addr)




def talkto(conn, des_username, rept = 1): #User wants to talk to username
	if(retrieve_auth_user(des_username) is not None): #If user is already authenticated
		return

	#check to see if this user already has a shared key with username
	u = retrieve_user(des_username)
	if(u is not None):
		send_talk_to_user_authenticate(conn, u, 1)
		return

	if(u is None):
		#Key establishment using DH with server
		DH_key_establishment_server(conn, des_username)
		time.sleep(0.8)
		if(rept == 1):
			talkto(conn, des_username, 2)
		return

def find_proof_back(hash_of_nonce, sub_nonce):

	for i in range (10000, 100000): # find last 5 digits of nonce
		test = sub_nonce + str(i)
		new_hash = Hash(test)
		if(base64.b64encode(new_hash).decode() == hash_of_nonce):
			return test

def main():

	public_key_file = sys.argv[1]
	private_key_file = sys.argv[2]	

	public_key_file_server = sys.argv[3]

	global public_key
	global private_key
	public_key, private_key = LoadKeys(public_key_file, private_key_file)

	global public_key_server
	public_key_server, temp = LoadKeys(public_key_file_server, None)

	#create socket and connect to server
	try:
		conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	except socket.error as msg:
		conn = 'None'
	port = random.randint(1025,9999)
	ip = '127.0.0.1'
	try:	
		conn.bind((ip, port))
	except socket.error as msg:
		conn.close
		conn = 'None'
		
	print("Client is ready", conn.getsockname())


	#thread1: always available to send msg to server
	#thread2: always ready to receive an INCOMING msg from server
	thread1 = threading.Thread(target=SendMassage, args = (conn,))
	thread1.start()


	thread2 = threading.Thread(target=ListenForMassage, args = (conn,))
	thread2.start()

if __name__ == "__main__":
	main()






















