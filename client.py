
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
username = ''
server_addr = ('127.0.0.1', 8000)

#remembering values
last_PUBKEY = ''
last_DHSTARTREQ = ''
last_REQSTART = ''
last_STARTTALKAUTH = ''
last_CONTINUETALKAUTH = ''

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
			des_user = None

			talkto(conn, des_username)
			find = False
			time.sleep(1.5)
			for u in auth_users:
				if(u[0] == des_username):
					des_user = u

			if(des_user != None):
				print('Enter your message:')
				m = raw_input('')
				send_conversation(conn, des_user, m)
					


#Receive a msg from socket s 
def ListenForMassage(conn):
	while(1):
		data, addr = conn.recvfrom(2048)

		data = json.loads(data.decode())
		print(data['type'], data)


		if(data['type'] == 'PROOF'):
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
				print("I do not trust you, maybe you should first establish a session key!")



	



def retrieve_session_key(username):

	for i in shared_keys_database:
		user = i[1]
		if(user[0] == username):
			return i[0]
	return None

def user_session_key(username):#if username has a session key, return the user
	for s, u, t in shared_keys_database:
		if(u[0] == username):
			return u
	return None

def recv_conversation(conn, data):
	# show message to the user
	print(data['username'] + ': ' + data['message'])


def send_conversation(conn, des_user, data):
	#send msg to des_user
	msg = {
		'type': 'CONVERSATION',
		'username': username,
		'message': data

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
		#decrypt ENCA and verify it
		session_key = retrieve_session_key(initiator_username)
		NA = ENCNA #symmetricdec(ENCNA, session_key)
		
		NB = os.urandom(16)
		NB = base64.b64encode(NB).decode()

		NA_NB = {
			'NA': NA,
			'NB': NB,
		}
		ENC_NA_NB = NA_NB # symmetricenc(NA_NB, session_key)

		#send msg 2 CONTINUETALKAUTH

		msg = {
			'type' : 'CONTINUETALKAUTH',
			'receiver_username' : username,
			'ENC_NA_NB': ENC_NA_NB,
		}


		last_CONTINUETALKAUTH = {
			'NB': NB,
			'session_key': session_key,
		}
		conn.sendto(json.dumps(msg).encode(), des_user[1])

	if(step == 2):
		#recv msg 3 FINISHTALKAUTH, verify NB with session key

		session_key = last_CONTINUETALKAUTH['session_key']
		ENCNB = data['ENCNB']
		NB = ENCNB # symmetricdec(ENCNB, session_key)
		if(NB != last_CONTINUETALKAUTH['NB']):
			print("Wrong encryption of my nonce NB in CONTINUETALKAUTH")

		#add username to authenticated users
		auth_users.append(des_user)

def send_talk_to_user_authenticate(conn, des_user, step, data):
	global last_STARTTALKAUTH
	if(step == 1):	
		#send msg 1 STARTTALKAUTH to username
		NA = os.urandom(16)
		NA = base64.b64encode(NA).decode()

		session_key = retrieve_session_key(des_user[0])

		ENCNA = NA #symmetricenc(NA, session_key)
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
		ENC_NA_NB = data['ENC_NA_NB']


		session_key = last_STARTTALKAUTH['session_key']
		NA_NB = ENC_NA_NB # symmetricdec(ENC_NA_NB, session_key)
		
		#verify NA
		if( NA_NB['NA'] != last_STARTTALKAUTH['NA']):
			print("Wrong encryption of my nonce NA in STARTTALKAUTH")
		NB = NA_NB['NB']
		ENCNB = NB # symmetricenc(NB, session_key)

		#send msg 3 FINISHTALKAUTH
		msg = {
			'type' : 'FINISHTALKAUTH',
			'initiator_username' : username,
			'ENCNB': ENCNB,
		}			
		conn.sendto(json.dumps(msg).encode(), des_user[1])

		#add username to authenticated users
		auth_users.append(des_user)


def DH_key_establishment_recv_from_user(conn, des_addr, data):
	
	#recv DHSTARTREQ: 

	#verifying and extracting TTB
	TTB = data['TTB']
	TTB_ENC = TTB['ENCB']
	TTB_signature = TTB['signature']
	inner_TTB = TTB_ENC #dec(TTB_ENC, my_private_key)
	if(TTB_signature != TTB_signature):
		print("Cannot verify TTB's signature from server")
		return
	g = inner_TTB['g']
	p = inner_TTB['p']
	pubkey_initiator = inner_TTB['pubkey_initiator']
	NA = inner_TTB['NA']
	NB = inner_TTB['NB']
	initiator_username = inner_TTB['initiator_username']

	#verify NA
	if(NA != data['NA']):
		print("Nonce does not match to what is inside my TTB")
		return
	#verify signature
	if(data['signature'] != data['signature']):#!= verify( data['NA'] + data['G_A_mod_P'], pubkey_initiator)
		print("Signature from initiator can not be verified")
		return


	#send msg 2: DHCONTINUEREQ to initiator
	signature = NB + 'G_B_mod_P'
	msg = {
		'type' : 'DHCONTINUEREQ',
		'receiver_username' : username,

		'NB': NB,
		'G_B_mod_P': 'G_B_mod_P',
		'signature': signature
	}

	conn.sendto(json.dumps(msg).encode(), des_addr)

	#build shared_key and add it to the list shared_keys_database
	des_username = data['initiator_username']
	auth_users.append((des_username, des_addr))
	session_key = 'session_key'#G^ab mod p
	shared_keys_database.append((session_key, (des_username, des_addr), 1000))


def DH_key_establishment_user(conn, des_addr, step, data):
	if(step == 1): 	
		#send msg1 DHSTARTREQ:
		
		#retrieve values from data(PUBKEY)
		g = data['g']
		p = data['p']
		signature = 'signature'#sign(data['NA'] + 'G_A_mod_P')
		msg = {
			'type' : 'DHSTARTREQ',
			'initiator_username' : username,

			'TTB': data['TTB'],
			'NA': data['NA'],
			'G_A_mod_P': 'G_A_mod_P',
			'signature': signature

		}
		global last_DHSTARTREQ
		last_DHSTARTREQ = msg
		conn.sendto(json.dumps(msg).encode(), des_addr)

	if(step == 2):
		#recv msg 2 DHCONTINUEREQ: verify NB, verify signature
		des_username = data['receiver_username']
		NB = data['NB']

		#verify NB
		if( NB != last_PUBKEY['NB']):
			print("Your nonce does not match with my PUBKEY data")
			return
		#verify signature
		if( data['signature'] != data['signature']):#!=data['NB'] + data['G_B_mod_P']		
			print("Cannot verify your signature from DHCONTINUEREQ")
			return

		#build shared_key and add it to the list shared_keys_database
		auth_users.append((des_username, des_addr))
		session_key = 'session_key'#G^ab mod p
		shared_keys_database.append((session_key, (des_username, des_addr), 1000))


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
		print("****", type(signature), signature)

		print("$$$", type(base64.b64encode(signature)), base64.b64encode(signature))
		print("#####", type(base64.b64encode(signature).decode()), base64.b64encode(signature).decode())

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

		ENCA = data['ENCA']
		signature = data['signature']
		#verify signature

		if( 0 ): #verify(enca, signature, pubkey_server)
			print("Wrong signature on message 4(PUBKEY)")
			return
		
		DECA = ENCA #denc(ENCA, my_private_key)

		global last_PUBKEY
		last_PUBKEY = DECA

		#return msg4 PUBKEY
		return (DECA, des_addr)




def talkto(conn, username): #User wants to talk to username
	for u in auth_users:
		if(u[0] == username):
			return

	#check to see if this user already has a shared key with username
	u = user_session_key(username)
	if(u is not None):
		send_talk_to_user_authenticate(conn, u, 1, s)

	if(u is None):
		#Key establishment using DH with server
		DH_key_establishment_server(conn, username)
		time.sleep(2)
		talkto(conn, username)

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






















