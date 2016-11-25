
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

#shared keys available to user in the list. Each one is:(session_key, (des_username, des_addr), expiration_time)

shared_keys_database = []
auth_users = []
username = ''
server_addr = ('127.0.0.1', 8000)



#Send a msg to server to socket s
def SendMassage(conn):
	while(1):
		msg = input('')

		if(msg.startswith('HI')):
			global username
			username = msg[3:]
			data = {'type': 'HI', 'username' :msg[3:]}
			conn.sendto(json.dumps(data).encode(), server_addr)

		if(msg == 'CONVERSATION'):
			print('Whom you want to talk?\n')
			des_username = input('')
			des_user = None

			talkto(conn, des_username)
			find = False
			time.sleep(1.5)
			for u in auth_users:
				if(u[0] == des_username):
					des_user = u

			if(des_user != None):
				print('Enter your message:')
				m = input('')
				send_conversation(conn, des_user, m)
					


#Receive a msg from socket s 
def ListenForMassage(conn):
	while(1):
		data, addr = conn.recvfrom(2048)

		data = json.loads(data.decode())
		print(data)


		if(data['type'] == 'PROOF'):
			DH_key_establishment_server(conn, 'des_username', 2, data)

		elif(data['type'] == 'PUBKEY'):
			des_addr = data['des_addr']
			inner_data, des_addr = DH_key_establishment_server(conn, des_addr[1], 4, data)
			DH_key_establishment_user(conn, des_addr, 1, data)




		elif(data['type'] == 'DHSTARTREQ'):
			DH_key_establishment_recv_from_user(conn, addr, data)
		elif(data['type'] == 'DHCONTINUEREQ'):
			DH_key_establishment_user(conn, addr, 2, data)





		elif(data['type'] == 'STARTTALKAUTH'):
			username = data['username']
			recv_talk_to_user_authenticate(conn, (username, addr), 1, data)
		elif(data['type'] == 'CONTINUETALKAUTH'):
			username = data['username']
			send_talk_to_user_authenticate(conn, (username, addr), 2, data)
		elif(data['type'] == 'FINISHTALKAUTH'):
			username = data['username']
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
				print("I do not trust you, maybe you should first esbalish a session key!")



	






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
	if(step == 1):
		#recv msg 1, retrieves values from data
		#send msg 2 CONTINUETALKAUTH

		msg = {
			'type' : 'CONTINUETALKAUTH',
			'username' : username
		}
		conn.sendto(json.dumps(msg).encode(), des_user[1])

	if(step == 2):
		#recv msg 3 FINISHTALKAUTH
		#add username to authenticated users
		auth_users.append(des_user)


def send_talk_to_user_authenticate(conn, des_user, step, data):

	if(step == 1):	
	#send msg 1 STARTTALKAUTH to username
		msg = {
			'type' : 'STARTTALKAUTH',
			'username' : username
		}	
		conn.sendto(json.dumps(msg).encode(), des_user[1])

	if(step == 2):
		#recv msg 2 CONTINUETALKAUTH	
		#send msg 3 FINISHTALKAUTH
		msg = {
			'type' : 'FINISHTALKAUTH',
			'username' : username
		}			
		conn.sendto(json.dumps(msg).encode(), des_user[1])
		auth_users.append(des_user)
	#add username to authenticated users

def DH_key_establishment_recv_from_user(conn, des_addr, data):
	
	#recv DHSTARTREQ, get values from data(1'th msg from user)
	
	#send msg 2(g^b, ...) DHCONTINUEREQ to other user
	msg = 'DHCONTINUEREQ' + username
	msg = {
		'type' : 'DHCONTINUEREQ',
		'username' : username
		} 
	conn.sendto(json.dumps(msg).encode(), des_addr)

	#build shared_key and add it to the list shared_keys_database
	des_username = data['username']
	auth_users.append((des_username, des_addr))
	shared_keys_database.append(('sessionkey', (des_username, des_addr), 1000))


def DH_key_establishment_user(conn, des_addr, step, data):
	#get values from data(4'th msg from server)
	if(step == 1):
	#send msg 1(ttb, g^a, ...) DHSTARTREQ to username
	#retrieve values from data

		msg = {
			'type' : 'DHSTARTREQ',
			'username' : username

		}
		conn.sendto(json.dumps(msg).encode(), des_addr)

	if(step == 2):
		#recv msg 2(g^b,...) DHCONTINUEREQ
		des_username = data['username']

		#build shared_key and add it to the list shared_keys_database
		auth_users.append((des_username, des_addr))
		shared_keys_database.append(('sessionkey', (des_username, des_addr), 1000))


def DH_key_establishment_server(conn, des_username, step = 1, data = ''):
	if(step == 1):
	#send msg 1(request) REQSTART
		#msg = 'REQSTART' + des_username
		msg = { 'type': 'REQSTART',
			'des_username': des_username					
			}
		conn.sendto(json.dumps(msg).encode(), server_addr)

	if(step == 2):
	#recv msg 2(hash) PROOF
		hash_of_nonce = data['hash_of_nonce']
		sub_nonce = data['sub_nonce']

	#send msg 3(proof of hash) PROOFBACK
		proof_back = find_proof_back(hash_of_nonce, sub_nonce)

		msg = { 'type': 'PROOFBACK',
			'proof_back': proof_back
			}
		conn.sendto(json.dumps(msg).encode(), server_addr)



	if(step == 4):
		#recv msg 4(ttb, public key) PUBKEY
		des_addr = data['des_addr']
		des_addr = (des_addr[0], des_addr[1])
		#should return msg 4 of protocol(ttb, sign g^a, ...)
		return ('inner data of pubkey msg', des_addr)





def talkto(conn, username): #User wants to talk to username
	for u in auth_users:
		if(u[0] == username):
			return
	shared_key_exist = False
	#check to see if this user already has a shared key with username
	for s, u, t in shared_keys_database:
		if(u[0] == username):
			#authenticate and reuse the key
			shared_key_exist = True
			send_talk_to_user_authenticate(conn, u, 1, s)

	if(shared_key_exist == False):
		#Key establishment using DH with server
		DH_key_establishment_server(conn, username)

def find_proof_back(hash_of_nonce, sub_nonce):

	for i in range (10000, 100000): # find last 5 digits of nonce
		test = sub_nonce + str(i)
		new_hash = Hash(test)
		if(base64.b64encode(new_hash).decode() == hash_of_nonce):
			return test

def main():




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






















