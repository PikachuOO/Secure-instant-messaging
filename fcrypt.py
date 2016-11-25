from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac, serialization
import os, sys, getopt, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def LoadKeys(public_key_file, private_key_file):
  # Load private key
  with open(private_key_file, "rb") as key_file:
    private_key = serialization.load_der_private_key(
              key_file.read(),
              password=None,
              backend=default_backend()
            )
  # Load public_key
  with open(public_key_file, "rb") as key_file:
    public_key = serialization.load_der_public_key(
              key_file.read(),
              backend=default_backend()
            )

  return (public_key, private_key)

def Hash(message):
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

	digest.update(message.encode())
	return digest.finalize()

def AESCTREncrypt(plain_text, k, n):
  #Encrypt plain_text with key k and nonce n using CTR mode
  c = Cipher(algorithms.AES(k), modes.CTR(n), backend=default_backend())
  encryptor = c.encryptor()
  cipher = encryptor.update(plain_text) + encryptor.finalize()
  return cipher


def AESCTRDecrypt(cipher_text, k, n):
  #Decrypt cipher_text with key k and nonce n using CTR mode
  c = Cipher(algorithms.AES(k), modes.CTR(n), backend=default_backend())
  decryptor = c.decryptor()
  message = decryptor.update(cipher_text) + decryptor.finalize()
  return message


def SymmetricEnc(message):
  #Uses symmertric encryption(AES CTR mode) to encrypt message and return key+ct(To enable decryption)
  key = os.urandom(16)
  nonce = os.urandom(16)
  cipher = AESCTREncrypt(message, key, nonce)
  ct = nonce + cipher
  return key, ct


def SymmetricDec(shared_key, cipher):
  #retrieve message+nonce from message, and then decrypt and return plain_text
  nonce = cipher[0:16]
  ct = cipher[16:]
  plain_text = AESCTRDecrypt(ct, shared_key, nonce)
  return plain_text





def RSAEncrypt(message, public_key):
  #RSA encrypt of message with public_key
  c = public_key.encrypt(message,
                        padding.OAEP(
                          mgf=padding.MGF1(algorithm=hashes.SHA1()),
                          algorithm=hashes.SHA1(),
                          label=None
                      )
  )
  return c


def RSASign(message, private_key):
  #Sign message with its private_key
  signer = private_key.signer(
    padding.PSS(
      mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH


    ),
    hashes.SHA256()
  )
  signer.update(message)
  signature = signer.finalize()
  return signature

def RSADecrypt(cipher, private_key):
  #decrypt cipher with privat_key using RSA
  message = private_key.decrypt(
      cipher,
      padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
      )
  )
  return message

def VerifySign(message, signature, public_key):
  #Authentication: check signature with public_key
  verifier = public_key.verifier(
    signature,
    padding.PSS(
         mgf=padding.MGF1(hashes.SHA256()),
         salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
  )
  verifier.update(message)
  verified = verifier.verify()
  return verified


def Encrypt(message, public_key, private_key):
  #For faster encryption, first encrpyt message with symmetric AES_CTR mode, then, use the shared_key to RSA encrypt, then sign the cipher_shared_key and return sign+cipher_shared_key+ct
  shared_key, ct = SymmetricEnc(message)
  cipher_shared_key = RSAEncrypt(shared_key, public_key)
  signature = RSASign(cipher_shared_key, private_key)

  result = signature + cipher_shared_key + ct

  return result

def Decrypt(cipher, public_key, private_key):
  #First, retrieve hmac and cipher_shared_key, then, verify signature, then decrypt cipher_shared_key using RSA decryption, then from shared_key, easily decrypt cipher_text
  hmac = cipher[0:256]
  cipher_shared_key = cipher[256:512]
  VerifySign(cipher_shared_key, hmac, public_key)


  shared_key = RSADecrypt(cipher_shared_key, private_key)

  ct = cipher[512:]

  m = SymmetricDec(shared_key, ct)

  return m



