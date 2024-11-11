from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
import socket
import pickle

# RSA Key Pair for signing
rsa_key = RSA.generate(2048)
rsa_public_key = rsa_key.publickey()

# ECC key for encryption (using predefined curve)
ecc_key = ECC.generate(curve='P-256')
ecc_public_key = ecc_key.public_key()

# ElGamal-like keys (predefined values)
p = 0xd51ef7dbaa3c3d80d0a67b3d7605f2f2a476d2b201f4cd3d7a36b67eb451ccbbcd194f4e7b5d7d85fb8ae376ac2d02f3659fbd29c917
g = 2
x = 0x1c8bf6c4b4b2e8cda82fdf407918f08b0fb173f9b92a2a7d4f2a3452b05177c0
y = pow(g, x, p)

def elgamal_encrypt(public_key, message):
    k = 123456789  # Random integer for demo
    c1 = pow(g, k, p)
    shared_secret = pow(public_key, k, p)
    c2 = (message * shared_secret) % p
    return c1, c2

# Get inputs
level1_info = input("Enter level 1 information: ")
level2_info = input("Enter level 2 information: ")
number1 = int(input("Enter number 1: "))
number2 = int(input("Enter number 2: "))

# Hash and sign level 2 information
hasher = SHA256.new(level2_info.encode())
signature = pkcs1_15.new(rsa_key).sign(hasher)

# Encrypt level 2 information with ElGamal
encrypted_level2 = elgamal_encrypt(y, bytes_to_long(level2_info.encode()))

# Encrypt numbers using ECC (using ECC encryption with simple approach here)
cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
encrypted_number1 = cipher_rsa.encrypt(long_to_bytes(number1))
encrypted_number2 = cipher_rsa.encrypt(long_to_bytes(number2))

# Send data to server
data = {
    'level1_info': level1_info,
    'encrypted_level2': encrypted_level2,
    'encrypted_number1': encrypted_number1,
    'encrypted_number2': encrypted_number2,
    'signature': signature,
    'rsa_public_key': rsa_public_key.export_key(),
    'rsa_private_key': rsa_key.export_key(),  # Send private key (for decryption)
    'ecc_public_key': ecc_public_key.export_key(format='DER')
}

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))
client_socket.sendall(pickle.dumps(data))
client_socket.close()
