from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import long_to_bytes, bytes_to_long
import socket
import pickle

# ElGamal-like keys (predefined values)
p = 0xd51ef7dbaa3c3d80d0a67b3d7605f2f2a476d2b201f4cd3d7a36b67eb451ccbbcd194f4e7b5d7d85fb8ae376ac2d02f3659fbd29c917
g = 2
x = 0x1c8bf6c4b4b2e8cda82fdf407918f08b0fb173f9b92a2a7d4f2a3452b05177c0

def elgamal_decrypt(ciphertext, private_key):
    c1, c2 = ciphertext
    shared_secret = pow(c1, private_key, p)
    plaintext = (c2 * pow(shared_secret, -1, p)) % p
    return plaintext

# Socket setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen(1)
print("Server listening on port 65432...")

conn, addr = server_socket.accept()
data = pickle.loads(conn.recv(4096))
conn.close()
server_socket.close()

# Extract and print received data
level1_info = data['level1_info']
encrypted_level2 = data['encrypted_level2']
encrypted_number1 = data['encrypted_number1']
encrypted_number2 = data['encrypted_number2']
signature = data['signature']
rsa_private_key = RSA.import_key(data['rsa_private_key'])

print("Received level 1 info:", level1_info)

# Decrypt level 2 information
decrypted_level2 = elgamal_decrypt(encrypted_level2, x)
level2_plaintext = long_to_bytes(decrypted_level2).decode()

# Verify the signature on level 2 information
hasher = SHA256.new(level2_plaintext.encode())
try:
    pkcs1_15.new(rsa_private_key).verify(hasher, signature)
    print("Signature verified! Level 2 plaintext:", level2_plaintext)
except (ValueError, TypeError):
    print("Signature verification failed!")

# Decrypt ECC encrypted numbers (using RSA here as ECC proxy)
cipher_rsa = PKCS1_OAEP.new(rsa_private_key)  # Use private key for decryption
number1 = bytes_to_long(cipher_rsa.decrypt(encrypted_number1))
number2 = bytes_to_long(cipher_rsa.decrypt(encrypted_number2))

# Homomorphic multiplication and print the result
homomorphic_result = number1 * number2
print("Homomorphic multiplication result (plaintext):", homomorphic_result)
