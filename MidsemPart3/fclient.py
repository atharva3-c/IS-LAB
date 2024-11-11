import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import binascii
import os

# Predefined AES key (ensure it is 16 bytes)
aes_key = b"16_bytes_predef_key"
nonce = os.urandom(16)  # Nonce (should be unique for each encryption)

# Function to load the server's public RSA key from a PEM file
def load_rsa_public_key(pem_file):
    with open(pem_file, 'rb') as f:
        key = RSA.import_key(f.read())
    return key

# Function to encrypt the AES key using RSA
def encrypt_rsa(public_key, aes_key):
    cipher = PKCS1_OAEP.new(public_key)  # Create an RSA cipher object
    encrypted_key = cipher.encrypt(aes_key)  # Encrypt the AES key
    return binascii.hexlify(encrypted_key).decode()  # Convert to hex string for transmission

# Function to ensure AES key length is 16 bytes
def ensure_aes_key_length(aes_key):
    # If the key length is greater than 16 bytes, truncate it
    if len(aes_key) > 16:
        aes_key = aes_key[:16]
    # If the key length is less than 16 bytes, pad it with zeros
    elif len(aes_key) < 16:
        aes_key = aes_key.ljust(16, b'\0')
    return aes_key

# Function to encrypt data using AES-GCM
def encrypt_aes(aes_key, nonce, plaintext):
    # Ensure AES key length is 16 bytes
    aes_key = ensure_aes_key_length(aes_key)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return binascii.hexlify(ciphertext).decode()  # Return ciphertext as hex

def client():
    host = '127.0.0.1'  # Server address
    port = 12345  # Port to connect to the server

    # Load the server's RSA public key from the PEM file
    public_key = load_rsa_public_key("public.pem")

    # Data to write to the file
    level_1_info = "Level 1 Info: Some basic information"
    level_2_info = "Level 2 Info: Some more sensitive information"
    number_1 = 5  # First number
    number_2 = 10  # Second number

    # Step 1: Write the data to a file
    with open("data.txt", "w") as file:
        file.write(f"{level_1_info}\n")
        file.write(f"{level_2_info}\n")
        file.write(f"Number 1: {number_1}\n")
        file.write(f"Number 2: {number_2}\n")

    # Set up the client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    # Step 2: Encrypt the AES key using RSA encryption
    encrypted_aes_key = encrypt_rsa(public_key, aes_key)
    client_socket.send(encrypted_aes_key.encode('utf-8'))

    # Step 3: Encrypt Level 2 information using AES
    aes_ciphertext = encrypt_aes(aes_key, nonce, level_2_info)

    # Send the AES-encrypted Level 2 information to the server
    client_socket.send(aes_ciphertext.encode('utf-8'))

    # Step 4: Send 'done' message to indicate the completion
    client_socket.send("done".encode())

    # Close the socket
    client_socket.close()

if __name__ == "__main__":
    client()
