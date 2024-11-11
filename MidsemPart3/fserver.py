import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import binascii
import os

# Function to load the private RSA key from a PEM file
def load_rsa_private_key(pem_file):
    with open(pem_file, 'rb') as f:
        key = RSA.import_key(f.read())
    return key

# Function to decrypt the AES key using RSA
def decrypt_rsa(private_key, encrypted_aes_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher.decrypt(binascii.unhexlify(encrypted_aes_key))
    return decrypted_key

# Function to decrypt data using AES-GCM
def decrypt_aes(aes_key, nonce, ciphertext):
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(binascii.unhexlify(ciphertext), b"")
    return decrypted_data.decode()

def server():
    host = '127.0.0.1'  # Host address
    port = 12345  # Port to listen for client connections

    # Load the server's private RSA key from the PEM file
    private_key = load_rsa_private_key("private.pem")

    # Set up the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print("Server is listening for incoming connections...")

    # Accept client connection
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    # Step 1: Receive the encrypted AES key from the client
    encrypted_aes_key = client_socket.recv(1024).decode('utf-8')
    aes_key = decrypt_rsa(private_key, encrypted_aes_key)

    # Step 2: Receive the AES-encrypted Level 2 information from the client
    aes_ciphertext = client_socket.recv(1024).decode('utf-8')
    nonce = os.urandom(16)  # Nonce (in a real scenario, this would need to match the client's nonce)

    # Decrypt Level 2 information using the AES key
    level_2_info = decrypt_aes(aes_key, nonce, aes_ciphertext)
    print("Decrypted Level 2 Information:", level_2_info)

    # Step 3: Wait for 'done' message from the client to proceed with multiplication
    done_message = client_socket.recv(1024).decode('utf-8')
    if done_message == "done":
        print("Received 'done' message from client.")

        # Step 4: Read the numbers from the file for homomorphic multiplication
        try:
            with open("data.txt", "r") as file:
                lines = file.readlines()
                number_1 = int(lines[3].split(":")[1].strip())  # Extract Number 1
                number_2 = int(lines[4].split(":")[1].strip())  # Extract Number 2
                print(f"Number 1: {number_1}, Number 2: {number_2}")

                # Step 5: Perform the multiplication
                result = number_1 * number_2
                print(f"Homomorphic Multiplication Result: {result}")

        except Exception as e:
            print(f"Error reading file: {e}")

    # Close the client socket
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    server()
