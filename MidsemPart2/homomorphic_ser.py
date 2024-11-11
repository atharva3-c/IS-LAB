import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def generate_keypair(nlength=1024):
    """Generates a public/private key pair"""
    key = RSA.generate(nlength)
    pub_key = key.publickey()
    return pub_key, key


def encrypt(pub_key, message):
    """Encrypts a message using the public key"""
    # Ensure the message is less than the modulus
    if message >= pub_key.n:
        raise ValueError("Message must be less than modulus n")

    # Encrypt the message
    ciphertext = pow(message, pub_key.e, pub_key.n)
    return ciphertext


def decrypt(priv_key, ciphertext):
    """Decrypts a ciphertext using the private key"""
    # Decrypt the ciphertext
    message = pow(ciphertext, priv_key.d, priv_key.n)
    return message


def homomorphic_multiply(ciphertext1, ciphertext2, pub_key):
    """Performs homomorphic multiplication on ciphertexts"""
    return (ciphertext1 * ciphertext2) % pub_key.n


def start_server():
    """Starts the server to listen for client connections"""
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)

    print("Server is listening...")

    while True:
        # Accept client connection
        client_socket, addr = server_socket.accept()
        print(f"Connection established with {addr}")

        # Generate key pair (public and private keys)
        pub_key, priv_key = generate_keypair()

        # Receive the two numbers from the client
        data = client_socket.recv(1024).decode()
        num1, num2 = map(int, data.split())

        # Encrypt the numbers
        ciphertext_a = encrypt(pub_key, num1)
        ciphertext_b = encrypt(pub_key, num2)

        # Perform homomorphic multiplication
        ciphertext_product = homomorphic_multiply(ciphertext_a, ciphertext_b, pub_key)

        # Decrypt the product
        decrypted_product = decrypt(priv_key, ciphertext_product)

        # Display the results on the server side
        print(f"Received numbers: {num1}, {num2}")
        print(f"Ciphertext of a: {ciphertext_a}")
        print(f"Ciphertext of b: {ciphertext_b}")
        print(f"Ciphertext of a * b: {ciphertext_product}")
        print(f"Decrypted product: {decrypted_product}")
        print(f"Original product: {num1 * num2}")

        # Close the client connection
        client_socket.close()
        print("Connection closed with client.")


if __name__ == "__main__":
    start_server()
