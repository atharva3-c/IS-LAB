import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7  # Import PKCS7 padding
from cryptography.hazmat.primitives.asymmetric import padding
# Function to generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


# Function to encrypt with RSA
def rsa_encrypt(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


# Function to decrypt with RSA
def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# Function to generate ECC keys
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


# ElGamal-style encryption using ECC
def elgamal_encrypt(message, recipient_public_key):
    # Generate ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Derive shared secret using ECDH
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

    # Derive AES key from shared secret
    aes_key = hashes.Hash(hashes.SHA256())
    aes_key.update(shared_secret)
    symmetric_key = aes_key.finalize()

    # Encrypt the message using AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Padding the message
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()

    # Encrypt the data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ephemeral_public_key, iv, ciphertext


# ElGamal decryption using ECC
def elgamal_decrypt(ephemeral_public_key, iv, ciphertext, recipient_private_key):
    # Derive shared secret using ECDH
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Derive AES key from shared secret
    aes_key = hashes.Hash(hashes.SHA256())
    aes_key.update(shared_secret)
    symmetric_key = aes_key.finalize()

    # Decrypt the data using AES
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the data
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()


# Measure performance for RSA and ElGamal
def measure_performance(message):
    # RSA Performance
    start_time = time.time()
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    key_gen_time_rsa = time.time() - start_time

    start_time = time.time()
    rsa_ciphertext = rsa_encrypt(rsa_public_key, message)
    encryption_time_rsa = time.time() - start_time

    start_time = time.time()
    rsa_plaintext = rsa_decrypt(rsa_private_key, rsa_ciphertext)
    decryption_time_rsa = time.time() - start_time

    print(f"RSA Key Generation Time: {key_gen_time_rsa:.6f} seconds")
    print(f"RSA Encryption Time: {encryption_time_rsa:.6f} seconds")
    print(f"RSA Decryption Time: {decryption_time_rsa:.6f} seconds")
    print(f"Original RSA Plaintext: {message.decode()} -> Decrypted: {rsa_plaintext.decode()}\n")

    # ElGamal Performance
    start_time = time.time()
    ecc_private_key, ecc_public_key = generate_ecc_keys()
    key_gen_time_ecc = time.time() - start_time

    start_time = time.time()
    ephemeral_pub_key, iv, ecc_ciphertext = elgamal_encrypt(message.decode(), ecc_public_key)
    encryption_time_ecc = time.time() - start_time

    start_time = time.time()
    ecc_plaintext = elgamal_decrypt(ephemeral_pub_key, iv, ecc_ciphertext, ecc_private_key)
    decryption_time_ecc = time.time() - start_time

    print(f"ECC Key Generation Time: {key_gen_time_ecc:.6f} seconds")
    print(f"ECC Encryption Time: {encryption_time_ecc:.6f} seconds")
    print(f"ECC Decryption Time: {decryption_time_ecc:.6f} seconds")
    print(f"Original ECC Plaintext: {message.decode()} -> Decrypted: {ecc_plaintext}\n")


if __name__ == "__main__":
    # Test with varying message sizes
    sizes = [1024, 10240]  # 1 KB, 10 KB
    for size in sizes:
        test_message = os.urandom(size)  # Generate random bytes for testing
        print(f"Testing with message size: {size} bytes")
        measure_performance(test_message)
