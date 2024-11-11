from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
import time

# Function to generate ECC keys
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt patient data
def elgamal_encrypt(patient_data, public_key):
    # Convert data to bytes
    data_bytes = patient_data.encode()

    # Generate ephemeral key
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_pub_key = ephemeral_key.public_key()

    # Derive shared secret
    shared_secret = ephemeral_key.exchange(ec.ECDH(), public_key)

    # Encrypt the data using a symmetric cipher (e.g., AES)
    # Here, we'll simply hash the shared secret to use as a key
    key = hashes.Hash(hashes.SHA256())
    key.update(shared_secret)
    symmetric_key = key.finalize()[:16]  # Use the first 16 bytes for AES-128

    # Encrypt the data (for demonstration, we will use simple XOR encryption)
    encrypted_data = bytes(a ^ b for a, b in zip(data_bytes, symmetric_key * (len(data_bytes) // len(symmetric_key) + 1)))

    return ephemeral_pub_key, encrypted_data

# Function to decrypt patient data
def elgamal_decrypt(ephemeral_pub_key, encrypted_data, private_key):
    # Derive shared secret
    ephemeral_private_key = private_key
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), ephemeral_pub_key)

    # Derive symmetric key
    key = hashes.Hash(hashes.SHA256())
    key.update(shared_secret)
    symmetric_key = key.finalize()[:16]  # Use the first 16 bytes for AES-128

    # Decrypt the data (using XOR for demonstration)
    decrypted_data = bytes(a ^ b for a, b in zip(encrypted_data, symmetric_key * (len(encrypted_data) // len(symmetric_key) + 1)))

    return decrypted_data.decode()

# Test the implementation with performance measurement
def main():
    # Generate ECC keys
    private_key, public_key = generate_keys()

    # Example patient record
    patient_data = "Patient: John Doe, Diagnosis: Hypertension, Prescription: Medication A"

    # Measure encryption time
    start_time = time.time()
    ephemeral_pub_key, encrypted_data = elgamal_encrypt(patient_data, public_key)
    encryption_time = time.time() - start_time

    # Measure decryption time
    start_time = time.time()
    decrypted_data = elgamal_decrypt(ephemeral_pub_key, encrypted_data, private_key)
    decryption_time = time.time() - start_time

    # Display results
    print("Original Patient Data:", patient_data)
    print("Encrypted Data:", encrypted_data.hex())
    print("Decrypted Data:", decrypted_data)
    print(f"Encryption Time: {encryption_time:.6f} seconds")
    print(f"Decryption Time: {decryption_time:.6f} seconds")

if __name__ == "__main__":
    main()
