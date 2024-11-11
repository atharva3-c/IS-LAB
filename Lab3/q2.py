from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# 1. Generate ECC key pairs
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# 2. Derive shared secret using ECDH
# Generate another key pair for demonstration
other_private_key = ec.generate_private_key(ec.SECP256R1())
other_public_key = other_private_key.public_key()

# Derive shared secret from the other party's public key
shared_secret = other_private_key.exchange(ec.ECDH(), public_key)

# Derive AES key from the shared secret using SHA-256 (32-byte key for AES-256)
digest = hashes.Hash(hashes.SHA256())
digest.update(shared_secret)
aes_key = digest.finalize()[:32]  # AES-256 requires a 32-byte key

# Example message to encrypt
message = b"Secure Transactions"

# 3. Encrypt data with AES-ECB using PyCryptodome
cipher = AES.new(aes_key, AES.MODE_ECB)  # Using ECB mode
padded_message = pad(message, AES.block_size)  # Pad the message to match AES block size
ciphertext = cipher.encrypt(padded_message)  # Encrypt the message

print("Ciphertext (ECB):", ciphertext.hex())

# 4. Decrypt data with AES-ECB using PyCryptodome
decryptor = AES.new(aes_key, AES.MODE_ECB)  # Create a new AES object for decryption
decrypted_padded_message = decryptor.decrypt(ciphertext)  # Decrypt the ciphertext
decrypted_message = unpad(decrypted_padded_message, AES.block_size)  # Unpad the message

print("Decrypted message:", decrypted_message.decode())
