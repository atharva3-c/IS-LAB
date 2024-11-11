import time
from Crypto.Util import number
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

def generate_prime(bits):
    """Generate a large prime number."""
    return number.getPrime(bits)

def generate_private_key(p):
    """Generate a private key (random integer < p)."""
    return number.getRandomRange(1, p)

def compute_public_key(g, private_key, p):
    """Compute public key: g^private_key mod p."""
    return pow(g, private_key, p)

def compute_shared_secret(public_key, private_key, p):
    """Compute the shared secret: public_key^private_key mod p."""
    return pow(public_key, private_key, p)

def derive_aes_key(shared_secret):
    """Derive a 256-bit AES key from the shared secret using SHA-256."""
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    sha256 = SHA256.new()
    sha256.update(shared_secret_bytes)
    return sha256.digest()  # Return the 32-byte AES key (256-bit)

# AES encryption function
def aes_encrypt(message, aes_key):
    """Encrypt the message using AES (CBC mode)."""
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return iv, ciphertext

# AES decryption function
def aes_decrypt(ciphertext, aes_key, iv):
    """Decrypt the ciphertext using AES (CBC mode)."""
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# Set parameters for Diffie-Hellman
bits = 512  # Size of the prime number
g = 2  # Common base (generator)

# Peer 1
start_time = time.time()
p1 = generate_prime(bits)  # Generate large prime p
private_key1 = generate_private_key(p1)  # Generate private key for Peer 1
public_key1 = compute_public_key(g, private_key1, p1)  # Compute public key
key_generation_time1 = time.time() - start_time

# Peer 2
start_time = time.time()
private_key2 = generate_private_key(p1)  # Generate private key for Peer 2
public_key2 = compute_public_key(g, private_key2, p1)  # Compute public key
key_generation_time2 = time.time() - start_time

# Key Exchange
start_time = time.time()
shared_secret1 = compute_shared_secret(public_key2, private_key1, p1)  # Peer 1 computes shared secret
shared_secret2 = compute_shared_secret(public_key1, private_key2, p1)  # Peer 2 computes shared secret
key_exchange_time = time.time() - start_time

# Verify both shared secrets are the same
assert shared_secret1 == shared_secret2, "Shared secrets do not match!"

# Derive AES key from the shared secret
aes_key = derive_aes_key(shared_secret1)

# Encrypt a message using the derived AES key
message = b"Secure Communication using Diffie-Hellman and AES"
iv, ciphertext = aes_encrypt(message, aes_key)
print(f"Ciphertext (Hex): {ciphertext.hex()}")

# Decrypt the message using the derived AES key
decrypted_message = aes_decrypt(ciphertext, aes_key, iv)
print(f"Decrypted message: {decrypted_message.decode()}")

# Output Results
print(f"Peer 1 - Key Generation Time: {key_generation_time1:.5f} seconds")
print(f"Peer 2 - Key Generation Time: {key_generation_time2:.5f} seconds")
print(f"Key Exchange Time: {key_exchange_time:.5f} seconds")
print(f"Shared Secret (Peer 1): {shared_secret1}")
print(f"Shared Secret (Peer 2): {shared_secret2}")
