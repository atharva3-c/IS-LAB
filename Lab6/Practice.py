from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
import hashlib
import secrets

# 1. Diffie-Hellman: Establish shared secret key
def generate_dh_key_pair(p, g):
    private_key = secrets.randbelow(p - 2) + 1
    public_key = pow(g, private_key, p)
    return private_key, public_key

def compute_shared_secret(their_public_key, my_private_key, p):
    return pow(their_public_key, my_private_key, p)

# 2. RSA: Generate RSA key pair for signing/verification
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# 3. RSA: Sign the shared secret with private key
def sign_message(private_key, message):
    rsa_key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pkcs1_15.new(rsa_key).sign(h)
    return signature

# 4. RSA: Verify the signature with public key
def verify_signature(public_key, message, signature):
    rsa_key = RSA.import_key(public_key)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(rsa_key).verify(h, signature)
        print("Signature is valid.")
    except (ValueError, TypeError):
        print("Signature is invalid.")

# Example usage
if __name__ == "__main__":
    # Diffie-Hellman setup
    p = 23  # Small prime for testing (use a larger safe prime for real applications)
    g = 5   # Generator

    # Generate Diffie-Hellman key pairs for Sender and Receiver
    sender_private_key, sender_public_key = generate_dh_key_pair(p, g)
    receiver_private_key, receiver_public_key = generate_dh_key_pair(p, g)

    # Compute shared secret on both sides
    sender_shared_secret = compute_shared_secret(receiver_public_key, sender_private_key, p)
    receiver_shared_secret = compute_shared_secret(sender_public_key, receiver_private_key, p)

    assert sender_shared_secret == receiver_shared_secret, "Shared secrets do not match!"

    shared_secret = sender_shared_secret.to_bytes(16, 'big')  # Convert shared secret to bytes for signing

    print(f"Shared secret (in bytes): {shared_secret.hex()}")

    # Generate RSA key pair for digital signatures
    rsa_private_key, rsa_public_key = generate_rsa_key_pair()

    # Sign the shared secret
    signature = sign_message(rsa_private_key, shared_secret)
    print(f"Signature (in bytes): {signature.hex()}")

    # Verify the signature
    verify_signature(rsa_public_key, shared_secret, signature)
