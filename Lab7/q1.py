from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import math


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


# Generate key pair
pub_key, priv_key = generate_keypair()

# Encrypt integers
a = int(input("enter numer1"))
b = int(input("enter number2"))
ciphertext_a = encrypt(pub_key, a)
ciphertext_b = encrypt(pub_key, b)

# Homomorphic multiplication
ciphertext_product = homomorphic_multiply(ciphertext_a, ciphertext_b, pub_key)

# Decrypt the product
decrypted_product = decrypt(priv_key, ciphertext_product)

# Output results
print(f"Ciphertext of a: {ciphertext_a}")
print(f"Ciphertext of b: {ciphertext_b}")
print(f"Ciphertext of a * b: {ciphertext_product}")
print(f"Decrypted product: {decrypted_product}")
print(f"Original product: {a * b}")
