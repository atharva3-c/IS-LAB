import random
from Crypto.Util.number import getPrime

# Use a larger prime p to reduce modular issues
p = getPrime(256)  # Generate a large 256-bit prime
g = 2  # Generator
x = random.randint(1, p - 2)  # Private key
h = pow(g, x, p)  # Public key component h = g^x mod p

# Function to encrypt the ASCII values of characters
def elgamal_encrypt_ascii(message, p, g, h):
    encrypted_message = []
    for char in message:
        m = ord(char)  # Convert character to its ASCII value

        # Generate a random ephemeral key k
        k = random.randint(1, p - 2)

        # Calculate ciphertext components
        c1 = pow(g, k, p)  # c1 = g^k mod p
        s = pow(h, k, p)  # Shared secret s = h^k mod p
        c2 = (m * s) % p  # c2 = (m * s) mod p

        encrypted_message.append((c1, c2))

    return encrypted_message

# Function to decrypt the ciphertext integers
def elgamal_decrypt_ascii(encrypted_message, p, x):
    decrypted_message = []
    for c1, c2 in encrypted_message:
        s = pow(c1, x, p)  # s = c1^x mod p
        s_inv = pow(s, p - 2, p)  # Compute modular inverse of s mod p

        m = (c2 * s_inv) % p  # Recover the original message

        # Convert the integer back to character, ensuring valid ASCII range
        if 32 <= m <= 126:
            decrypted_message.append(chr(m))
        else:
            decrypted_message.append('?')  # Replace invalid characters

    return ''.join(decrypted_message)

# Message to be encrypted
message = "Asymmetric Algorithms"

# Encrypt the ASCII values of the message
encrypted_message = elgamal_encrypt_ascii(message, p, g, h)
print("Encrypted message (c1, c2):", encrypted_message)

# Decrypt the message
decrypted_message = elgamal_decrypt_ascii(encrypted_message, p, x)
print("Decrypted message:", decrypted_message)
