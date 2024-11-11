from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random

# ElGamal Key Generation
def generate_elgamal_keys(bits=256):
    p = getPrime(bits)  # Large prime number
    g = random.randint(2, p - 1)  # Generator g
    x = random.randint(1, p - 2)  # Private key x
    h = pow(g, x, p)  # Public key h = g^x mod p
    return (p, g, h), x  # Public key (p, g, h) and private key x

# ElGamal Encryption
def elgamal_encrypt(public_key, message):
    p, g, h = public_key
    k = random.randint(1, p - 2)  # Ephemeral key k
    c1 = pow(g, k, p)  # c1 = g^k mod p
    m = bytes_to_long(message)  # Convert message to integer
    s = pow(h, k, p)  # Shared secret s = h^k mod p
    c2 = (m * s) % p  # c2 = (m * s) mod p
    return c1, c2  # Ciphertext (c1, c2)

# ElGamal Decryption
def elgamal_decrypt(private_key, public_key, ciphertext):
    p, g, h = public_key
    c1, c2 = ciphertext
    x = private_key  # Private key
    s_decrypt = pow(c1, x, p)  # Shared secret s = c1^x mod p
    s_inv = inverse(s_decrypt, p)  # Modular inverse of shared secret
    m_decrypted = (c2 * s_inv) % p  # m = (c2 * s_inv) mod p
    return long_to_bytes(m_decrypted)  # Convert decrypted message to bytes

# Example usage
if __name__ == "__main__":
    # Key generation
    public_key, private_key = generate_elgamal_keys()
    print("Public Key (p, g, h):", public_key)
    print("Private Key (x):", private_key)

    # Message to encrypt
    message = b"Confidential Data"

    # Encrypt the message
    ciphertext = elgamal_encrypt(public_key, message)
    print("Ciphertext (c1, c2):", ciphertext)

    # Decrypt the message
    decrypted_message = elgamal_decrypt(private_key, public_key, ciphertext)
    print("Decrypted message:", decrypted_message.decode())
