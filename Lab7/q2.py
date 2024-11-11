import random
from math import gcd
from Crypto.Util.number import getPrime

def generate_keypair(bits):
    """Generate public and private keys."""
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    n2 = n * n
    lambda_ = (p - 1) * (q - 1) // gcd(p - 1, q - 1)  # lcm(p-1, q-1)

    # Choose g
    g = random.randint(1, n2 - 1)

    # Compute mu using the modular inverse
    g_lambda = pow(g, lambda_, n2)
    L = (g_lambda - 1) // n
    mu = pow(L, -1, n)

    return (n, g, lambda_, mu), (p, q)  # (public_key, private_key)

def encrypt(public_key, m):
    """Encrypt a message m using the public key."""
    n, g, _, _ = public_key
    r = random.randint(1, n - 1)
    c = (pow(g, m, n**2) * pow(r, n, n**2)) % (n**2)
    return c

def decrypt(lambda_, mu, c, n):
    """Decrypt the ciphertext c using the private key components (lambda_, mu)."""
    c_lambda = pow(c, lambda_, n**2)
    L = (c_lambda - 1) // n
    m = (L * mu) % n
    return m

# Example usage
public_key, private_key = generate_keypair(512)  # Use larger bits for real applications

# Encrypt two integers
m1 = 15
m2 = 25
ciphertext1 = encrypt(public_key, m1)
ciphertext2 = encrypt(public_key, m2)

# Perform homomorphic addition
ciphertext_sum = (ciphertext1 * ciphertext2) % (public_key[0]**2)

# Decrypt the sum
decrypted_sum = decrypt(public_key[2], public_key[3], ciphertext_sum, public_key[0])

# Output results
print(f"Original message 1: {m1}")
print(f"Original message 2: {m2}")
print(f"Ciphertext of m1: {ciphertext1}")
print(f"Ciphertext of m2: {ciphertext2}")
print(f"Ciphertext of m1 + m2: {ciphertext_sum}")
print(f"Decrypted sum: {decrypted_sum}")
print(f"Original sum: {m1 + m2}")
