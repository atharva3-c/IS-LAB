from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes

# RSA Key Generation
def generate_keypair(nlength=1024):
    """Generates a public/private key pair"""
    key = RSA.generate(nlength)
    pub_key = key.publickey()
    return pub_key, key

# RSA Encryption and Decryption Functions
def rsa_encrypt(pub_key, message):
    """Encrypts a message using the public key (as an integer)"""
    if message >= pub_key.n:
        raise ValueError("Message must be less than modulus n")
    ciphertext = pow(message, pub_key.e, pub_key.n)
    return ciphertext

def rsa_decrypt(priv_key, ciphertext):
    """Decrypts a ciphertext using the private key (as an integer)"""
    message = pow(ciphertext, priv_key.d, priv_key.n)
    return message

# Homomorphic Multiplication for RSA Ciphertexts
def homomorphic_multiply(ciphertext1, ciphertext2, pub_key):
    """Performs homomorphic multiplication on ciphertexts"""
    return (ciphertext1 * ciphertext2) % pub_key.n

# AES Encryption and Decryption Functions
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Step 1: Generate RSA and AES Keys
pub_key, priv_key = generate_keypair()
aes_key = get_random_bytes(32)  # AES-256 key

# Step 2: Input Data and Encrypt as per Requirements
level_1_info = "Level 1 security information."
level_2_info = "Level 2 security info."
number1 = 1  # Replace with actual user input if needed
number2 = 4  # Replace with actual user input if needed

# Encrypt Level 2 Info with AES
nonce, aes_ciphertext, aes_tag = aes_encrypt(level_2_info, aes_key)

# Encrypt Number1 and Number2 with RSA
ciphertext_number1 = rsa_encrypt(pub_key, number1)
ciphertext_number2 = rsa_encrypt(pub_key, number2)

# Perform homomorphic multiplication of RSA ciphertexts
ciphertext_product = homomorphic_multiply(ciphertext_number1, ciphertext_number2, pub_key)

# Decrypt the product to verify
try:
    decrypted_product = rsa_decrypt(priv_key, ciphertext_product)
except ValueError as e:
    print("Decryption failed:", e)
    decrypted_product = "Error in decryption; product cannot be verified."

# Step 3: Write Results to result.txt
with open("result.txt", "w") as result_file:
    result_file.write(f"{level_1_info}\n")
    result_file.write(f"AES Encrypted Level 2 info: {aes_ciphertext.hex()}\n")
    result_file.write(f"RSA Encrypted Number1: {hex(ciphertext_number1)}\n")
    result_file.write(f"RSA Encrypted Number2: {hex(ciphertext_number2)}\n")
    result_file.write(f"Product of Number1 and Number2 (Decrypted): {decrypted_product}\n")

print("Data has been written to result.txt")
