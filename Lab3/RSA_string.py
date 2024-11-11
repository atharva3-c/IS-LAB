from Crypto.PublicKey import RSA

# Generate RSA key (using small key size for demonstration)
n, e, d = 323,5,173

print("n (modulus):", n)
print("e (public exponent):", e)
print("d (private exponent):", d)

# Function to encrypt each character's ASCII value
def rsa_encrypt_string(message, e, n):
    encrypted_chars = []
    for char in message:
        # Convert char to ASCII, then encrypt
        ascii_value = ord(char)
        encrypted_value = pow(ascii_value, e, n)
        # Store as hex string for display
        encrypted_chars.append(hex(encrypted_value))
    return encrypted_chars

# Function to decrypt each encrypted hex value back to characters
def rsa_decrypt_string(encrypted_chars, d, n):
    decrypted_message = []
    for encrypted_char in encrypted_chars:
        # Convert hex to integer
        encrypted_value = int(encrypted_char, 16)
        # Decrypt the value using RSA
        decrypted_ascii = pow(encrypted_value, d, n)
        # Convert ASCII back to character
        decrypted_message.append(chr(decrypted_ascii))
    return ''.join(decrypted_message)

# Message to be encrypted
message = "Cryptographic Protocols"

# Encrypt the message (each character separately)
encrypted_message = rsa_encrypt_string(message, e, n)
print("Encrypted message (hex):", encrypted_message)

# Decrypt the message
decrypted_message = rsa_decrypt_string(encrypted_message, d, n)
print("Decrypted message:", decrypted_message)
