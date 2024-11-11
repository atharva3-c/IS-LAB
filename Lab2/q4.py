from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Key (48 hex characters or 24 bytes)
key = bytes.fromhex('1234567890ADEF1234567890ABCDEF123BC4567890ABCDEF')

# Message to be encrypted
message = "Classified Text".encode()

# Create Triple DES cipher object in ECB mode (Note: ECB mode is generally not secure)
cipher = DES3.new(key, DES3.MODE_ECB)

# Padding the message to be a multiple of 8 bytes (block size for DES)
padded_message = pad(message, DES3.block_size)

# Encrypt the message
ciphertext = cipher.encrypt(padded_message)
print(f"Ciphertext (in hex): {ciphertext.hex()}")

# Decrypt the ciphertext
decrypted_padded_message = cipher.decrypt(ciphertext)

# Unpad the decrypted message
decrypted_message = unpad(decrypted_padded_message, DES3.block_size).decode('utf-8')
print(f"Decrypted Message: {decrypted_message}")
