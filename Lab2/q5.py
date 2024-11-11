from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify

# Message to encrypt
message = b"Top Secret Data"

# Key as a byte string (Truncate to 24 bytes for AES-192)
key = "FEDCBA9876543210FEDCBA9876543210".encode()[:24]  # Taking the first 24 bytes

# Create AES cipher in ECB mode
cipher = AES.new(key, AES.MODE_ECB)

# Pad the message to be a multiple of 16 bytes (AES block size)
padded_message = pad(message, AES.block_size)

# Encrypt the message
ciphertext = cipher.encrypt(padded_message)
print("Ciphertext:", hexlify(ciphertext).decode())

# Decrypt the message
decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
print("Decrypted message:", decrypted_message.decode())
