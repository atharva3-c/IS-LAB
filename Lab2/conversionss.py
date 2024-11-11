import base64
import binascii

# 1. Hexadecimal to Bytes
hex_string = "A1B2C3D4"
byte_data_from_hex = bytes.fromhex(hex_string)
print(f"Hex to Bytes: {byte_data_from_hex}")

# 2. Bytes to Hexadecimal
byte_data = b'\xa1\xb2\xc3\xd4'
hex_string_from_bytes = byte_data.hex()
print(f"Bytes to Hex: {hex_string_from_bytes}")

# 3. String to Bytes (encode)
string = "Hello, World!"
byte_data_from_string = string.encode('utf-8')
print(f"String to Bytes: {byte_data_from_string}")

# 4. Bytes to String (decode)
byte_data = b'Hello, World!'
string_from_bytes = byte_data.decode('utf-8')
print(f"Bytes to String: {string_from_bytes}")

# 5. Base64 Encoding (Bytes to Base64 String)
base64_encoded = base64.b64encode(byte_data_from_string).decode()
print(f"Bytes to Base64: {base64_encoded}")

# 6. Base64 Decoding (Base64 String to Bytes)
base64_string = "SGVsbG8sIFdvcmxkIQ=="
byte_data_from_base64 = base64.b64decode(base64_string)
print(f"Base64 to Bytes: {byte_data_from_base64}")

# 7. Hexadecimal String to Integer
integer_from_hex = int(hex_string, 16)
print(f"Hex to Integer: {integer_from_hex}")

# 8. Integer to Hexadecimal String
hex_string_from_int = hex(integer_from_hex)
print(f"Integer to Hex: {hex_string_from_int}")

# 9. Integer to Bytes
byte_data_from_int = integer_from_hex.to_bytes((integer_from_hex.bit_length() + 7) // 8, byteorder='big')
print(f"Integer to Bytes: {byte_data_from_int}")

# 10. Bytes to Integer
integer_from_bytes = int.from_bytes(byte_data_from_int, byteorder='big')
print(f"Bytes to Integer: {integer_from_bytes}")

# 11. String to Hexadecimal
hex_string_from_string = string.encode('utf-8').hex()
print(f"String to Hex: {hex_string_from_string}")

# 12. Hexadecimal to String
string_from_hex = bytes.fromhex(hex_string_from_string).decode('utf-8')
print(f"Hex to String: {string_from_hex}")

# 13. Bytes to Binary String
binary_string_from_bytes = ''.join(format(byte, '08b') for byte in byte_data)
print(f"Bytes to Binary: {binary_string_from_bytes}")

# 14. Binary String to Bytes
binary_string = "1010000110110010"
byte_data_from_binary = int(binary_string, 2).to_bytes((len(binary_string) + 7) // 8, byteorder='big')
print(f"Binary to Bytes: {byte_data_from_binary}")
