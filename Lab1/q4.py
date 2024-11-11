import numpy as np
from math import gcd


# Function to find the modular inverse of a number mod 26
def mod_inverse(a, modulus):
    a = a % modulus
    return pow(a, -1, modulus) if gcd(a, modulus) == 1 else None


# Function to find the inverse of a 2x2 matrix mod 26
def mod_inverse_matrix(matrix, modulus):
    a, b, c, d = matrix[0][0], matrix[0][1], matrix[1][0], matrix[1][1]

    # Calculate the determinant of the matrix
    det = (a * d - b * c) % modulus

    # Check if the determinant is invertible
    det_inv = mod_inverse(det, modulus)

    if det_inv is None:
        raise ValueError("Matrix determinant is not invertible under modulus 26.")

    # Calculate the inverse matrix mod 26
    inverse_matrix = [
        [(d * det_inv) % modulus, (-b * det_inv) % modulus],
        [(-c * det_inv) % modulus, (a * det_inv) % modulus]
    ]

    return inverse_matrix


# Ensure plaintext length is a multiple of 2 by padding with 'x'
def pad_plaintext(plaintext):
    if len(plaintext) % 2 != 0:
        plaintext += 'x'  # Append 'x' if the length is odd
    return plaintext


# Hill cipher encryption function
def hill_encrypt(plaintext, key_matrix):
    ciphertext = ''
    for i in range(0, len(plaintext), 2):
        v = []  # Store numeric values for two characters at a time
        for j in range(2):
            v.append(ord(plaintext[i + j]) - ord('a'))  # convert 'a' -> 0, 'b' -> 1, etc.

        # Perform matrix multiplication (key_matrix * vector) % 26
        res = np.dot(key_matrix, v) % 26

        # Convert result back to characters and append to ciphertext
        for af in res:
            ciphertext += chr(int(af) + ord('a'))

    return ciphertext


# Input plaintext and key matrix
pt = input("Enter the plaintext (multiple of 2 in length): ").replace(" ", "").lower()
pt = pad_plaintext(pt)  # Ensure the plaintext length is a multiple of 2

n = 2  # matrix size is 2x2

# Key matrix input (2x2)
m = []
print("Enter the 2x2 key matrix:")
for i in range(n):
    a = []
    for j in range(n):
        a.append(int(input()))  # Take integer input for key matrix
    m.append(a)

# Encrypt the plaintext
cipher_text = hill_encrypt(pt, m)

print("Ciphertext:", cipher_text)


# Decryption part
def decrypt(cipher_text, matrix_inverse):
    plain_text = ''
    for i in range(0, len(cipher_text), 2):
        v = []
        for j in range(2):
            v.append(ord(cipher_text[i + j]) - ord('a'))  # Convert ciphertext letters to numbers

        # Multiply by the inverse matrix and apply modulo 26
        res = np.dot(matrix_inverse, v) % 26

        # Convert the result back to characters
        for af in res:
            plain_text += chr(int(af) + ord('a'))
    return plain_text


# Compute inverse of the key matrix modulo 26
modulus = 26
try:
    m_inv = mod_inverse_matrix(m, modulus)
    print("Inverse Key Matrix (mod 26):")
    for row in m_inv:
        print(row)
except ValueError as e:
    print(e)
    exit(1)  # Exit if the matrix is not invertible

# Decrypt the ciphertext
decrypted_text = decrypt(cipher_text, m_inv)

print("Decrypted Text:", decrypted_text)
