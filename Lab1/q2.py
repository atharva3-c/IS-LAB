a = "houseisbeingsoldtonight"
b = "dollars"
i = len(b)
s = ''
f = ''
z = 0

# First loop: Vigenère Cipher Encryption
for ele in range(0, len(a)):
    d = chr(((ord(a[ele]) + ord(b[z]) - 2 * ord('a')) % 26) + ord('a'))
    s += d
    z = (z + 1) % i

print("Vigenère result (s):", s)

# Autokey Cipher Encryption
z = 0
flag = 0
for ele in range(0, len(a)):
    if flag == 0:
        # Vigenère-like encryption with the key `b`
        d = chr(((ord(a[ele]) + ord(b[z]) - 2 * ord('a')) % 26) + ord('a'))
        f += d
        z += 1
    else:
        # Autokey encryption, using plaintext as the key after `b` is exhausted
        d = chr(((ord(a[ele]) + ord(a[z]) - 2 * ord('a')) % 26) + ord('a'))
        f += d
        z += 1

    if z == i and flag == 0:
        flag = 1
        z = 0  # Start using the plaintext as key from this point onward

print("Autokey result (f):", f)


# ---------------------------------
# Decryption
# ---------------------------------

# Vigenère Decryption
def vigenere_decrypt(ciphertext, key):
    i = len(key)
    z = 0
    decrypted_text = ''

    for ele in range(0, len(ciphertext)):
        d = chr(((ord(ciphertext[ele]) - ord(key[z]) + 26) % 26) + ord('a'))  # Subtract the key
        decrypted_text += d
        z = (z + 1) % i

    return decrypted_text


# Autokey Decryption
def autokey_decrypt(ciphertext, key):
    i = len(key)
    z = 0
    flag = 0
    decrypted_text = ''

    for ele in range(0, len(ciphertext)):
        if flag == 0:
            # Vigenère-like decryption using the initial key
            d = chr(((ord(ciphertext[ele]) - ord(key[z]) + 26) % 26) + ord('a'))
            decrypted_text += d
            z += 1
        else:
            # Autokey decryption, using the decrypted text itself as the key
            d = chr(((ord(ciphertext[ele]) - ord(decrypted_text[z]) + 26) % 26) + ord('a'))
            decrypted_text += d
            z += 1

        if z == i and flag == 0:
            flag = 1
            z = 0  # Start using the decrypted text as the key from this point onward

    return decrypted_text


# Decrypt the Vigenère result
vigenere_decrypted = vigenere_decrypt(s, b)
print("Vigenère decrypted (original text):", vigenere_decrypted)

# Decrypt the Autokey result
autokey_decrypted = autokey_decrypt(f, b)
print("Autokey decrypted (original text):", autokey_decrypted)
