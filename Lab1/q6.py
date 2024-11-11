def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_decrypt(cipher_text, a, b, m):
    a_inv = mod_inverse(a, m)
    if a_inv is None:
        return None
    decrypted = []
    for ch in cipher_text:
        if ch.isalpha():
            num = (a_inv * (ord(ch) - ord('A') - b)) % m
            if num < 0:
                num += m
            decrypted.append(chr(num + ord('A')))
        else:
            decrypted.append(ch)
    return ''.join(decrypted)

def find_keys(cipher_text, known_plaintext, known_ciphertext):
    m = 26
    # Convert known plaintext and ciphertext to numerical values
    plain_indices = [ord(ch) - ord('a') for ch in known_plaintext]
    cipher_indices = [ord(ch) - ord('A') for ch in known_ciphertext]

    # To find 'a' and 'b' such that a*P + b = C (mod 26)
    for a in range(1, m):
        if gcd(a, m) == 1:
            a_inv = mod_inverse(a, m)
            for b in range(m):
                valid = True
                for p, c in zip(plain_indices, cipher_indices):
                    if (a * p + b) % m != c:
                        valid = False
                        break
                if valid:
                    decrypted_text = affine_decrypt(cipher_text, a, b, m)
                    print(f"Trying keys: a = {a}, b = {b}")
                    print(f"Decrypted text: {decrypted_text}")
                    if decrypted_text != cipher_text:
                        print(f"Correct keys found: a = {a}, b = {b}")
                        return a, b
    return None, None

# Given ciphertext and known plaintext-ciphertext mapping
cipher_text = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
known_plaintext = "ab"
known_ciphertext = "GL"

# Find the affine cipher keys
a, b = find_keys(cipher_text, known_plaintext, known_ciphertext)

if a is not None and b is not None:
    print(f"Found keys: a = {a}, b = {b}")
else:
    print("No valid keys found.")
