import string


def getcord(m, val):
    for i in range(0, 5):
        for j in range(0, 5):
            if m[i][j] == val:
                return i, j
    return None, None


# Create a Playfair key matrix
def create_matrix(keyword):
    d = dict.fromkeys(string.ascii_lowercase, 0)
    matrix = []
    t = keyword + string.ascii_lowercase  # concatenate keyword with alphabet
    index = 0
    for i in range(0, 5):
        row = []
        for j in range(0, 5):
            while d[t[index]] != 0 or t[index] == 'j':  # skip 'j' and already used letters
                index += 1
            row.append(t[index])
            d[t[index]] += 1
            index += 1
        matrix.append(row)
    return matrix


# Prepare the input string by removing spaces and handling repeated letters and odd length
def prepare_input(plain_text):
    # Remove spaces and handle repeated letters
    plain_text = plain_text.replace(" ", "").lower()
    new_text = ''
    i = 0
    while i < len(plain_text):
        new_text += plain_text[i]
        if i + 1 < len(plain_text) and plain_text[i] == plain_text[i + 1]:
            new_text += 'x'  # Insert 'x' between repeated letters
        elif i + 1 == len(plain_text):  # If there's a single last character, add 'x'
            new_text += 'x'
        else:
            new_text += plain_text[i + 1]
        i += 2
    return new_text


# Playfair encryption process
def playfair_encrypt(plain_text, matrix):
    final = ''
    for i in range(0, len(plain_text) - 1, 2):
        a, b = getcord(matrix, plain_text[i])
        c, d = getcord(matrix, plain_text[i + 1])

        # Same row: shift right
        if a == c:
            final += matrix[a][(b + 1) % 5]
            final += matrix[c][(d + 1) % 5]
        # Same column: shift down
        elif b == d:
            final += matrix[(a + 1) % 5][b]
            final += matrix[(c + 1) % 5][d]
        # Rectangle case: swap corners
        else:
            final += matrix[a][d]
            final += matrix[c][b]

    return final.upper()


# Playfair decryption process
def playfair_decrypt(cipher_text, matrix):
    decrypted = ''
    for i in range(0, len(cipher_text) - 1, 2):
        a, b = getcord(matrix, cipher_text[i].lower())
        c, d = getcord(matrix, cipher_text[i + 1].lower())

        # Same row: shift left
        if a == c:
            decrypted += matrix[a][(b - 1) % 5]
            decrypted += matrix[c][(d - 1) % 5]
        # Same column: shift up
        elif b == d:
            decrypted += matrix[(a - 1) % 5][b]
            decrypted += matrix[(c - 1) % 5][d]
        # Rectangle case: swap corners
        else:
            decrypted += matrix[a][d]
            decrypted += matrix[c][b]

    return decrypted.lower()


# Input string and keyword
plain_text = "thekeyishiddenunderthedoorpad"
keyword = "guidance"

# Prepare the matrix and input text
matrix = create_matrix(keyword)
prepared_text = prepare_input(plain_text)

# Encrypt the message
cipher_text = playfair_encrypt(prepared_text, matrix)

# Decrypt the message
decrypted_text = playfair_decrypt(cipher_text, matrix)

# Display the matrix, encrypted text, and decrypted text
print("Playfair Matrix:")
for row in matrix:
    print(row)

print(f"Prepared Input: {prepared_text}")
print(f"Encrypted Output: {cipher_text}")
print(f"Decrypted Output: {decrypted_text}")
