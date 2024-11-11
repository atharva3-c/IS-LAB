import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib


# AES Encryption and Decryption functions
def encrypt_data(key, data, iv=None):
    """Encrypts data using AES (CBC mode). If IV is provided, use it, otherwise generate a new one."""
    if iv is None:
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
    else:
        cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv, ciphertext


def decrypt_data(key, iv, ciphertext):
    """Decrypts ciphertext using AES (CBC mode)."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()


# Step 1a: Generate a Dataset of 10 Documents
documents = {
    "doc1": "the quick brown fox jumps over the lazy dog",
    "doc2": "the sky is blue and the sun is bright",
    "doc3": "the dog chased the cat",
    "doc4": "the cat climbed the tree",
    "doc5": "the fox and the dog became friends",
    "doc6": "the sun sets in the west",
    "doc7": "the tree provides shade and shelter",
    "doc8": "the cat jumped over the fence",
    "doc9": "the dog barked at the stranger",
    "doc10": "the fox hunts during the night"
}


# Step 1c: Create an Inverted Index and Encrypt it
def create_inverted_index(documents, key):
    """Create an inverted index and encrypt it."""
    index = {}
    for doc_id, doc in documents.items():
        for word in doc.split():
            word_hash = hashlib.sha256(word.encode()).digest()
            if word_hash not in index:
                index[word_hash] = []
            index[word_hash].append(doc_id)

    # Encrypt the index
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        # Use a fixed IV for word encryption to ensure deterministic encryption
        fixed_iv = b'\x00' * 16  # Deterministic IV for word encryption
        encrypted_word_hash = encrypt_data(key, word_hash.hex(), fixed_iv)[1]
        encrypted_doc_ids = []

        for doc_id in doc_ids:
            iv, encrypted_doc_id = encrypt_data(key, doc_id)  # Random IV for doc IDs
            encrypted_doc_ids.append(iv + encrypted_doc_id)  # Combine IV and encrypted ID
        encrypted_index[encrypted_word_hash] = encrypted_doc_ids

    return encrypted_index


# Step 1d: Implement the Search Function
def search_in_encrypted_index(encrypted_index, query, key):
    """Search the encrypted index for matching query terms."""
    query_hash = hashlib.sha256(query.encode()).digest()

    # Use the same fixed IV for query encryption to ensure deterministic encryption
    fixed_iv = b'\x00' * 16
    encrypted_query_hash = encrypt_data(key, query_hash.hex(), fixed_iv)[1]

    matching_docs = []
    for encrypted_word, encrypted_doc_ids in encrypted_index.items():
        if encrypted_word == encrypted_query_hash:
            # Decrypt the document IDs
            for encrypted_doc_id in encrypted_doc_ids:
                iv = encrypted_doc_id[:AES.block_size]
                doc_id_ciphertext = encrypted_doc_id[AES.block_size:]
                decrypted_doc_id = decrypt_data(key, iv, doc_id_ciphertext)
                matching_docs.append(decrypted_doc_id)

    return matching_docs


# Example usage
if __name__ == "__main__":
    # Step 1b: Generate AES Key
    key = get_random_bytes(16)

    # Step 1c: Create and Encrypt the Inverted Index
    encrypted_index = create_inverted_index(documents, key)

    # Step 1d: Perform Search Query
    query = "fox"
    results = search_in_encrypted_index(encrypted_index, query, key)

    if results:
        print(f"Documents containing the word '{query}': {results}")
    else:
        print(f"No documents found for the word '{query}'.")
