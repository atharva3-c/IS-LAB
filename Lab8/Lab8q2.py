import random
import math
from phe import paillier  # Paillier cryptosystem
import hashlib

# Step 2a: Generate a dataset of 10 documents
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

# Step 2b: Encryption and Decryption using Paillier cryptosystem
# Generate Paillier public and private keys
public_key, private_key = paillier.generate_paillier_keypair()

def encrypt_data(public_key, data):
    """Encrypts data using Paillier public key."""
    return public_key.encrypt(data)

def decrypt_data(private_key, encrypted_data):
    """Decrypts data using Paillier private key."""
    return private_key.decrypt(encrypted_data)

# Step 2c: Create an encrypted inverted index
def create_encrypted_inverted_index(documents, public_key):
    """Create an encrypted inverted index using Paillier cryptosystem."""
    index = {}
    for doc_id, doc in documents.items():
        for word in doc.split():
            if word not in index:
                index[word] = []
            index[word].append(doc_id)

    # Encrypt the index: Hash words and encrypt document IDs
    encrypted_index = {}
    for word, doc_ids in index.items():
        # Hash the word (use its SHA-256 hash for deterministic encryption)
        word_hash = hashlib.sha256(word.encode()).hexdigest()

        # Encrypt document IDs associated with the word using Paillier encryption
        encrypted_doc_ids = [encrypt_data(public_key, int(doc_id[3:])) for doc_id in doc_ids]
        encrypted_index[word_hash] = encrypted_doc_ids

    return encrypted_index

# Step 2d: Implement the search function
def search_encrypted_index(encrypted_index, query, public_key, private_key):
    """Search the encrypted index for a query and decrypt the matching document IDs."""
    query_hash = hashlib.sha256(query.encode()).hexdigest()

    matching_docs = []
    if query_hash in encrypted_index:
        encrypted_doc_ids = encrypted_index[query_hash]
        # Decrypt the document IDs
        decrypted_doc_ids = [decrypt_data(private_key, doc_id) for doc_id in encrypted_doc_ids]
        matching_docs.extend(decrypted_doc_ids)

    return [f"doc{doc_id}" for doc_id in matching_docs]

# Example usage
if __name__ == "__main__":
    # Step 2c: Create and encrypt the inverted index
    encrypted_index = create_encrypted_inverted_index(documents, public_key)

    # Step 2d: Perform search query
    query = "fox"
    results = search_encrypted_index(encrypted_index, query, public_key, private_key)

    if results:
        print(f"Documents containing the word '{query}': {results}")
    else:
        print(f"No documents found for the word '{query}'.")
