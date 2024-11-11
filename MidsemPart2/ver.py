from Crypto.Util.number import bytes_to_long, long_to_bytes

# Simplified small RSA keys and numbers
p = 179  # Small prime
q = 199  # Small prime
n = p * q  # RSA modulus
e = 17  # Public exponent (usually a small prime number)
phi_n = (p - 1) * (q - 1)  # Euler's totient function
d = pow(e, -1, phi_n)  # Private exponent (modular inverse of e mod phi(n))

# Global dictionary to hold information
documents = {}
status = {}  # To store whether each document is signed and verified


# Function to sign a message
def sign_message(message):
    # Convert message to a number (ASCII or simple number for small example)
    m = bytes_to_long(message.encode('utf-8'))

    # Sign by raising the message to the power of d mod n
    signature = pow(m, d, n)
    return signature


# Function to verify the signature with public key (e, n)
def verify_signature(message, signature):
    # Convert message to a number
    m = bytes_to_long(message.encode('utf-8'))

    # Verify by raising the signature to the power of e mod n
    verified_message = pow(signature, e, n)

    # Compare the original message and the verified message
    return m == verified_message


# Function to add information to the dictionary
def add_information():
    info = input("Enter the information to add: ")
    doc_id = f"Doc{len(documents) + 1}"
    documents[doc_id] = info
    status[doc_id] = {'signed': False, 'verified': False, 'signature': None}
    print(f"Information added with ID: {doc_id}")


# Function to sign a document by its ID
def signer():
    doc_id = input("Enter the document ID to sign: ")
    if doc_id in documents:
        signature = sign_message(documents[doc_id])
        status[doc_id]['signed'] = True
        status[doc_id]['signature'] = signature
        print(f"Document {doc_id} signed.")
    else:
        print(f"Document {doc_id} not found.")


# Function to verify a document by its ID
def verifier():
    doc_id = input("Enter the document ID to verify: ")
    if doc_id in documents and status[doc_id]['signed']:
        signature = status[doc_id]['signature']
        if verify_signature(documents[doc_id], signature):
            status[doc_id]['verified'] = True
            print(f"Document {doc_id} verified successfully.")
        else:
            print("Signature verification failed.")
    else:
        print(f"Document {doc_id} not found or not signed.")


# Function to view a document and its status
def viewer():
    doc_id = input("Enter the document ID to view: ")
    if doc_id in documents:
        doc_value = documents[doc_id]
        doc_status = status[doc_id]
        signed = doc_status['signed']
        verified = doc_status['verified']
        print(f"Document {doc_id}: {doc_value}")
        print(f"Signed: {signed}, Verified: {verified}")
    else:
        print(f"Document {doc_id} not found.")


# Main menu function
def menu():
    while True:
        print("\n--- Menu ---")
        print("1) Signer")
        print("2) Verifier")
        print("3) Viewer")
        print("4) Add Information")
        print("5) Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            signer()
        elif choice == '2':
            verifier()
        elif choice == '3':
            viewer()
        elif choice == '4':
            add_information()
        elif choice == '5':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")


# Run the program
if __name__ == "__main__":
    menu()
