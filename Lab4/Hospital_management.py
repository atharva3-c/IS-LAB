from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Data storage dictionaries
patients_data = {}
rsa_keys = {}
lab_requests = []  # List to store requested patient IDs by Lab Assistant
granted_access = []  # Public list to store IDs for which access has been granted

# Nurse's keys for signing
nurse_private_key = None
nurse_public_key = None

# Admin
def generate_rsa_keys():
    """Generates RSA private and public keys"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Nurse's signature (for testing, we'll sign with "nurse" message)
def sign_message(private_key, message):
    """Signs the message using RSA private key"""
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    """Verifies the signature using RSA public key"""
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

# Encryption
def rsa_encrypt(public_key, message):
    """Encrypts message using RSA public key"""
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return ciphertext

# Decryption
def rsa_decrypt(private_key, ciphertext):
    """Decrypts ciphertext using RSA private key"""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return plaintext.decode()

# Menu for Patient
def patient_menu():
    patient_id = input("Enter Patient ID: ")

    if patient_id not in patients_data:
        # Generate keys for Level 1 and Level 2
        private_key1, public_key1 = generate_rsa_keys()
        private_key2, public_key2 = generate_rsa_keys()

        rsa_keys[patient_id] = {"Level1": (private_key1, public_key1), "Level2": (private_key2, public_key2)}

        # Collect message for Level 1 and Level 2
        level1_message = input("Enter Level 1 message: ").encode()
        level2_message = input("Enter Level 2 message: ").encode()

        # Encrypt and store
        encrypted_level1 = rsa_encrypt(public_key1, level1_message)
        encrypted_level2 = rsa_encrypt(public_key2, level2_message)

        # Update patient data with "not signed" status and no signature yet
        patients_data[patient_id] = {
            "Level1": [encrypted_level1, private_key1, "not signed", None],
            "Level2": [encrypted_level2, private_key2, "not signed", None]
        }
        print(f"Messages for {patient_id} encrypted and stored.")
    else:
        print("Patient ID already exists! You cannot re-enter information.")

# Menu for Doctor
def doctor_menu():
    patient_id = input("Enter Patient ID: ")

    if patient_id in patients_data:
        # Decrypt both Level 1 and Level 2
        encrypted_level1, private_key1, signature_status1, signature1 = patients_data[patient_id]["Level1"]
        encrypted_level2, private_key2, signature_status2, signature2 = patients_data[patient_id]["Level2"]

        decrypted_level1 = rsa_decrypt(private_key1, encrypted_level1)
        decrypted_level2 = rsa_decrypt(private_key2, encrypted_level2)

        print(f"\n--- Patient {patient_id} Information ---")
        print(f"Level 1: {decrypted_level1} (Status: {signature_status1})")
        print(f"Level 2: {decrypted_level2} (Status: {signature_status2})")

        if signature_status1 == "signed":
            verify_level = input("Do you want to verify Level 1? (yes/no): ")
            if verify_level.lower() == "yes":
                if verify_signature(nurse_public_key, decrypted_level1.encode(), signature1):
                    print("Level 1 signature is valid.")
                else:
                    print("Level 1 signature is invalid.")
    else:
        print(f"Patient ID {patient_id} not found!")

# Menu for Nurse (only decrypt Level 1, option to sign message)
def nurse_menu():
    patient_id = input("Enter Patient ID: ")

    if patient_id in patients_data:
        # Decrypt Level 1 only
        encrypted_level1, private_key1, _, _ = patients_data[patient_id]["Level1"]
        decrypted_level1 = rsa_decrypt(private_key1, encrypted_level1)

        print(f"\n--- Patient {patient_id} Information ---")
        print(f"Level 1: {decrypted_level1}")

        # Option to sign message
        sign_choice = input("Do you want to sign this message? (yes/no): ")
        if sign_choice.lower() == "yes":
            signature1 = sign_message(nurse_private_key, decrypted_level1.encode())
            patients_data[patient_id]["Level1"][2] = "signed"
            patients_data[patient_id]["Level1"][3] = signature1  # Store the signature
            print("Message signed by Nurse.")
    else:
        print(f"Patient ID {patient_id} not found!")

# Menu for Lab Assistant
def lab_assistant_menu():
    print("\n--- Lab Assistant Menu ---")
    print("1) View Encrypted Records")
    print("2) Request Access")

    choice = input("Enter your choice: ")

    if choice == "1":
        print("\n--- Encrypted Records ---")
        for patient_id, records in patients_data.items():
            if patient_id in granted_access:
                encrypted_level1, private_key1, _, _ = records["Level1"]
                encrypted_level2, private_key2, _, _ = records["Level2"]

                decrypted_level1 = rsa_decrypt(private_key1, encrypted_level1)
                decrypted_level2 = rsa_decrypt(private_key2, encrypted_level2)

                print(f"Patient {patient_id}:\n  Level 1 (Decrypted): {decrypted_level1}\n  Level 2 (Decrypted): {decrypted_level2}")
            else:
                encrypted_level1, _, _, _ = records["Level1"]
                encrypted_level2, _, _, _ = records["Level2"]
                print(f"Patient {patient_id}:\n  Level 1 (Encrypted): {encrypted_level1.hex()}\n  Level 2 (Encrypted): {encrypted_level2.hex()}")

    elif choice == "2":
        patient_id = input("Enter Patient ID to request access: ")
        lab_requests.append(patient_id)
        print(f"Request for access to patient {patient_id} sent to Admin.")

# Admin Menu
def admin_menu():
    print("\n--- Admin Menu ---")
    print("1) View Requests")
    print("2) Grant Access")

    choice = input("Enter your choice: ")

    if choice == "1":
        print("\n--- Requests ---")
        if not lab_requests:
            print("No requests.")
        else:
            for request in lab_requests:
                print(f"Requested Patient ID: {request}")

    elif choice == "2":
        patient_id = input("Enter Patient ID to grant access: ")
        if patient_id in lab_requests:
            granted_access.append(patient_id)
            lab_requests.remove(patient_id)
            print(f"Access granted for patient {patient_id}.")
        else:
            print(f"No request found for patient {patient_id}.")

# Main Menu
def main_menu():
    global nurse_private_key, nurse_public_key
    nurse_private_key, nurse_public_key = generate_rsa_keys()  # Nurse's keys for signing

    while True:
        print("\n--- SecureHospital System ---")
        print("1) Patient")
        print("2) Doctor")
        print("3) Nurse")
        print("4) Lab Assistant")
        print("5) Admin")
        print("6) Exit")

        choice = input("Select a role: ")

        if choice == "1":
            patient_menu()
        elif choice == "2":
            doctor_menu()
        elif choice == "3":
            nurse_menu()
        elif choice == "4":
            lab_assistant_menu()
        elif choice == "5":
            admin_menu()
        elif choice == "6":
            print("Exiting the system.")
            break
        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main_menu()
