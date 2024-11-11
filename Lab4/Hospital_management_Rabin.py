import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse, GCD
from math import gcd

# Data storage dictionaries
patients_data = {}
rabin_keys = {}
lab_requests = []
granted_access = []


def rabin_encrypt(public_key, message):

    n = public_key
    m = bytes_to_long(message)
    ciphertext = pow(m, 2, n)
    return ciphertext

def rabin_decrypt(private_key, ciphertext):

    p, q = private_key
    n = p * q

    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)

    g, yp, yq = GCD(p, q), inverse(p, q), inverse(q, p)
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3

    for r in [r1, r2, r3, r4]:
        try:
            decoded = long_to_bytes(r).decode()
            if decoded.isprintable():
                return decoded
        except:
            continue
    return None

def generate_rabin_keys(bits=512):

    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p % 4 == 3 and q % 4 == 3:
            break
    n = p * q
    return (p, q), n

# Menu
def patient_menu():
    patient_id = input("Enter Patient ID: ")

    if patient_id not in patients_data:

        private_key1, public_key1 = generate_rabin_keys()
        private_key2, public_key2 = generate_rabin_keys()

        rabin_keys[patient_id] = {"Level1": public_key1, "Level2": public_key2}


        level1_message = input("Enter Level 1 message: ").encode()
        level2_message = input("Enter Level 2 message: ").encode()


        encrypted_level1 = rabin_encrypt(public_key1, level1_message)
        encrypted_level2 = rabin_encrypt(public_key2, level2_message)


        patients_data[patient_id] = {
            "Level1": [encrypted_level1, private_key1, "not signed", None],
            "Level2": [encrypted_level2, private_key2, "not signed", None]
        }
        print(f"Messages for {patient_id} encrypted and stored.")
    else:
        print("Patient ID already exists! You cannot re-enter information.")

# Menu
def doctor_menu():
    patient_id = input("Enter Patient ID: ")

    if patient_id in patients_data:
        # Decrypt both Level 1 and Level 2
        encrypted_level1, private_key1, signature_status1, signature1 = patients_data[patient_id]["Level1"]
        encrypted_level2, private_key2, signature_status2, signature2 = patients_data[patient_id]["Level2"]

        decrypted_level1 = rabin_decrypt(private_key1, encrypted_level1)
        decrypted_level2 = rabin_decrypt(private_key2, encrypted_level2)

        print(f"\n--- Patient {patient_id} Information ---")
        print(f"Level 1: {decrypted_level1} (Status: {signature_status1})")
        print(f"Level 2: {decrypted_level2} (Status: {signature_status2})")

    else:
        print(f"Patient ID {patient_id} not found!")

# Menu for Nurse (only decrypt Level 1, option to sign message)
def nurse_menu():
    patient_id = input("Enter Patient ID: ")

    if patient_id in patients_data:
        # Decrypt Level 1 only
        encrypted_level1, private_key1, _, _ = patients_data[patient_id]["Level1"]
        decrypted_level1 = rabin_decrypt(private_key1, encrypted_level1)

        print(f"\n--- Patient {patient_id} Information ---")
        print(f"Level 1: {decrypted_level1}")

        # Option to sign message
        sign_choice = input("Do you want to sign this message? (yes/no): ")
        if sign_choice.lower() == "yes":
            patients_data[patient_id]["Level1"][2] = "signed"
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

                decrypted_level1 = rabin_decrypt(private_key1, encrypted_level1)
                decrypted_level2 = rabin_decrypt(private_key2, encrypted_level2)

                print(f"Patient {patient_id}:\n  Level 1 (Decrypted): {decrypted_level1}\n  Level 2 (Decrypted): {decrypted_level2}")
            else:
                encrypted_level1, _, _, _ = records["Level1"]
                encrypted_level2, _, _, _ = records["Level2"]
                print(f"Patient {patient_id}:\n  Level 1 (Encrypted): {encrypted_level1}\n  Level 2 (Encrypted): {encrypted_level2}")

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
