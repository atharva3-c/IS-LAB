from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


patients_data = {}
doctors = {}
doctor_inboxes = {}



def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def patient_menu():
    patient_id = input("Enter Patient ID: ")

    if patient_id not in patients_data:

        private_key1, public_key1 = generate_rsa_keys()
        private_key2, public_key2 = generate_rsa_keys()

        level1_message = input("Enter Level 1 message: ").encode()
        level2_message = input("Enter Level 2 message: ").encode()

        cipher1 = PKCS1_OAEP.new(RSA.import_key(public_key1))
        encrypted_level1 = cipher1.encrypt(level1_message)

        cipher2 = PKCS1_OAEP.new(RSA.import_key(public_key2))
        encrypted_level2 = cipher2.encrypt(level2_message)

        patients_data[patient_id] = {
            "Level1": [encrypted_level1, private_key1],
            "Level2": [encrypted_level2, private_key2]
        }
        print(f"Messages for Patient {patient_id} stored securely.")
    else:
        print("Patient ID already exists!")


def doctor_menu():
    doctor_id = input("Enter Doctor ID: ")

    # Check if doctor exists, if not generate keys
    if doctor_id not in doctors:
        print(f"Doctor {doctor_id} not found. Generating keys...")
        private_key, public_key = generate_rsa_keys()
        doctors[doctor_id] = {'public_key': public_key, 'private_key': private_key}
        doctor_inboxes[doctor_id] = []
        print(f"Keys generated for Doctor {doctor_id}.")
    else:
        print(f"Welcome, Doctor {doctor_id}!")


    while True:
        print("\nDoctor Menu")
        print("1) View Inbox")
        print("2) Decrypt a message from inbox")
        print("3) Logout")

        choice = input("Enter your choice: ")
        if choice == "1":
            view_inbox(doctor_id)
        elif choice == "2":
            decrypt_message(doctor_id)
        elif choice == "3":
            print(f"Doctor {doctor_id} logged out.")
            break
        else:
            print("Invalid choice. Please try again.")


def view_inbox(doctor_id):
    inbox = doctor_inboxes.get(doctor_id, [])
    if not inbox:
        print(f"Inbox is empty for Doctor {doctor_id}.")
    else:
        for index, message in enumerate(inbox):
            print(f"Message {index}: {base64.b64encode(message).decode('utf-8')}")


def decrypt_message(doctor_id):
    inbox = doctor_inboxes.get(doctor_id, [])
    if not inbox:
        print(f"Inbox is empty for Doctor {doctor_id}.")
        return

    index = int(input(f"Enter the index of the message to decrypt (0-{len(inbox) - 1}): "))
    if index < 0 or index >= len(inbox):
        print("Invalid index. Please try again.")
        return

    encrypted_message = inbox[index]

    private_key = RSA.import_key(doctors[doctor_id]['private_key'])
    cipher_rsa = PKCS1_OAEP.new(private_key)

    try:
        decrypted_message = cipher_rsa.decrypt(encrypted_message).decode('utf-8')
        print(f"Decrypted Message: {decrypted_message}")
    except Exception as e:
        print(f"Error decrypting the message: {str(e)}")


def nurse_menu():
    patient_id = input("Enter Patient ID: ")

    if patient_id in patients_data:
        encrypted_level1, private_key1 = patients_data[patient_id]["Level1"]

        private_key = RSA.import_key(private_key1)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_level1 = cipher_rsa.decrypt(encrypted_level1).decode()

        print(f"Patient {patient_id} Level 1 Info: {decrypted_level1}")
    else:
        print(f"Patient {patient_id} not found!")

def lab_assistant_menu():
    print("\nLab Assistant Menu:")
    print("1) View All Encrypted Records")
    print("2) Request (Coming soon...)")

    choice = input("Enter your choice: ")

    if choice == "1":
        # View all encrypted records
        print("\n--- Encrypted Patient Records ---")
        for patient_id, data in patients_data.items():
            encrypted_level1, _ = data["Level1"]
            encrypted_level2, _ = data["Level2"]
            print(f"Patient {patient_id}:\n  Level 1 (Encrypted): {encrypted_level1.hex()}\n  Level 2 (Encrypted): {encrypted_level2.hex()}")
    elif choice == "2":
        print("Request: Hello (Coming soon...)")
    else:
        print("Invalid option!")


# Admin menu (placeholder)
def admin_menu():
    print("Admin: Hello (Admin functions coming soon)")


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
