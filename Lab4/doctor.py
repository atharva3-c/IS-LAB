from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64


# Data structures to store doctors, their keys, and inboxes
doctors = {}
doctor_inboxes = {}


# Function to generate RSA keys and store them for a doctor
def generate_keys_for_doctor(doctor_id):
    # Generate RSA keys for the doctor
    key = RSA.generate(1024)  # 1024-bit RSA key
    public_key = key.publickey().export_key()
    private_key = key.export_key()

    doctors[doctor_id] = {
        'public_key': public_key,
        'private_key': private_key
    }
    doctor_inboxes[doctor_id] = []  # Initialize an empty inbox for the doctor


# Function for doctor login
def doctor_login():
    doctor_id = input("Enter Doctor ID: ")

    # Check if doctor exists, if not, generate keys
    if doctor_id not in doctors:
        print(f"Doctor {doctor_id} not found. Generating keys...")
        generate_keys_for_doctor(doctor_id)

    # Doctor menu options
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


# Function to view the doctor's inbox
def view_inbox(doctor_id):
    inbox = doctor_inboxes.get(doctor_id, [])
    if not inbox:
        print(f"Inbox is empty for Doctor {doctor_id}.")
    else:
        for index, message in enumerate(inbox):
            print(f"Message {index}: {base64.b64encode(message).decode('utf-8')}")


# Function to decrypt a message in the inbox
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


# Function for patient login
def patient_login():
    patient_id = input("Enter Patient ID: ")
    doctor_id = input("Enter Doctor ID: ")

    # Check if the doctor exists
    if doctor_id not in doctors:
        print(f"Doctor {doctor_id} does not exist.")
        return

    # Get the doctor's public key
    public_key = RSA.import_key(doctors[doctor_id]['public_key'])

    # Enter the message and encrypt it
    message = input("Enter the message to send: ")
    message=f"Patient{patient_id}  :"+message
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))

    # Add the encrypted message to the doctor's inbox
    doctor_inboxes[doctor_id].append(encrypted_message)
    print(f"Message sent to Doctor {doctor_id}'s inbox.")


# Main menu loop
def main_menu():
    while True:
        print("\nMain Menu")
        print("1) Doctor Login")
        print("2) Patient Login")
        print("3) Exit")

        choice = input("Enter your choice: ")
        if choice == "1":
            doctor_login()
        elif choice == "2":
            patient_login()
        elif choice == "3":
            print("Exiting system...")
            exit(0)
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main_menu()
