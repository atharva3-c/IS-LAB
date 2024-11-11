from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import os

# Global Lists and Dictionaries
registered_users = []
encrypted_users = []
user_signatures = {}

# Generate RSA Key Pair for Signing and Encryption
pub_key, priv_key = RSA.generate(1024), RSA.generate(1024)
aes_key = get_random_bytes(32)  # AES-256 key for Level 2 encryption


# Helper Functions
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce, ciphertext, tag


def rsa_encrypt(pub_key, message):
    if message >= pub_key.n:
        raise ValueError("Message must be less than modulus n")
    return pow(message, pub_key.e, pub_key.n)


def rsa_decrypt(priv_key, ciphertext):
    return pow(ciphertext, priv_key.d, priv_key.n)


def homomorphic_multiply(ciphertext1, ciphertext2, pub_key):
    return (ciphertext1 * ciphertext2) % pub_key.n


# Menu Functions
def enter_info():
    user_id = input("Enter User ID: ")
    if user_id in registered_users:
        print("User ID already entered.")
        return
    registered_users.append(user_id)

    level_1_info = input("Enter Level 1 security information: ")
    level_2_info = input("Enter Level 2 security info: ")
    number1 = int(input("Enter Number 1: "))
    number2 = int(input("Enter Number 2: "))

    filename = f"file_{user_id}_plaintext.txt"
    with open(filename, "w") as file:
        file.write(f"{level_1_info}\n")
        file.write(f"{level_2_info}\n")
        file.write(f"{number1}\n")
        file.write(f"{number2}\n")

    print(f"Data for User ID {user_id} has been saved to {filename}")


def encrypt_data():
    user_id = input("Enter User ID for encryption: ")
    if user_id in encrypted_users:
        print("Encryption already done for this user.")
        return
    if user_id not in registered_users:
        print("User ID not found. Please enter info first.")
        return

    encrypted_users.append(user_id)
    filename_plain = f"file_{user_id}_plaintext.txt"
    filename_enc = f"file_{user_id}_encrypted.txt"

    with open(filename_plain, "r") as file:
        lines = file.readlines()
        level_1_info = lines[0].strip()
        level_2_info = lines[1].strip()
        number1 = int(lines[2].strip())
        number2 = int(lines[3].strip())

    nonce, aes_ciphertext, aes_tag = aes_encrypt(level_2_info, aes_key)
    ciphertext_number1 = rsa_encrypt(pub_key, number1)
    ciphertext_number2 = rsa_encrypt(pub_key, number2)
    ciphertext_product = homomorphic_multiply(ciphertext_number1, ciphertext_number2, pub_key)

    with open(filename_enc, "w") as file:
        file.write(f"{level_1_info}\n")
        file.write(f"AES Encrypted Level 2 info: {aes_ciphertext.hex()}\n")
        file.write(f"RSA Encrypted Number1: {hex(ciphertext_number1)}\n")
        file.write(f"RSA Encrypted Number2: {hex(ciphertext_number2)}\n")
        file.write(f"Product of Number1 and Number2 (Encrypted): {hex(ciphertext_product)}\n")

    print(f"Encryption for User ID {user_id} has been saved to {filename_enc}")


def sign_info():
    user_id = input("Enter User ID for signing: ")
    if user_id not in registered_users:
        print("User ID not found.")
        return

    if user_id in user_signatures and user_signatures[user_id]["status"] == "signed":
        print("Already signed.")
        return

    filename = f"file_{user_id}_plaintext.txt"
    with open(filename, "r") as file:
        level_1_info = file.readline().strip()

    hasher = SHA256.new(level_1_info.encode())
    signature = pkcs1_15.new(priv_key).sign(hasher)

    user_signatures[user_id] = {
        "status": "signed",
        "signature": signature,
        "hash": hasher.hexdigest()
    }

    print(f"Level 1 info for User ID {user_id} has been signed and stored.")


def view_status():
    user_id = input("Enter User ID to view status: ")
    if user_id not in registered_users:
        print("User ID not created.")
        return

    encryption_status = "yes" if user_id in encrypted_users else "no"
    signing_status = "signed" if user_id in user_signatures and user_signatures[user_id][
        "status"] == "signed" else "unsigned"

    print(f"Encryption done: {encryption_status}")
    print(f"Signature status: {signing_status}")


def get_homomorphic_product():
    user_id = input("Enter User ID to get homomorphic product: ")
    if user_id not in encrypted_users:
        print("Encryption has not been done for this user.")
        return

    filename_enc = f"file_{user_id}_encrypted.txt"
    with open(filename_enc, "r") as file:
        lines = file.readlines()
        ciphertext_number1 = int(lines[2].strip().split(": ")[1], 16)
        ciphertext_number2 = int(lines[3].strip().split(": ")[1], 16)
        ciphertext_product = int(lines[4].strip().split(": ")[1], 16)

    # Decrypt the product to verify the result
    decrypted_product = rsa_decrypt(priv_key, ciphertext_product)
    print(f"Homomorphic Product of Number1 and Number2 (Decrypted): {decrypted_product}")


# Main Menu
def main_menu():
    while True:
        print("\n--- Menu ---")
        print("1. Enter Info")
        print("2. Encrypt Data")
        print("3. Sign Info")
        print("4. View Status")
        print("5. Get Homomorphic Product")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            enter_info()
        elif choice == '2':
            encrypt_data()
        elif choice == '3':
            sign_info()
        elif choice == '4':
            view_status()
        elif choice == '5':
            get_homomorphic_product()
        elif choice == '6':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please select a valid option.")


# Run the main menu
if __name__ == "__main__":
    main_menu()
