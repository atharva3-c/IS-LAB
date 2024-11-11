from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Step 1: Generate RSA keys for signer
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Step 2: Sign a message (e.g., Signer name) using the private key
def sign_message(private_key, message):
    rsa_private_key = RSA.import_key(private_key)
    h = SHA256.new(message.encode('utf-8'))  # Create hash of the message
    signature = pkcs1_15.new(rsa_private_key).sign(h)  # Create the signature
    return signature

# Step 3: Verify the signature using the public key
def verify_signature(public_key, message, signature):
    rsa_public_key = RSA.import_key(public_key)
    h = SHA256.new(message.encode('utf-8'))  # Create hash of the message

    try:
        pkcs1_15.new(rsa_public_key).verify(h, signature)
        print("Signature is valid. The message has not been tampered with.")
    except (ValueError, TypeError):
        print("Signature is invalid. The message has been tampered with.")

# Example usage
def main():
    # Step 1: Generate RSA key pair (private and public)
    private_key, public_key = generate_rsa_keys()

    # Example message (e.g., name of the signer)
    message = "DoctorName123"

    # Step 2: Sign the message with the private key
    signature = sign_message(private_key, message)

    # Step 3: Verify the signature with the public key
    print(f"Original Message: {message}")
    print(f"Signature (hex): {signature.hex()}")

    # Step 4: Verifying the message using the public key
    verify_signature(public_key, message, signature)

    # Example of tampered message:
    tampered_message = "DoctorName124"
    print(f"\nTampered Message: {tampered_message}")
    verify_signature(public_key, tampered_message, signature)

if __name__ == "__main__":
    main()
