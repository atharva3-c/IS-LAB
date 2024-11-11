from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes
import base64

# Step 1: Generate RSA keys (private and public)
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Step 2: Hash the message and sign (encrypt the hash with private key)
def sign_message(private_key, message):
    # Hash the message
    hashed_message = SHA256.new(message.encode('utf-8')).digest()

    # Convert the hash to an integer
    hashed_message_int = bytes_to_long(hashed_message)

    # Sign the message by encrypting the hash with the private key
    rsa_private_key = RSA.import_key(private_key)
    signature_int = pow(hashed_message_int, rsa_private_key.d, rsa_private_key.n)  # Manual RSA signing

    # Convert the signature to bytes
    signature = long_to_bytes(signature_int)
    return signature

# Step 3: Verify the signature by decrypting it with the public key and comparing the hash
def verify_signature(public_key, message, signature):
    # Hash the message
    expected_hash = SHA256.new(message.encode('utf-8')).digest()

    # Convert signature from bytes to integer
    signature_int = bytes_to_long(signature)

    # Decrypt the signature using the public key
    rsa_public_key = RSA.import_key(public_key)
    decrypted_hash_int = pow(signature_int, rsa_public_key.e, rsa_public_key.n)  # Manual RSA verification

    # Convert the decrypted hash back to bytes
    decrypted_hash = long_to_bytes(decrypted_hash_int)

    # Compare the decrypted hash with the expected hash
    if decrypted_hash == expected_hash:
        print("Signature is valid. The message has not been tampered with.")
    else:
        print("Signature is invalid. The message has been tampered with.")

# Example usage
def main():
    # Step 1: Generate RSA key pair
    private_key, public_key = generate_rsa_keys()

    # Example message (e.g., name of the signer)
    message = "DoctorName123"

    # Step 2: Sign the message with the private key
    signature = sign_message(private_key, message)

    # Step 3: Verify the signature with the public key
    print(f"Original Message: {message}")
    print(f"Signature (base64): {base64.b64encode(signature).decode()}")

    # Step 4: Verifying the message using the public key
    verify_signature(public_key, message, signature)

    # Example of tampered message
    tampered_message = "DoctorName124"
    print(f"\nTampered Message: {tampered_message}")
    verify_signature(public_key, tampered_message, signature)


if __name__ == "__main__":
    main()
