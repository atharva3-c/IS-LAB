from Crypto.Util.number import bytes_to_long, long_to_bytes

# Simplified small RSA keys and numbers
p = 179  # Small prime
q = 199  # Small prime
n = p * q  # RSA modulus
e = 17  # Public exponent (usually a small prime number)
phi_n = (p - 1) * (q - 1)  # Euler's totient function
d = pow(e, -1, phi_n)  # Private exponent (modular inverse of e mod phi(n))

# Function to sign the message with private key (d, n)
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
    if m == verified_message:
        print("Signature is valid. The message has not been tampered with.")
    else:
        print("Signature is invalid. The message has been tampered with.")

# Example usage
def main():
    # Example message (should be a small string for this example)
    message = "ab"

    # Sign the message
    signature = sign_message(message)
    print(f"Original Message: {message}")
    print(f"Signature (as number): {signature}")

    # Verify the signature
    verify_signature(message, signature)

    # Example of tampered message
    tampered_message = "Bcfbf"
    print(f"\nTampered Message: {tampered_message}")
    verify_signature(tampered_message, signature)


if __name__ == "__main__":
    main()
