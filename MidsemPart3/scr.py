from Crypto.PublicKey import RSA


def generate_rsa_keys():
    # Generate RSA keys
    key = RSA.generate(2048)

    # Export the public and private keys
    private_key = key.export_key()
    with open('private.pem', 'wb') as private_file:
        private_file.write(private_key)

    public_key = key.publickey().export_key()
    with open('public.pem', 'wb') as public_file:
        public_file.write(public_key)

    print("RSA Keys generated and saved as 'public.pem' and 'private.pem'")


# Call the function to generate and save the keys
generate_rsa_keys()
