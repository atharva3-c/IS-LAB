from Crypto.Util.number import getPrime, inverse, GCD
from math import isqrt
import random


# Step 1: RSA Key Generation with small primes
def generate_weak_rsa_key(bits=16):
    """Generate weak RSA keys with small prime factors."""
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    e = 65537  # Commonly used public exponent
    phi_n = (p - 1) * (q - 1)

    # Ensure that e and phi_n are coprime
    if GCD(e, phi_n) != 1:
        return generate_weak_rsa_key(bits)

    # Compute the private exponent
    d = inverse(e, phi_n)
    return (e, d, n, p, q)


# Step 2: Factorization attack to recover p and q from n (Brute-force Fermat's method)
def factor_rsa_modulus(n):
    """Attempt to factor n using Fermat's factorization method with brute-force steps."""
    print(f"\nEve is attempting to factor n = {n} using brute force...")

    a = isqrt(n) + 1
    b2 = a * a - n
    steps = 0

    # Brute-force search for p and q
    while isqrt(b2) * isqrt(b2) != b2:
        print(f"Step {steps}: Trying a = {a}, b^2 = {b2}... No factor found yet.")
        a += 1
        b2 = a * a - n
        steps += 1

    print(f"Factorization successful after {steps} steps!")
    p = a - isqrt(b2)
    q = a + isqrt(b2)
    return p, q


# Step 3: Private key recovery from factorized primes
def recover_private_key(e, n, p, q):
    """Recover the private exponent d from p, q, and e."""
    phi_n = (p - 1) * (q - 1)
    d = inverse(e, phi_n)
    return d


# Step 4: Simulate Eve's attack
def demonstrate_rsa_attack():
    print("Generating weak RSA key...")
    e, d, n, p, q = generate_weak_rsa_key()
    print(f"Generated keys: n={n}, e={e}, d={d}")
    print(f"p={p}, q={q}")

    print("\nEve has intercepted the public key (n, e) and is attempting to factor n...")
    p_recovered, q_recovered = factor_rsa_modulus(n)

    print(f"Recovered factors: p={p_recovered}, q={q_recovered}")

    print("\nNow Eve will use the recovered factors to compute the private key...")
    d_recovered = recover_private_key(e, n, p_recovered, q_recovered)

    print(f"Recovered private key: d={d_recovered}")
    if d_recovered == d:
        print("\nAttack successful: Eve has recovered the private key!")
    else:
        print("\nAttack failed: Eve could not recover the private key.")


# Step 5: Mitigation discussion
def mitigation_discussion():
    print("\nMitigation steps:")
    print("- Ensure that RSA prime factors p and q are large (at least 2048 bits).")
    print("- Use cryptographically secure random number generators to generate p and q.")
    print("- Periodically rotate keys to ensure long-term security.")
    print(
        "- Consider using stronger encryption algorithms such as ECC (Elliptic Curve Cryptography) for better security.")


# Execute the attack demonstration
if __name__ == "__main__":
    demonstrate_rsa_attack()
    mitigation_discussion()
