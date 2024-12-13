# # Diffie-Hellman Key Exchange Implementation in Python

# This code implements the **Diffie-Hellman Key Exchange**, a cryptographic protocol that allows two parties (Alice and Bob) to establish a shared secret key over an insecure channel. Here's an explanation of how it works:

# ### Key Components:

# 1. **Prime Number (`prime`) and Base (`base`)**:
#    - **Prime Number**: A large prime number agreed upon by both Alice and Bob.
#    - **Base**: Also known as the generator or primitive root modulo prime. This is a number less than the prime that serves as the base for the calculations.

# 2. **Private Key**:
#    - Each party (Alice and Bob) generates their own **private key**, which is a random number less than the prime number.

# 3. **Public Key**:
#    - Using their private key and the base number, each party computes a **public key** using the formula:
#      \[
#      \text{Public Key} = (\text{Base})^{\text{Private Key}} \mod \text{Prime}
#      \]
#    - The public keys are shared with the other party.

# 4. **Shared Secret**:
#    - After exchanging public keys, Alice and Bob can each compute the **shared secret** using the other's public key and their own private key:
#      \[
#      \text{Shared Secret} = (\text{Public Key})^{\text{Private Key}} \mod \text{Prime}
#      \]
#    - The result will be the same for both Alice and Bob, allowing them to establish a secure shared secret that only they know.

# ### Functions Explained:

# 1. **`generate_private_key(prime)`**:
#    - Generates a random private key (a number between 1 and `prime - 1`) for each party.

# 2. **`compute_public_key(private_key, base, prime)`**:
#    - Computes the public key using the formula: \((\text{Base})^{\text{Private Key}} \mod \text{Prime}\).

# 3. **`compute_shared_secret(public_key_other, private_key, prime)`**:
#    - Computes the shared secret using the other party's public key and the user's private key: \((\text{Public Key})^{\text{Private Key}} \mod \text{Prime}\).

# ### Workflow:

# 1. **Prime Number and Base**: 
#    - The user inputs a large prime number and a base (primitive root modulo the prime).

# 2. **Private Key Generation**:
#    - Both Alice and Bob generate their own private keys using `generate_private_key`.

# 3. **Public Key Calculation**:
#    - Alice and Bob compute their public keys based on their private keys using `compute_public_key`.

# 4. **Shared Secret Calculation**:
#    - Using each other's public keys, Alice and Bob compute the shared secret using `compute_shared_secret`.

# 5. **Verification**:
#    - The shared secrets computed by Alice and Bob should be identical. The program checks if they match, indicating that the Diffie-Hellman key exchange was successful.

# ### Example:

# Assume:
# - `prime = 23` (a small prime number for illustration purposes).
# - `base = 5` (a primitive root modulo 23).

# #### Key Exchange Process:
# 1. **Private Keys**:
#    - Alice's private key is a random number, say `6`.
#    - Bob's private key is another random number, say `15`.

# 2. **Public Keys**:
#    - Alice's public key: \(5^6 \mod 23 = 8\).
#    - Bob's public key: \(5^{15} \mod 23 = 19\).

# 3. **Shared Secret**:
#    - Alice computes: \(19^6 \mod 23 = 2\).
#    - Bob computes: \(8^{15} \mod 23 = 2\).

# Both Alice and Bob compute the same shared secret (`2`), which they can use as a key for further secure communication.

# ## Python Code :

# ``` python
import random

def generate_private_key(prime):
    """Generate a private key (a random number less than prime)."""
    return random.randint(1, prime - 1)

def compute_public_key(private_key, base, prime):
    """Compute the public key."""
    return pow(base, private_key, prime)

def compute_shared_secret(public_key_other, private_key, prime):
    """Compute the shared secret key."""
    return pow(public_key_other, private_key, prime)

prime = int(input("Enter a prime number: "))
base = int(input("Enter a base (primitive root modulo prime): "))

alice_private = generate_private_key(prime)
alice_public = compute_public_key(alice_private, base, prime)

bob_private = generate_private_key(prime)
bob_public = compute_public_key(bob_private, base, prime)

alice_shared_secret = compute_shared_secret(bob_public, alice_private, prime)
bob_shared_secret = compute_shared_secret(alice_public, bob_private, prime)

print("\nResults:")
print("Prime number:", prime)
print("Base number:", base)
print("\nAlice's Private Key:", alice_private)
print("Alice's Public Key:", alice_public)
print("Bob's Private Key:", bob_private)
print("Bob's Public Key:", bob_public)
print("\nAlice's Shared Secret:", alice_shared_secret)
print("Bob's Shared Secret:", bob_shared_secret)

if alice_shared_secret == bob_shared_secret:
    print("\nSuccess: Shared secrets match!")
else:
    print("\nError: Shared secrets do not match!")