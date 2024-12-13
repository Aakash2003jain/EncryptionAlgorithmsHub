import string
import random

# Function to generate a random substitution key
def generate_key():
    letters = list(string.ascii_lowercase)
    shuffled_letters = random.sample(letters, len(letters))  # Randomly shuffle the alphabet
    return dict(zip(letters, shuffled_letters))  # Create a mapping from original to shuffled alphabet

# Function to encrypt the message
def monoalphabetic_encrypt(plaintext, key):
    result = ""
    for char in plaintext.lower():
        if char in key:
            result += key[char]  # Substitute each letter using the key
        else:
            result += char  # Keep non-alphabet characters (spaces, punctuation) as is
    return result

# Function to decrypt the message
def monoalphabetic_decrypt(ciphertext, key):
    reverse_key = {v: k for k, v in key.items()}  # Reverse the key for decryption
    result = ""
    for char in ciphertext:
        if char in reverse_key:
            result += reverse_key[char]  # Substitute using the reverse key
        else:
            result += char
    return result

# Example usage
plaintext = input("Enter the message to encrypt: ")

# Generate a random substitution key
key = generate_key()
print("Generated key (alphabet mapping):", key)

# Encrypt and decrypt
encrypted_message = monoalphabetic_encrypt(plaintext, key)
print("Encrypted message:", encrypted_message)

decrypted_message = monoalphabetic_decrypt(encrypted_message, key)
print("Decrypted message:", decrypted_message)
