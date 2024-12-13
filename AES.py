# # Advanced Encryption Standard Implementation in Python
# This code provides a simple implementation of **AES encryption** and **decryption** using the **CBC (Cipher Block Chaining)** mode. It also includes a method for generating an AES key from a user-provided password using the SHA-256 hash function. Here’s a detailed explanation of how each part of the code works:

# ### Key Components:

# 1. **AES Encryption**:
#    - AES (Advanced Encryption Standard) is a symmetric encryption algorithm, meaning the same key is used for both encryption and decryption.
#    - This implementation uses **AES in CBC mode**, which requires an initialization vector (IV) for security. The IV ensures that the same plaintext encrypted multiple times will yield different ciphertexts.

# 2. **Padding**:
#    - AES encryption works on fixed-size blocks (128 bits or 16 bytes), so if the data isn’t a multiple of 16 bytes, it needs to be padded. The **PKCS7 padding scheme** (provided by `Crypto.Util.Padding.pad`) is used to ensure the plaintext is properly aligned to the block size.

# 3. **Hashing the Password**:
#    - The code uses **SHA-256** to hash the user’s password and generates a 128-bit AES key from it (the first 16 bytes of the hash are used as the key for AES-128 encryption).

# ---

# ### Functions:

# #### 1. **`aes_encrypt(data, key)`**:
#    - **Input**:
#      - `data`: The plaintext data to be encrypted (as a string).
#      - `key`: The AES key (16 bytes for AES-128).
#    - **Process**:
#      1. Creates a new AES cipher object in **CBC mode**, which requires a random initialization vector (**IV**).
#      2. Pads the plaintext data to ensure it’s a multiple of 16 bytes (the AES block size).
#      3. Encrypts the padded data using the AES cipher.
#    - **Output**:
#      - The initialization vector (`iv`), which is needed for decryption.
#      - The encrypted data (ciphertext).

# #### 2. **`aes_decrypt(iv, encrypted_data, key)`**:
#    - **Input**:
#      - `iv`: The initialization vector (used to decrypt the data).
#      - `encrypted_data`: The ciphertext to be decrypted.
#      - `key`: The AES key (16 bytes for AES-128).
#    - **Process**:
#      1. Creates a new AES cipher object in CBC mode using the same key and IV.
#      2. Decrypts the encrypted data.
#      3. Removes the padding from the decrypted data to recover the original plaintext.
#    - **Output**:
#      - The decrypted plaintext data.

# #### 3. **`generate_key(password)`**:
#    - **Input**:
#      - `password`: The user-provided password.
#    - **Process**:
#      - Hashes the password using **SHA-256** to ensure a strong, secure key is derived from it.
#      - Returns the first 16 bytes of the SHA-256 hash, which is used as the AES-128 key.
#    - **Output**:
#      - A 128-bit (16-byte) AES key.

# ---

# ### Example Workflow:

# 1. **User Input**:
#    - The user is prompted to enter a password, which is used to generate the AES encryption key.
#    - The user also provides plaintext data to be encrypted.

# 2. **Encryption**:
#    - The `aes_encrypt()` function is called, which encrypts the user’s data using the AES key derived from the password.
#    - The IV and the encrypted data (ciphertext) are printed in hexadecimal format.

# 3. **Decryption**:
#    - The encrypted data is then decrypted using the same AES key and IV via the `aes_decrypt()` function, and the original plaintext is printed.

# ---

# ### Example:

# If the user provides:
# - **Password**: `"mysecretpassword"`
# - **Plaintext**: `"Hello, World!"`

# The output might look like this:

# Enter password to generate AES key: mysecretpassword
# Enter data to encrypt: Hello, World!

# Encrypted data (hex): 1f8b50b51e283a88b91b8b6d62faee5c

# ```
# In this example:
# - The plaintext `"Hello, World!"` is padded, encrypted, and the ciphertext is printed in hexadecimal form.
# - The decryption process successfully retrieves the original message.
  
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return cipher.iv, encrypted_data

def aes_decrypt(iv, encrypted_data, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data, AES.block_size)

def generate_key(password):
    key = hashlib.sha256(password.encode()).digest()
    return key[:16]  

if __name__ == "__main__":
    password = input("Enter password to generate AES key: ")
    key = generate_key(password)  

    data = input("Enter data to encrypt: ")

    iv, encrypted_data = aes_encrypt(data, key)
    print("\nEncrypted data (hex):", encrypted_data.hex())

    decrypted_data = aes_decrypt(iv, encrypted_data, key)
    print("Decrypted data:", decrypted_data.decode('utf-8'))


# Decrypted data: Hello, World!
