# # Data Encryption Standard Implementation in Python

# This code implements **DES (Data Encryption Standard)** encryption and decryption using the **CBC (Cipher Block Chaining)** mode. It also includes a method for generating a DES key from a user-provided password using SHA-256. Let's break down the functionality of each part of the code:

# ### Key Components:

# 1. **DES Encryption**:
#    - **DES** is a symmetric key encryption algorithm that operates on 64-bit blocks of data using a 56-bit key. Here, the key size is 64 bits (8 bytes), though 8 bits are typically used for parity.
#    - This implementation uses **DES in CBC mode**, which requires an initialization vector (IV) to add randomness to the encryption process. CBC mode ensures that identical plaintext blocks encrypt to different ciphertext blocks.

# 2. **Padding**:
#    - Since DES works on fixed-size blocks (8 bytes or 64 bits), if the input data is not a multiple of 8 bytes, it needs to be padded. The code uses the **PKCS7 padding scheme** to ensure the plaintext data is properly aligned to the block size.

# 3. **Hashing the Password**:
#    - The key is derived from the password by hashing it with **SHA-256** and then using the first 8 bytes of the resulting hash as the DES key. DES uses a 64-bit key, but only 56 bits are effective; the extra bits are often used for error detection or parity.

# ---

# ### Functions:

# #### 1. **`generate_des_key(password)`**:
#    - **Input**:
#      - `password`: The user-provided password.
#    - **Process**:
#      - Hashes the password using **SHA-256**.
#      - Returns the first 8 bytes of the hash as the DES key.
#    - **Output**:
#      - An 8-byte DES key derived from the password.

# #### 2. **`des_encrypt(data, key)`**:
#    - **Input**:
#      - `data`: The plaintext data to be encrypted (as a string).
#      - `key`: The DES key (8 bytes).
#    - **Process**:
#      1. Creates a new DES cipher object in **CBC mode** with a random IV.
#      2. Pads the plaintext data to ensure it’s a multiple of 8 bytes (the DES block size).
#      3. Encrypts the padded data using the DES cipher.
#    - **Output**:
#      - The initialization vector (`iv`), which is needed for decryption.
#      - The encrypted data (ciphertext).

# #### 3. **`des_decrypt(iv, encrypted_data, key)`**:
#    - **Input**:
#      - `iv`: The initialization vector (used to decrypt the data).
#      - `encrypted_data`: The ciphertext to be decrypted.
#      - `key`: The DES key (8 bytes).
#    - **Process**:
#      1. Creates a new DES cipher object in CBC mode using the same key and IV.
#      2. Decrypts the encrypted data.
#      3. Removes the padding from the decrypted data to recover the original plaintext.
#    - **Output**:
#      - The decrypted plaintext data.

# ---

# ### Workflow:

# 1. **User Input**:
#    - The user provides a password, which is hashed with SHA-256 to generate a DES key.
#    - The user then inputs the plaintext data to be encrypted.

# 2. **Encryption**:
#    - The `des_encrypt()` function is called, which:
#      - Generates a random IV.
#      - Encrypts the padded plaintext using the DES key.
#      - The encrypted data (ciphertext) is printed in hexadecimal format.

# 3. **Decryption**:
#    - The encrypted data is then decrypted using the same DES key and IV via the `des_decrypt()` function, and the original plaintext is printed.

# ---

# ### Example:

# If the user provides:
# - **Password**: `"mysecretpassword"`
# - **Plaintext**: `"HelloDES"`

# The output might look like this:

# ```
# Enter password to generate DES key: mysecretpassword
# Enter data to encrypt: HelloDES

# Encrypted data (hex): e987e2e7b3d291a89fe9ff0b5db00d23

# Decrypted data: HelloDES
# ```

# ### How It Works:

# - **Key Generation**: The password is hashed using SHA-256, and the first 8 bytes are used as the DES key.
# - **Padding**: The plaintext `"HelloDES"` is exactly 8 bytes, so no additional padding is needed in this case.
# - **Encryption**: The plaintext is encrypted using the generated DES key and a random IV, producing the encrypted output in hexadecimal format.
# - **Decryption**: The ciphertext is decrypted using the same key and IV, and the original message is successfully recovered.

# ## Python Code :
# ``` python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib

def generate_des_key(password):
    key = hashlib.sha256(password.encode()).digest()[:8]
    return key

def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_CBC)
    padded_data = pad(data.encode('utf-8'), DES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return cipher.iv, encrypted_data

def des_decrypt(iv, encrypted_data, key):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data, DES.block_size)

if __name__ == "__main__":
    password = input("Enter password to generate DES key: ")
    key = generate_des_key(password)  
    data = input("Enter data to encrypt: ")
    iv, encrypted_data = des_encrypt(data, key)
    print("\nEncrypted data (hex):", encrypted_data.hex())
    decrypted_data = des_decrypt(iv, encrypted_data, key)
    print("Decrypted data:", decrypted_data.decode('utf-8'))
