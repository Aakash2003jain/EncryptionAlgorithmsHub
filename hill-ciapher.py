# Hill Cipher Implementation in Python
# This code implements the **Hill Cipher**, a classical cryptographic algorithm that uses linear algebra (matrix multiplication) to encrypt and decrypt messages. It works by dividing the message into blocks of `n` characters and encrypting each block using a matrix derived from the key.

# ### Key Components:

# 1. **Matrix Operations**:
#    - The Hill cipher relies on matrix multiplication. The key is transformed into a square matrix (key matrix), and blocks of the message are converted into vectors. Encryption is done by multiplying the key matrix with the message vectors.

# 2. **Steps**:
#    - **Encryption**: The message is divided into equal-sized blocks, and each block is converted into a vector. This vector is multiplied by the key matrix to get the cipher vector. The result is then converted back into text to form the ciphertext.
#    - **Decryption**: To decrypt, the inverse of the key matrix is multiplied with the cipher vector to recover the original message.

# ---

# ### Functions Explained:

# 1. **`getKeyMatrix(key, n)`**:
#    - Takes the `key` (a string) and its length `n` to form a square matrix (`keyMatrix`).
#    - Each character in the key is converted to a number (A = 0, B = 1, ..., Z = 25) using the formula `ord(char) % 65`.
#    - The matrix is populated row-wise with the values from the key.

# 2. **`encrypt(message, keyMatrix, n)`**:
#    - Encrypts a block of `n` characters from `message` using the `keyMatrix`.
#    - The message characters are converted into a vector (`messageVector`), and matrix multiplication is performed (`keyMatrix * messageVector`). The result is then converted back into characters to form part of the ciphertext.

# 3. **`modInverse(a, m)`**:
#    - Finds the modular inverse of `a` under modulo `m`. This is required to compute the inverse of the key matrix during decryption. It ensures that the matrix operations can be reversed.

# 4. **`getCofactor(matrix, temp, p, q, n)`**:
#    - A helper function to compute the cofactor of a matrix. This is used in finding the determinant and adjoint of the matrix, which are required for matrix inversion.

# 5. **`determinant(matrix, n)`**:
#    - Recursively computes the determinant of a matrix. The determinant is essential for determining if a matrix is invertible.

# 6. **`adjoint(matrix, adj)`**:
#    - Computes the adjoint of the matrix. The adjoint is a key step in finding the inverse of the matrix.

# 7. **`getInverseMatrix(matrix, n)`**:
#    - Computes the inverse of the `matrix` modulo 26 using its determinant and adjoint. The inverse matrix is used during decryption to reverse the encryption process.

# 8. **`decrypt(ciphertext, keyMatrix, n)`**:
#    - Decrypts a block of ciphertext using the inverse of the `keyMatrix`. It performs matrix multiplication between the inverse key matrix and the ciphertext vector to recover the original message block.

# ---

# ### Main Logic:

# 1. **Input**:
#    - The user is prompted to input the `message` (plaintext) and the `key`. Both are converted to uppercase, and spaces are removed.
#    - The key length must be a perfect square (e.g., 4, 9, 16, etc.), as it is converted into a square matrix. If the key length isn't a perfect square, the program exits with an error message.
   
# 2. **Padding**:
#    - If the length of the message is not a multiple of `n` (the size of the key matrix), the message is padded with 'X' to make it a multiple of `n`.

# 3. **Key Matrix Generation**:
#    - The `getKeyMatrix` function is called to generate the key matrix from the input key.

# 4. **Encryption**:
#    - The message is processed block by block (of size `n`). Each block is encrypted using the `encrypt` function, and the resulting blocks are concatenated to form the final ciphertext.

# 5. **Decryption**:
#    - Similarly, the ciphertext is processed block by block. Each block is decrypted using the `decrypt` function, and the decrypted blocks are concatenated to form the original plaintext.

# ---

### Example:

# Suppose the user enters:
# - `message = "HELLO"`
# - `key = "GYBNQKURP"` (a 3x3 matrix, so `n = 3`)

# 1. The `keyMatrix` will be:
#    ```
#    [[6, 24, 1],
#     [13, 16, 10],
#     [20, 17, 15]]
#    ```

# 2. The message will be padded with 'X' to make it a multiple of 3: `HELLO -> HELLOX`.

# 3. The message is broken into two blocks: `HEL` and `LOX`.

# 4. Encryption is done block by block:
#    - `HEL` is encrypted using the key matrix to produce a part of the ciphertext.
#    - `LOX` is similarly encrypted.

# 5. Decryption reverses the process, recovering the original message "HELLO".


# ## Python Code:
# ``` python
import numpy as np

def getKeyMatrix(key, n):
    k = 0
    keyMatrix = [[0] * n for i in range(n)]
    for i in range(n):
        for j in range(n):
            keyMatrix[i][j] = ord(key[k].upper()) % 65
            k += 1
    return keyMatrix

def encrypt(message, keyMatrix, n):
    messageVector = [[ord(message[i].upper()) % 65] for i in range(n)]
    cipherMatrix = np.dot(keyMatrix, messageVector) % 26
    CipherText = "".join([chr(int(cipherMatrix[i][0]) + 65) for i in range(n)])
    return CipherText

def modInverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return -1

def getCofactor(matrix, temp, p, q, n):
    i = 0
    j = 0
    for row in range(n):
        for col in range(n):
            if row != p and col != q:
                temp[i][j] = matrix[row][col]
                j += 1
                if j == n - 1:
                    j = 0
                    i += 1

def determinant(matrix, n):
    det = 0
    if n == 1:
        return matrix[0][0]

    temp = [[0] * n for i in range(n)]
    sign = 1

    for f in range(n):
        getCofactor(matrix, temp, 0, f, n)
        det += (sign * matrix[0][f] * determinant(temp, n - 1))
        sign = -sign

    return det

def adjoint(matrix, adj):
    n = len(matrix)
    if n == 1:
        adj[0][0] = 1
        return

    temp = [[0] * n for i in range(n)]
    sign = 1
    for i in range(n):
        for j in range(n):
            getCofactor(matrix, temp, i, j, n)
            sign = 1 if (i + j) % 2 == 0 else -1
            adj[j][i] = (sign * determinant(temp, n - 1)) % 26

def getInverseMatrix(matrix, n):
    det = determinant(matrix, n) % 26
    inverse_det = modInverse(det, 26)

    if inverse_det == -1:
        raise ValueError("Matrix is not invertible under modulo 26.")

    adj = [[0] * n for i in range(n)]
    adjoint(matrix, adj)

    inverse_matrix = [[(adj[i][j] * inverse_det) % 26 for j in range(n)] for i in range(n)]
    return inverse_matrix

def decrypt(ciphertext, keyMatrix, n):
    cipherVector = [[ord(ciphertext[i].upper()) % 65] for i in range(n)]
    inverseKeyMatrix = getInverseMatrix(keyMatrix, n)
    messageMatrix = np.dot(inverseKeyMatrix, cipherVector) % 26
    PlainText = "".join([chr(int(messageMatrix[i][0]) + 65) for i in range(n)])
    return PlainText

def main():
    message = input("Enter the message: ").replace(" ", "").upper()
    key = input("Enter the key: ").replace(" ", "").upper()
    n = int(len(key) ** 0.5)
    if n * n != len(key):
        print("Key length must be a perfect square (e.g., 4, 9, 16).")
        return
    while len(message) % n != 0:
        message += 'X'
    keyMatrix = getKeyMatrix(key, n)
    encrypted_message = ""
    for i in range(0, len(message), n):
        encrypted_message += encrypt(message[i:i + n], keyMatrix, n)
    print("Encrypted Message: ", encrypted_message)
    decrypted_message = ""
    for i in range(0, len(encrypted_message), n):
        decrypted_message += decrypt(encrypted_message[i:i + n], keyMatrix, n)
    print("Decrypted Message: ", decrypted_message)

if __name__ == "__main__":
    main()