# # Playfair Cipher Implementation in Python
# This code implements the **Playfair Cipher**, a manual symmetric encryption technique used to encrypt pairs of letters. It encrypts the message by manipulating the positions of letters in a 5x5 matrix, using a keyword as a basis. Here's a breakdown of how the Playfair Cipher works:

# ### Key Components:

# 1. **`generate_key_matrix(key)`**:
#    - This function creates a 5x5 matrix using the `key` provided by the user.
#    - The matrix contains unique characters from the key followed by the remaining letters of the alphabet (excluding 'J', which is usually merged with 'I' in the Playfair cipher).
#    - The result is a matrix where letters will be used to substitute characters during encryption and decryption.

# 2. **`format_message(message)`**:
#    - This function prepares the input `message` for encryption. 
#    - It removes any 'J' characters (replacing them with 'I') and splits the message into pairs of characters.
#    - If two characters in a pair are the same, it inserts an 'X' between them to ensure no duplicate letters exist in a pair.
#    - If the length of the message is odd, an 'X' is appended at the end to make it even.

# 3. **`find_position(char, key_matrix)`**:
#    - This utility function locates the row and column of a given character in the `key_matrix`.
#    - It helps in identifying the position of characters during encryption and decryption.

# 4. **`encrypt_pair(pair, key_matrix)`**:
#    - Encrypts two characters (a pair) based on the Playfair cipher rules:
#      - If the characters are in the same row, each is replaced by the letter to its immediate right (wrapping around if necessary).
#      - If the characters are in the same column, each is replaced by the letter directly below it.
#      - If the characters form a rectangle, they are replaced by the letters in the opposite corners of the rectangle.

# 5. **`decrypt_pair(pair, key_matrix)`**:
#    - Decrypts a pair of characters by reversing the Playfair cipher rules:
#      - Same row: each character is replaced by the letter to its immediate left.
#      - Same column: each character is replaced by the letter directly above it.
#      - Rectangle: letters are replaced by the opposite corner letters.

# 6. **`playfair_encrypt(message, key)`**:
#    - This function handles the overall encryption process:
#      - It generates the key matrix.
#      - Formats the message into pairs.
#      - Encrypts each pair using `encrypt_pair`.
#      - Returns the encrypted ciphertext.

# 7. **`playfair_decrypt(ciphertext, key, original_length)`**:
#    - Decrypts the ciphertext by processing each pair of characters using `decrypt_pair`.
#    - It ensures the decrypted message matches the original message's length.

# 8. **`main()`**:
#    - The main function handles user input for the message and key.
#    - It calls the encryption and decryption functions, then prints the encrypted and decrypted messages.

# ### Example:

# If the user inputs:
# - `message = "HELLO"`
# - `key = "PLAYFAIR"`

# The generated key matrix might look like this:
# ```
# P L A Y F
# I R B C D
# E G H K M
# N O Q S T
# U V W X Z
# ```

# The message is formatted as "HE LX LO" (with an 'X' inserted to separate duplicate letters).

# The encrypted message might be something like "KC SY SV". 

# Decrypting "KC SY SV" will return "HELLO".

# ## Python Code:

# ``` python
def generate_key_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []
    used_chars = set()
    for char in key:
        if char not in used_chars and char.isalpha():
            matrix.append(char)
            used_chars.add(char)
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in used_chars:
            matrix.append(char)
            used_chars.add(char)
    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def format_message(message):
    message = message.upper().replace("J", "I")
    formatted_message = ""
    i = 0
    while i < len(message):
        char1 = message[i]
        char2 = message[i + 1] if i + 1 < len(message) else 'X'
        if char1 == char2:
            formatted_message += char1 + 'X'
            i += 1
        else:
            formatted_message += char1 + char2
            i += 2
    if len(formatted_message) % 2 != 0:
        formatted_message += 'X'
    return formatted_message

def find_position(char, key_matrix):
    for i in range(5):
        for j in range(5):
            if key_matrix[i][j] == char:
                return i, j
    raise ValueError(f"Character {char} not found in key matrix")

def encrypt_pair(pair, key_matrix):
    row1, col1 = find_position(pair[0], key_matrix)
    row2, col2 = find_position(pair[1], key_matrix)
    if row1 == row2:
        return key_matrix[row1][(col1 + 1) % 5] + key_matrix[row2][(col2 + 1) % 5]
    elif col1 == col2:
        return key_matrix[(row1 + 1) % 5][col1] + key_matrix[(row2 + 1) % 5][col2]
    else:
        return key_matrix[row1][col2] + key_matrix[row2][col1]

def decrypt_pair(pair, key_matrix):
    if len(pair) < 2:
        raise ValueError("Cannot decrypt incomplete pair.")
    row1, col1 = find_position(pair[0], key_matrix)
    row2, col2 = find_position(pair[1], key_matrix)
    if row1 == row2:
        return key_matrix[row1][(col1 - 1) % 5] + key_matrix[row2][(col2 - 1) % 5]
    elif col1 == col2:
        return key_matrix[(row1 - 1) % 5][col1] + key_matrix[(row2 - 1) % 5][col2]
    else:
        return key_matrix[row1][col2] + key_matrix[row2][col1]

def playfair_encrypt(message, key):
    key_matrix = generate_key_matrix(key)
    formatted_message = format_message(message)
    encrypted_message = ""
    for i in range(0, len(formatted_message), 2):
        encrypted_message += encrypt_pair(formatted_message[i:i + 2], key_matrix)
    return encrypted_message

def playfair_decrypt(ciphertext, key, original_length):
    key_matrix = generate_key_matrix(key)
    decrypted_message = ""
    for i in range(0, len(ciphertext), 2):
        decrypted_message += decrypt_pair(ciphertext[i:i + 2], key_matrix)
    if len(decrypted_message) > original_length:
        decrypted_message = decrypted_message[:original_length]
    return decrypted_message

def main():
    message = input("Enter the message: ").replace(" ", "").upper()
    key = input("Enter the key: ").replace(" ", "").upper()

    # Format the message before encrypting and calculating its length
    formatted_message = format_message(message)
    
    # Encrypt the message
    encrypted_message = playfair_encrypt(formatted_message, key)
    print("Encrypted Message: ", encrypted_message)
    
    # Decrypt the message using the formatted message length
    decrypted_message = playfair_decrypt(encrypted_message, key, len(formatted_message))
    print("Decrypted Message: ", decrypted_message)

if __name__ == "__main__":
    main()
