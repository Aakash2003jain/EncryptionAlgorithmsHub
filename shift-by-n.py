def shift_cipher_encrypt(text, shift):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        else:
            result += chr((ord(char) + shift - 97) % 26 + 97)
    return result

def shift_cipher_decrypt(cipher_text, shift):
    return shift_cipher_encrypt(cipher_text, -shift)

# Dynamic input from user
message = input("Enter the message to encrypt: ")
shift = int(input("Enter the shift value: "))

# Encrypt and Decrypt the message
encrypted = shift_cipher_encrypt(message, shift)
print("Encrypted:", encrypted)

decrypted = shift_cipher_decrypt(encrypted, shift)
print("Decrypted:", decrypted)
