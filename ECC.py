import tinyec.ec as ec
import tinyec.registry as reg
from Crypto.Cipher import AES
import hashlib
import secrets

# AES encryption and decryption using shared ECC key
def encrypt_AES_GCM(msg, secretKey):
    cipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(msg)
    return cipher.nonce, ciphertext, tag

def decrypt_AES_GCM(encryptedMsg, secretKey):
    (nonce, ciphertext, tag) = encryptedMsg
    cipher = AES.new(secretKey, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Generate a shared ECC secret
def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    return sha.digest()

curve = reg.get_curve('brainpoolP256r1')

def encrypt_ECC(msg, pubKey):
    privKey = secrets.randbelow(curve.field.n)
    sharedECCKey = privKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    nonce, ciphertext, tag = encrypt_AES_GCM(msg, secretKey)
    pubKeyCipher = privKey * curve.g
    return (ciphertext, pubKeyCipher, nonce, tag)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, pubKeyCipher, nonce, tag) = encryptedMsg
    sharedECCKey = privKey * pubKeyCipher
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    return decrypt_AES_GCM((nonce, ciphertext, tag), secretKey)

# Example Usage
msg = b'This is a secret message'

# ECC key pairs
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

print("Original Message:", msg)

# Encrypt the message using ECC
encryptedMsg = encrypt_ECC(msg, pubKey)
print("Encrypted Message:", encryptedMsg)

# Decrypt the message
decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
print("Decrypted Message:", decryptedMsg)
