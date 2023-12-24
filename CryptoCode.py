
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from cryptography.hazmat.backends import(
         default_backend
 )

from cryptography.hazmat.primitives import(
    padding)

from random import (
    randint)
    
import random

#generates public key
def generate_key(p, g, private_key):
    public_key = (g ** private_key) % p
    return public_key

#calculates the shared secret key
def calculate_shared_secret(public_key, private_key, p):
    shared_secret = (public_key ** private_key) % p
    return shared_secret

#Creates the AES key from the shared secret key
def derive_aes_key(shared_secret):
    # Convert the shared secret to bytes
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')

    # Use the most significant bits as the AES key
    aes_key = shared_secret_bytes[:32]  # 256 bits

    # Add padding to make the key the required size
    aes_key = aes_key.ljust(16, b'\0')  # For 128-bit AES

    return aes_key

#Creates AES encryption 
def aes_encrypt(data, aes_key):
    # Pad the data to a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Create a Cipher object
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())

    # Create an encryptor object
    encryptor = cipher.encryptor()

    # Encrypt the padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data

def aes_decrypt(encrypted_data, aes_key):
    # Create a Cipher object
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())

    # Create a decryptor object
    decryptor = cipher.decryptor()

    # Decrypt the encrypted data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding using PKCS7
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data