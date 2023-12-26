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
def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n <= 1 or n % 2 == 0:
        return False
    if n == 2 or n == 3:
        return True

    # Write (n - 1) as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generate a random prime number with the specified number of bits."""
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1  # Ensure the number has the desired number of bits and is odd
        if is_prime(candidate):
            return candidate

# Example: Generate a random prime number with 24 bits
p = generate_prime(8)
print("Generated prime number (p):", p)


if __name__ == "__main__":
    # Shared prime (p) and base (g)   
    g = 29

    # Sheldon's private key
    private_key_sheldon = randint(1, p-2)

    # Bank's private key
    private_key_bank = randint(1, p-2)
    # Display results
    print("Sheldon's private key:", private_key_sheldon)
    print("Bank's private key:", private_key_bank)

def generate_key(p, g, private_key):
    public_key = (g ** private_key) % p
    return public_key


public_key_sheldon = generate_key(p, g, private_key_sheldon)
public_key_bank = generate_key(p, g, private_key_bank)

print("Public key generated by Sheldon:", public_key_sheldon)
print("Public key generated by Bank:", public_key_bank)

def calculate_shared_secret(public_key, private_key, p):
    shared_secret = (public_key ** private_key) % p
    return shared_secret
# Calculate shared secrets
shared_secret_sheldon = calculate_shared_secret(public_key_bank, private_key_sheldon, p)
shared_secret_bank = calculate_shared_secret(public_key_sheldon, private_key_bank, p)

print("Shared secret calculated by Sheldon:", shared_secret_sheldon)
print("Shared secret calculated by Bank:", shared_secret_bank)    

#AES CODE STARTS

def derive_aes_key(shared_secret):
    # Convert the shared secret to bytes
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')

    # Use the most significant bits as the AES key
    aes_key = shared_secret_bytes[:32]  # 256 bits

    # Add padding to make the key the required size
    aes_key = aes_key.ljust(32, b'\0')  # For 256-bit AES

    return aes_key

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
    
# Derive AES keys from shared secrets
aes_key_sheldon = derive_aes_key(shared_secret_sheldon)
aes_key_bank = derive_aes_key(shared_secret_bank)

    # Simulate a financial transaction using AES encryption
transaction_amount = 2500 # Example transaction amount

    # Sheldon encrypts the transaction amount
encrypted_amount_sheldon = aes_encrypt(bytes(str(transaction_amount), 'utf-8'), aes_key_sheldon)
    # Bank decrypts the transaction amount
decrypted_amount_bank = aes_decrypt(encrypted_amount_sheldon, aes_key_bank)

    # Display results
print(f"Sheldon encrypts the transaction amount: {encrypted_amount_sheldon.hex()}")
print(f"Bank decrypts the transaction amount: {int(decrypted_amount_bank.decode('utf-8'))}")