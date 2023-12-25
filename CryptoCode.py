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
p = generate_prime(24)
print("Generated prime number (p):", p)


if __name__ == "__main__":
    #   generate base (g)   
    g = 29

    # Alice's private key
    private_key_alice = randint(1, p-2)

    # Bob's private key
    private_key_bob = randint(1, p-2)
    # Display results
    print("Alice's private key:", private_key_alice)
    print("Bob's private key:", private_key_bob)

def generate_key(p, g, private_key):
    public_key = (g ** private_key) % p
    return public_key


public_key_alice = generate_key(p, g, private_key_alice)
public_key_bob = generate_key(p, g, private_key_bob)

print("Public key generated by Alice:", public_key_alice)
print("Public key generated by Bob:", public_key_bob)

def calculate_shared_secret(public_key, private_key, p):
    shared_secret = (public_key ** private_key) % p
    return shared_secret
# Calculate shared secrets
shared_secret_alice = calculate_shared_secret(public_key_bob, private_key_alice, p)
shared_secret_bob = calculate_shared_secret(public_key_alice, private_key_bob, p)

print("Shared secret calculated by Alice:", shared_secret_alice)
print("Shared secret calculated by Bob:", shared_secret_bob)    

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
aes_key_alice = derive_aes_key(shared_secret_alice)
aes_key_bob = derive_aes_key(shared_secret_bob)

    # Simulate a financial transaction using AES encryption
transaction_amount = 2500 # Example transaction amount

    # Alice encrypts the transaction amount
encrypted_amount_alice = aes_encrypt(bytes(str(transaction_amount), 'utf-8'), aes_key_alice)
    # Bob decrypts the transaction amount
decrypted_amount_bob = aes_decrypt(encrypted_amount_alice, aes_key_bob)

    # Display results
print(f"Alice encrypts the transaction amount: {encrypted_amount_alice.hex()}")
print(f"Bob decrypts the transaction amount: {int(decrypted_amount_bob.decode('utf-8'))}")
