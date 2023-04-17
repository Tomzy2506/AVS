import json
import keyring
from cryptography.fernet import Fernet

KEYRING_SERVICE_NAME = "AUTO OSINT SCANNER"  # Replace with your tool's name
KEYRING_USER_NAME = "tomiwa"  # Replace with a suitable identifier

def get_encryption_key():
    """
    Retrieves the encryption key from Keyring storage.

    Returns:
        str: Encryption key if available, else None.
    """
    return keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_USER_NAME)

def set_encryption_key(key):
    """
    Stores the encryption key in Keyring storage.

    Args:
        key (str): Encryption key to store.
    """
    keyring.set_password(KEYRING_SERVICE_NAME, KEYRING_USER_NAME, key)

def generate_encryption_key():
    """
    Generates a new Fernet encryption key and stores it in Keyring storage.
    """
    key = Fernet.generate_key().decode()
    set_encryption_key(key)
    print("A new encryption key has been generated and saved.")
    return key

def encrypt_data(data, key):
    """
    Encrypts the input data using Fernet encryption.

    Args:
        data (str): Data to be encrypted.

    Returns:
        tuple: Encrypted data (bytes) and the encryption key (str).
    """
    f = Fernet(key.encode())
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data
    
def decrypt_data(encrypted_data, key):
    """
    Decrypts the encrypted data using the provided key.

    Args:
        encrypted_data (bytes): Encrypted data.
        key (str): Encryption key.

    Returns:
        str: Decrypted data.
    """
    f = Fernet(key.encode())
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode()

def encrypt_existing_file(file_path):
    """
    Encrypts the content of an existing file.

    Args:
        file_path (str): Path to the file to be encrypted.
    """
    try:
        with open(file_path, "r") as f:
            content = f.read()
            key = get_encryption_key()
            if not key:
                print("No encryption key found. Generating a new key...")
                key = generate_encryption_key()
            encrypted_data = encrypt_data(content, key)
        encrypted_file_path = f"{file_path}"
        with open(encrypted_file_path, "wb") as f:
            f.write(encrypted_data)
        print(f"Encrypted file saved as {encrypted_file_path}")
        print(f"Encryption key: {key}")
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
       
def decrypt_report(encrypted_file, decrypted_file, decryption_key=None):
    """
    Decrypts an encrypted file and saves the decrypted content to a new file.

    Args:
        encrypted_file (str): Path to the encrypted file.
        decrypted_file (str): Path to the file where the decrypted content will be saved.
        decryption_key (str): Encryption key to decrypt the data.
    """
    if not decryption_key:
        decryption_key = get_encryption_key()
        if not decryption_key:
            print("Error: No decryption key found.")
            return
    with open(encrypted_file, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_data(encrypted_data, decryption_key)

    with open(decrypted_file, 'w') as f:
        f.write(decrypted_data)

    print(f"Decrypted data saved to: {decrypted_file}")
