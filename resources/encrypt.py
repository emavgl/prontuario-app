import sys
import os
import json
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.fernet import Fernet
from hashlib import sha256

def encrypt_string(plaintext: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(plaintext.encode())

def derive_key(password: str):
    password_bytes = password.encode('utf-8')
    return base64.urlsafe_b64encode(sha256(password_bytes).digest())

def encrypt_json(json_data, encryption_key):
    # Convert the JSON data to a string
    json_string = json.dumps(json_data)

    # Derive a key of appropriate length
    key = derive_key(encryption_key)

    # Encrypt the JSON string using AES-GCM
    ciphertext = Fernet(key).encrypt(json_string.encode())

    # Combine IV and ciphertext
    encrypted_data = base64.b64encode(ciphertext).decode('utf-8')

    return encrypted_data

def main():
    # Check if the input file path is provided
    if len(sys.argv) != 2:
        print("Usage: python script.py input_file_path")
        sys.exit(1)

    input_file_path = sys.argv[1]

    try:
        # Read JSON data from the input file
        with open(input_file_path, 'r') as input_file:
            json_data = json.load(input_file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Retrieve the encryption key from the environment variable
    encryption_key = os.environ.get('PRONTUARIO_ENC_KEY')

    if not encryption_key:
        print("Error: PRONTUARIO_ENC_KEY environment variable not set.")
        sys.exit(1)

    # Encrypt the JSON data
    encrypted_json = encrypt_json(json_data, encryption_key)

    # Write the encrypted JSON to a file named "data_encrypted.json" in the same location
    output_file_path = "data_encrypted.json"
    with open(output_file_path, 'w') as output_file:
        output_file.write(encrypted_json)

    print(f"Encrypted JSON written to {output_file_path}")

if __name__ == "__main__":
    main()
