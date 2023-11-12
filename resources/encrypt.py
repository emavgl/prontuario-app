import sys
import base64
import json
from cryptography.fernet import Fernet

def encrypt_json(json_data, encryption_key):
    # Convert the JSON data to a string
    json_string = json.dumps(json_data)

    # Encrypt the JSON string using AES-GCM
    ciphertext = Fernet(encryption_key).encrypt(json_string.encode())

    # Combine IV and ciphertext
    encrypted_data = ciphertext.decode('utf-8')

    return encrypted_data

def main():
    # Check if the input file path is provided
    if len(sys.argv) != 3:
        print("Usage: python script.py input_file_path encryption_key_path")
        sys.exit(1)

    input_file_path = sys.argv[1]
    encryption_key_path = sys.argv[2]

    try:
        # Read JSON data from the input file
        with open(input_file_path, 'r') as input_file:
            json_data = json.load(input_file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error: {e}")
        sys.exit(1)

    try:
        # Read JSON data from the input file
        with open(encryption_key_path, 'r') as input_file:
            encryption_key = bytes(input_file.read(), 'utf-8')
            print(encryption_key)
    except (FileNotFoundError) as e:
        print(f"Error: {e}")
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
