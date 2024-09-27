import os
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv


def convert_to_binary(file_path):
    with open(file_path, 'rb') as file:
        binary_data = file.read()
    return binary_data


def encrypt_data(binary_data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(binary_data) + padder.finalize()
    
    print(f'Padded Data Length: {len(padded_data)}')
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data


def save_encrypted_file(encrypted_data, output_path):
    with open(output_path, 'wb') as file:
        file.write(encrypted_data)


def save_key_to_file(key, file_path):
    with open(file_path, 'w') as file:
        file.write(key)


def select_file_with_fzf():
    try:
        result = subprocess.run(['fzf'], stdout=subprocess.PIPE, check=True)
        return result.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        print("fzf selection failed or was cancelled.")
        return None


def generate_encrypted_file_name(original_file_name):
    base, ext = os.path.splitext(original_file_name)
    return f"{base}_encrypted{ext}"


def main():
    load_dotenv()
    input_file = select_file_with_fzf()
    if not input_file:
        print("No file selected. Exiting.")
        return
    
    output_file = generate_encrypted_file_name(input_file)
    base, ext = os.path.splitext(input_file)
    key_file = f"{base}_key.txt"
    key = os.urandom(32)
    binary_data = convert_to_binary(input_file)
    
    print(f'Original Data Length: {len(binary_data)} bytes')
    
    encrypted_data = encrypt_data(binary_data, key)
    save_encrypted_file(encrypted_data, output_file)
    
    key_hex = key.hex()
    save_key_to_file(key_hex, key_file)
    
    print(f'Encrypted Data Length: {len(encrypted_data)} bytes')
    print(f'Encrypted Data (first 64 bytes): {encrypted_data[:64].hex()}')
    print(f'File encrypted and saved to {output_file}')
    print(f'Encryption key (saved to {key_file}): {key_hex}')


if __name__ == "__main__":
    main()