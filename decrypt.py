import os
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv


def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    
    print(f'IV: {iv.hex()}')
    print(f'Encrypted Data Length (after IV removed): {len(encrypted_data)}')
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    print(f'Decrypted Padded Data Length: {len(decrypted_padded_data)}')
    print(f'Decrypted Padded Data (first 64 bytes): {decrypted_padded_data[:64].hex()}')
    
    unpadder = padding.PKCS7(128).unpadder()
    try:
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except ValueError as e:
        print("Padding error:", e)
        print(f'Decrypted Padded Data (first 64 bytes): {decrypted_padded_data[:64].hex()}')
        raise
    
    return decrypted_data


def save_decrypted_file(decrypted_data, output_path):
    with open(output_path, 'wb') as file:
        file.write(decrypted_data)


def load_key_from_file(file_path):
    with open(file_path, 'r') as file:
        key = file.read()
    return key


def select_file_with_fzf():
    try:
        result = subprocess.run(['fzf'], stdout=subprocess.PIPE, check=True)
        return result.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        print("fzf selection failed or was cancelled.")
        return None


def generate_decrypted_file_name(encrypted_file_name):
    if "_encrypted" in encrypted_file_name:
        return encrypted_file_name.replace("_encrypted", "")
    else:
        return f"{encrypted_file_name}_decrypted"


def main():
    load_dotenv()
    
    input_file = select_file_with_fzf()
    if not input_file:
        print("No file selected. Exiting.")
        return
    
    output_file = generate_decrypted_file_name(input_file)
    base, ext = os.path.splitext(input_file)
    key_file = base.replace('_encrypted', '') + '_key.txt'
    
    key_hex = load_key_from_file(key_file)
    key = bytes.fromhex(key_hex)
    
    print(f'Input File: {input_file}')
    print(f'Output File: {output_file}')
    print(f'Encryption Key: {key_hex}')
    
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()
        
    print(f'Encrypted Data Length: {len(encrypted_data)} bytes')
    print(f'Encrypted Data (first 64 bytes): {encrypted_data[:64].hex()}')
    
    decrypted_data = decrypt_data(encrypted_data, key)
    
    print(f'Decrypted Data Length: {len(decrypted_data)} bytes')
    
    save_decrypted_file(decrypted_data, output_file)
    print(f'File decrypted and saved to {output_file}')


if __name__ == "__main__":
    main()