#!/usr/bin/env python3

import os
import zipfile
import argparse
import shutil
import hashlib
import base64
import getpass
from cryptography.fernet import Fernet

def zip_folder(folder_path, output_path):
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, folder_path)
                zipf.write(abs_path, rel_path)
        zipf.writestr("meta.txt", os.path.basename(folder_path))

def unzip_folder(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(extract_to)

def derive_key(password):
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_file(file_path, password):
    key = derive_key(password)
    fernet = Fernet(key)
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(file_path + '.enc', 'wb') as f:
        f.write(encrypted)
    os.remove(file_path)

def decrypt_file(enc_path, password):
    key = derive_key(password)
    fernet = Fernet(key)
    with open(enc_path, 'rb') as f:
        data = f.read()
    decrypted = fernet.decrypt(data)
    zip_path = enc_path.replace('.enc', '')
    with open(zip_path, 'wb') as f:
        f.write(decrypted)
    os.remove(enc_path)
    return zip_path

def get_original_folder_name(zip_path):
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        with zipf.open("meta.txt") as meta_file:
            return meta_file.read().decode().strip()

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a folder.")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Action to perform")
    parser.add_argument("path", help="Folder to encrypt or encrypted file to decrypt")
    parser.add_argument("--output", help="Output folder or file (optional)")

    args = parser.parse_args()

    password = getpass.getpass("Enter password: ")

    if args.action == "encrypt":
        if not os.path.isdir(args.path):
            print("Error: path must be a folder to encrypt.")
            return

        zip_name = args.output or args.path + ".zip"
        zip_folder(args.path, zip_name)
        encrypt_file(zip_name, password)

        shutil.rmtree(args.path)

        print(f"Encrypted file: {zip_name}.enc")
        print(f"Original folder '{args.path}' has been deleted.")

    elif args.action == "decrypt":
        if not args.path.endswith(".enc"):
            print("Error: file must end with .enc")
            return

        zip_path = decrypt_file(args.path, password)

        original_folder_name = get_original_folder_name(zip_path)

        output_dir = args.output or original_folder_name
        unzip_folder(zip_path, output_dir)
        os.remove(zip_path)

        print(f"Decrypted folder restored to: {output_dir}")

if __name__ == "__main__":
    main()