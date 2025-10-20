import os
import sys
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class FileEncryptor:
    def __init__(self, password):
        self.password = password.encode()
        self.salt = os.urandom(16)
        self.key = self._generate_key()

    def _generate_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return key

    def encrypt_file(self, input_file, output_file=None):
        if not output_file:
            output_file = input_file + '.encrypted'

        try:
            with open(input_file, 'rb') as f:
                data = f.read()

            fernet = Fernet(self.key)
            encrypted_data = fernet.encrypt(data)

            with open(output_file, 'wb') as f:
                f.write(self.salt + encrypted_data)

            print(f"File encrypted successfully: {output_file}")
            return output_file

        except FileNotFoundError:
            print(f"Error: File {input_file} not found.")
        except PermissionError:
            print(f"Error: Permission denied for {input_file}.")
        except Exception as e:
            print(f"Encryption error: {e}")

    def decrypt_file(self, input_file, output_file=None):
        if not output_file:
            output_file = input_file.replace('.encrypted', '.decrypted')

        try:
            with open(input_file, 'rb') as f:
                file_data = f.read()

            salt = file_data[:16]
            encrypted_data = file_data[16:]

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.password))

            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)

            with open(output_file, 'wb') as f:
                f.write(decrypted_data)

            print(f"File decrypted successfully: {output_file}")
            return output_file

        except FileNotFoundError:
            print(f"Error: File {input_file} not found.")
        except PermissionError:
            print(f"Error: Permission denied for {input_file}.")
        except Exception as e:
            print(f"Decryption error: {e}")

def main():
    parser = argparse.ArgumentParser(description='File Encryption and Decryption Utility')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform')
    parser.add_argument('file', help='Input file to encrypt or decrypt')
    parser.add_argument('-p', '--password', required=True, help='Password for encryption/decryption')
    parser.add_argument('-o', '--output', help='Output file path')

    args = parser.parse_args()

    encryptor = FileEncryptor(args.password)

    if args.action == 'encrypt':
        encryptor.encrypt_file(args.file, args.output)
    else:
        encryptor.decrypt_file(args.file, args.output)

if __name__ == '__main__':
    main()