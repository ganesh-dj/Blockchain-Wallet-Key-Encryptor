import os
import sys
import getpass
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()
salt = b'static_salt_demo'

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password.encode())

def sha256_hash(data):
    sha = hashlib.sha256()
    sha.update(data)
    return sha.hexdigest()

def check_password_strength(password):
    if len(password) < 8:
        print("⚠️  Weak password! Use at least 8 characters.")
    elif len(password) < 12:
        print("✅ Medium strength password.")
    else:
        print("💪 Strong password.")

def encrypt_file(file_path, output_path=None):
    password = getpass.getpass("🔐 Enter encryption password: ")
    check_password_strength(password)
    key = derive_key(password)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        data = f.read()

    padding_length = 16 - (len(data) % 16)
    data += bytes([padding_length]) * padding_length

    encrypted_data = encryptor.update(data) + encryptor.finalize()
    if not output_path:
        output_path = file_path + ".enc"

    with open(output_path, 'wb') as f:
        f.write(iv + encrypted_data)

    hash_value = sha256_hash(encrypted_data)
    with open("encryption_report.txt", "a") as report:
        report.write(f"{datetime.now()} - Encrypted {file_path} to {output_path} - SHA256: {hash_value}\n")

    print(f"✅ Encrypted: {output_path}")
    print(f"🔑 SHA-256 of encrypted data: {hash_value}")

def decrypt_file(file_path, output_path=None):
    password = getpass.getpass("🔐 Enter decryption password: ")
    key = derive_key(password)

    with open(file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]

    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_path = file_path.replace(".enc", f".decrypted_{timestamp}")

    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    hash_value = sha256_hash(decrypted_data)
    print(f"🔓 Decrypted: {output_path}")
    print(f"✅ SHA-256 of decrypted data: {hash_value}")

def batch_encrypt(folder_path):
    for filename in os.listdir(folder_path):
        full_path = os.path.join(folder_path, filename)
        if os.path.isfile(full_path):
            encrypt_file(full_path)

def batch_decrypt(folder_path):
    for filename in os.listdir(folder_path):
        full_path = os.path.join(folder_path, filename)
        if os.path.isfile(full_path) and filename.endswith(".enc"):
            decrypt_file(full_path)

def usage():
    print("Usage:")
    print("  python encryptor.py encrypt <file_path> [--output <output_path>]")
    print("  python encryptor.py decrypt <file_path> [--output <output_path>]")
    print("  python encryptor.py encrypt-folder <folder_path>")
    print("  python encryptor.py decrypt-folder <folder_path>")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
        sys.exit(1)

    action = sys.argv[1]
    target = sys.argv[2]
    output = None

    if "--output" in sys.argv:
        output_index = sys.argv.index("--output") + 1
        output = sys.argv[output_index]

    if action == "encrypt":
        encrypt_file(target, output)
    elif action == "decrypt":
        decrypt_file(target, output)
    elif action == "encrypt-folder":
        batch_encrypt(target)
    elif action == "decrypt-folder":
        batch_decrypt(target)
    else:
        usage()
