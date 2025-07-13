import os
import tarfile
import getpass
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

KEY_FILE = "key.enc"
SALT_FILE = "salt.bin"

# ----------------------------
# توليد مفتاح وحمايته بكلمة مرور
# ----------------------------
def generate_key_with_password():
    if os.path.exists(KEY_FILE) and os.path.exists(SALT_FILE):
        print(f"[+] Found existing encrypted key.")
        password = getpass.getpass("Enter key password: ").encode()
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)
    else:
        password = getpass.getpass("Set new key password: ").encode()
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)

        with open(KEY_FILE, 'wb') as f:
            f.write(urlsafe_b64encode(key))
        print(f"[+] New encrypted key generated: {KEY_FILE} & salt saved.")

    return key

# ----------------------------
# دالة تشفير + HMAC
# ----------------------------
def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # HMAC
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    tag = h.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext + tag)

    print(f"[+] File encrypted → {output_file} (IV + Ciphertext + HMAC)")

# ----------------------------
# فك التشفير + التحقق من HMAC
# ----------------------------
def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        data = f.read()

    iv = data[:16]
    ciphertext = data[16:-32]
    tag = data[-32:]

    # Verify HMAC
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    try:
        h.verify(tag)
        print("[+] HMAC verified. File is intact.")
    except:
        print("[-] HMAC verification failed! File may be tampered.")
        return

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"[+] File decrypted → {output_file}")

# ----------------------------
# ضغط مجلد قبل التشفير
# ----------------------------
def compress_folder(folder_path, archive_name):
    with tarfile.open(archive_name, "w:gz") as tar:
        tar.add(folder_path, arcname=os.path.basename(folder_path))
    print(f"[+] Folder compressed → {archive_name}")

# ----------------------------
# CLI
# ----------------------------
def main():
    key = generate_key_with_password()

    print("\n🗝️ Welcome to Dark Shadows Ops 🗝️")
    print("1) Encrypt FILE")
    print("2) Encrypt FOLDER")
    print("3) Decrypt")
    choice = input("Choose (1/2/3): ").strip()

    if choice == '1':
        infile = input("Enter input file: ").strip()
        outfile = infile + ".enc"
        encrypt_file(infile, outfile, key)

    elif choice == '2':
        folder = input("Enter folder name: ").strip()
        archive = folder + ".tar.gz"
        compress_folder(folder, archive)
        outfile = archive + ".enc"
        encrypt_file(archive, outfile, key)

    elif choice == '3':
        infile = input("Enter input file to decrypt: ").strip()
        outfile = infile.replace(".enc", ".dec")
        decrypt_file(infile, outfile, key)

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()

