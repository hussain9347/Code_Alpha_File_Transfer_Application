import os
import paramiko
import getpass
import logging
from cryptography.fernet import Fernet

# Setup logging
logging.basicConfig(filename="audit.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Access control (Authentication)
def authenticate():
    valid_users = {"admin": "securepassword"}  # Update with your credentials
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    if valid_users.get(username) == password:
        print("✅ Authentication successful!")
        logging.info(f"User {username} authenticated")
        return True
    else:
        print("❌ Access denied!")
        logging.warning(f"Failed login attempt for {username}")
        return False

# Generate and save encryption key
def generate_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        print("🔑 Encryption key generated.")
        logging.info("Encryption key generated.")
    else:
        print("🔑 Encryption key already exists.")

# Load the encryption key
def load_key():
    return open("secret.key", "rb").read()

# Encrypt a file
def encrypt_file(input_file, output_file):
    key = load_key()
    cipher = Fernet(key)
    
    with open(input_file, "rb") as file:
        encrypted_data = cipher.encrypt(file.read())

    with open(output_file, "wb") as file:
        file.write(encrypted_data)

    print(f"🔒 {input_file} encrypted as {output_file}")
    logging.info(f"File {input_file} encrypted.")

# Decrypt a file
def decrypt_file(input_file, output_file):
    key = load_key()
    cipher = Fernet(key)

    with open(input_file, "rb") as file:
        decrypted_data = cipher.decrypt(file.read())

    with open(output_file, "wb") as file:
        file.write(decrypted_data)

    print(f"🔓 {input_file} decrypted as {output_file}")
    logging.info(f"File {input_file} decrypted.")

# Secure File Transfer using SFTP
def upload_file(host, username, password, local_file, remote_file):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)

        sftp = ssh.open_sftp()
        sftp.put(local_file, remote_file)
        sftp.close()
        ssh.close()

        print(f"📤 {local_file} uploaded successfully!")
        logging.info(f"File {local_file} uploaded to {host}.")
    except Exception as e:
        print(f"❌ Upload failed: {e}")
        logging.error(f"Upload failed: {e}")

def download_file(host, username, password, remote_file, local_file):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)

        sftp = ssh.open_sftp()
        sftp.get(remote_file, local_file)
        sftp.close()
        ssh.close()

        print(f"📥 {remote_file} downloaded successfully!")
        logging.info(f"File {remote_file} downloaded from {host}.")
    except Exception as e:
        print(f"❌ Download failed: {e}")
        logging.error(f"Download failed: {e}")

# Main Function
def main():
    if not authenticate():
        return

    generate_key()

    while True:
        print("\n🔹 Secure File Transfer Menu:")
        print("1️⃣ Encrypt a file")
        print("2️⃣ Decrypt a file")
        print("3️⃣ Upload a file")
        print("4️⃣ Download a file")
        print("5️⃣ Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            input_file = input("Enter file to encrypt: ")
            output_file = "encrypted_" + input_file
            encrypt_file(input_file, output_file)

        elif choice == "2":
            input_file = input("Enter encrypted file: ")
            output_file = "decrypted_" + input_file.replace("encrypted_", "")
            decrypt_file(input_file, output_file)

        elif choice == "3":
            host = input("Enter SFTP server IP: ")
            username = input("Enter SFTP username: ")
            password = getpass.getpass("Enter SFTP password: ")
            local_file = input("Enter local file to upload: ")
            remote_file = input("Enter remote file path: ")
            upload_file(host, username, password, local_file, remote_file)

        elif choice == "4":
            host = input("Enter SFTP server IP: ")
            username = input("Enter SFTP username: ")
            password = getpass.getpass("Enter SFTP password: ")
            remote_file = input("Enter remote file path: ")
            local_file = input("Enter local file name to save: ")
            download_file(host, username, password, remote_file, local_file)

        elif choice == "5":
            print("🚀 Exiting Secure File Transfer Application.")
            break
        else:
            print("❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
