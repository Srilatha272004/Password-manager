import json
import os
from cryptography.fernet import Fernet
import bcrypt

# Generate and save a key
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load the key
def load_key():
    return open("secret.key", "rb").read()

# Encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Decrypt data
def decrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

# Hash master password
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Verify master password
def verify_password(hashed, password):
    return bcrypt.checkpw(password.encode(), hashed)

# Store master password and username
def store_master_password(username, password):
    hashed_password = hash_password(password)
    master_data = {
        "username": username,
        "password": hashed_password.decode()
    }
    with open("master_password.json", "w") as file:
        json.dump(master_data, file, indent=4)

# Load master password and username
def load_master_password():
    with open("master_password.json", "r") as file:
        return json.load(file)

# Store service password
def store_password(service, username, password, key):
    encrypted_username = encrypt_data(username, key)
    encrypted_password = encrypt_data(password, key)
    
    if os.path.exists("passwords.json"):
        with open("passwords.json", "r") as file:
            passwords = json.load(file)
    else:
        passwords = {}
    
    passwords[service] = {
        "username": encrypted_username.decode(),
        "password": encrypted_password.decode()
    }
    
    with open("passwords.json", "w") as file:
        json.dump(passwords, file, indent=4)

# Retrieve service password
def retrieve_password(service, key):
    with open("passwords.json", "r") as file:
        passwords = json.load(file)
    
    if service in passwords:
        encrypted_username = passwords[service]["username"]
        encrypted_password = passwords[service]["password"]
        
        username = decrypt_data(encrypted_username.encode(), key)
        password = decrypt_data(encrypted_password.encode(), key)
        
        return username, password
    else:
        return None

# Main function
def main():
    if not os.path.exists("secret.key"):
        generate_key()
    
    key = load_key()

    if not os.path.exists("master_password.json"):
        username = input("Set master username: ")
        master_password = input("Set master password: ")
        store_master_password(username, master_password)
    else:
        master_data = load_master_password()
        username = master_data["username"]
        hashed_master_password = master_data["password"].encode()
        master_password = input(f"Enter master password for user {username}: ")
        
        if not verify_password(hashed_master_password, master_password):
            print("Password does not match!")
            return
    
    # Example usage
    service = input("Enter service name: ")

    # Load passwords.json if it exists
    if os.path.exists("passwords.json"):
        with open("passwords.json", "r") as file:
            passwords = json.load(file)
    else:
        passwords = {}

    if service in passwords:
        retrieved = retrieve_password(service, key)
        if retrieved:
            print(f"Retrieved - Username: {retrieved[0]}, Password: {retrieved[1]}")
    else:
        choice = input("This service does not exist. Do you want to create a new one? (Y/N): ").strip().lower()
        if choice != "y":
            print("Thank you")
        else:
            username = input("Enter username: ")
            password = input("Enter password: ")
            store_password(service, username, password, key)
            print("Credentials stored successfully.")
        
if __name__ == "__main__":
    main()
