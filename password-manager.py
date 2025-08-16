#!/usr/bin/env python3

import json
import os
import base64
from cryptography.fernet import Fernet
import pyotp
import qrcode
from getpass import getpass

class PasswordManager:
    def __init__(self):
        self.data_file = "passwords.json"
        self.key_file = "master.key"
        self.data = {}

    def generate_key(self):
        """Generate a new encryption key"""
        return Fernet.generate_key()
    
    def load_key(self):
        """Load encryption key from file"""
        if not os.path.exists(self.key_file):
            # First time - create new key
            key = self.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            print("🔑 New encryption key created!")
            return key
        
        with open(self.key_file, 'rb') as f:
            return f.read()
        
    def load_data(self):
        """Load password data from file"""
        if os.path.exists(self.data_file):
            with open(self.data_file, 'r') as f:
                self.data = json.load(f)
        else:
            self.data = {"passwords": {}, "master_password": "", "totp_secret": ""}
    
    def save_data(self):
        """Save password data to file"""
        with open(self.data_file, 'w') as f:
            json.dump(self.data, f, indent=2)

    def encrypt_text(self, text):
        """Encrypt text using the key"""
        key = self.load_key()
        cipher = Fernet(key)
        encrypted = cipher.encrypt(text.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_text(self, encrypted_text):
        """Decrypt text using the key"""
        key = self.load_key()
        cipher = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_text.encode())
        decrypted = cipher.decrypt(encrypted_bytes)
        return decrypted.decode()
    
    def hash_password(self, password):
        """Simple password hashing"""
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()
    
    def setup_first_time(self):
        """Set up master password and 2FA"""
        print("🔐 Welcome! Let's set up your password manager")
        
        # Create master password
        while True:
            master_pass = getpass("Create a master password: ")
            confirm_pass = getpass("Confirm master password: ")
            
            if master_pass == confirm_pass and len(master_pass) >= 5:
                # Hash and store master password
                hashed_master = self.hash_password(master_pass)
                self.data["master_password"] = hashed_master
                break
            elif len(master_pass) < 5:
                print("❌ Password must be at least 5 characters!")
            else:
                print("❌ Passwords don't match!")

    # Set up 2FA
        print("\n📱 Setting up Google Authenticator...")
        totp_secret = pyotp.random_base32()
        
        # Encrypt and store the secret
        encrypted_secret = self.encrypt_text(totp_secret)
        self.data["totp_secret"] = encrypted_secret
        
        # Show QR code
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name="My Password Manager",
            issuer_name="Python Project"
        )
        
        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=8, border=4)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
        
        print(f"\n📱 Scan the QR code above with Google Authenticator")
        print(f"Or manually add this secret: {totp_secret}")
        
        # Test 2FA setup
        while True:
            test_code = input("\nEnter the 6-digit code from your app: ")
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(test_code):
                print("✅ 2FA setup successful!")
                break
            else:
                print("❌ Wrong code, try again")
        
        self.save_data()
        print("\n🎉 Setup complete!")

    def login(self):
        """Verify master password and 2FA"""
        # Check master password
        master_pass = getpass("Enter master password: ")
        hashed_input = self.hash_password(master_pass)
        
        if hashed_input != self.data["master_password"]:
            print("❌ Wrong master password!")
            return False
        
        # Check 2FA
        encrypted_secret = self.data["totp_secret"]
        totp_secret = self.decrypt_text(encrypted_secret)
        
        code = input("Enter 6-digit Google Authenticator code: ")
        totp = pyotp.TOTP(totp_secret)
        
        if totp.verify(code):
            print("✅ Login successful!")
            return True
        else:
            print("❌ Wrong 2FA code!")
            return False
        
    def add_password(self):
        """Add a new password"""
        print("\n➕ Add New Password")
        service = input("Service name (e.g., Gmail, Facebook): ")
        username = input("Username/Email: ")
        password = getpass("Password: ")
        
        # Encrypt password before storing
        encrypted_pass = self.encrypt_text(password)
        
        self.data["passwords"][service] = {
            "username": username,
            "password": encrypted_pass
        }
        
        self.save_data()
        print(f"✅ Password for {service} saved!")

    def list_all(self):
        if not self.data["passwords"]:
            print("📭 No passwords stored yet!")
            return
        
        print("\n📋 Your stored services:")
        services = list(self.data["passwords"].keys())
        for i, service in enumerate(services, 1):
            print(f"{i}. {service}")
        
        try:
            choice = int(input("\nSelect service number: ")) - 1
            if 0 <= choice < len(services):
                service = services[choice]
                username = self.data["passwords"][service]["username"]
                encrypted_pass = self.data["passwords"][service]["password"]
                password = self.decrypt_text(encrypted_pass)
                
                print(f"\n🔑 {service}:")
                print(f"Username: {username}")
                print(f"Password: {password}")
            else:
                print("❌ Invalid selection!")
        except ValueError:
            print("❌ Please enter a number!")

    def generate_password(self):
        """Generate a random password"""
        import random
        import string
        
        length = input("Password length (press Enter for 12): ")
        length = int(length) if length.isdigit() else 12

        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(random.choice(characters) for _ in range(length))
        
        print(f"🎲 Generated password: {password}")
        
        save_it = input("Save this password? (y/n): ").lower()
        if save_it == 'y':
            service = input("Service name: ")
            username = input("Username: ")
            
            encrypted_pass = self.encrypt_text(password)
            self.data["passwords"][service] = {
                "username": username,
                "password": encrypted_pass
            }
            self.save_data()
            print("✅ Password saved!")

    def view_password(self):
        if not self.data["passwords"]:
            print("📭 No passwords stored yet!")
            return
        
        print(f"\n📋 You have {len(self.data['passwords'])} stored passwords:")
        for service in self.data["passwords"]:
            username = self.data["passwords"][service]["username"]
            print(f"• {service} ({username})")

    def run(self):
        """Main program"""
        print("🔐 Simple Password Manager with 2FA")
        print("=" * 40)
        
        # Load existing data
        self.load_data()
        
        # First time setup
        if not self.data["master_password"]:
            self.setup_first_time()
            return
        
        # Login
        if not self.login():
            return
        
        # Main menu
        while True:
            print("\n" + "=" * 40)
            print("What would you like to do?")
            print("1. Add new password")
            print("2. View stored password")
            print("3. Generate random password")
            print("4. List all services")
            print("5. Exit")
            
            choice = input("\nChoose option (1-5): ")
            
            if choice == '1':
                self.add_password()
            elif choice == '2':
                self.view_password()
            elif choice == '3':
                self.generate_password()
            elif choice == '4':
                self.list_all()
            elif choice == '5':
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice!")

# Run the program
if __name__ == "__main__":
    # Check if required libraries are installed
    try:
        import cryptography
        import pyotp  
        import qrcode
    except ImportError:
        print("❌ Please install required libraries first:")
        print("pip install cryptography pyotp qrcode[pil]")
        exit()
    
    manager = PasswordManager()
    manager.run()