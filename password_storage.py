import json
import os

class PasswordStorage:
    def __init__(self, filename='passwords.json'):
        self.filename = filename
        self.passwords = self.load_passwords()

    def load_passwords(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as file:
                return json.load(file)
        return {}

    def save_password(self, key, encrypted_password):
        self.passwords[key] = encrypted_password
        with open(self.filename, 'w') as file:
            json.dump(self.passwords, file)

    def get_password(self, key):
        return self.passwords.get(key)
