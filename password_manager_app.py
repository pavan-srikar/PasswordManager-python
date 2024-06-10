import tkinter as tk
from tkinter import messagebox
from encryption_util import EncryptionUtil
from password_storage import PasswordStorage

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")

        self.encryption_util = None
        self.password_storage = PasswordStorage()

        self.password_label = tk.Label(root, text="Master Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        self.login_button = tk.Button(root, text="Login", command=self.set_master_password)
        self.login_button.pack()

        self.key_label = tk.Label(root, text="Key:")
        self.key_label.pack()
        self.key_entry = tk.Entry(root)
        self.key_entry.pack()

        self.password_label = tk.Label(root, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        self.save_button = tk.Button(root, text="Save", command=self.save_password)
        self.save_button.pack()

        self.retrieve_button = tk.Button(root, text="Retrieve", command=self.retrieve_password)
        self.retrieve_button.pack()

    def set_master_password(self):
        master_password = self.password_entry.get().encode()
        self.encryption_util = EncryptionUtil(master_password)
        messagebox.showinfo("Info", "Master password set successfully")

    def save_password(self):
        key = self.key_entry.get()
        password = self.password_entry.get()
        if self.encryption_util and key and password:
            encrypted_password = self.encryption_util.encrypt(password)
            self.password_storage.save_password(key, encrypted_password)
            self.key_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            messagebox.showinfo("Info", "Password saved successfully")

    def retrieve_password(self):
        key = self.key_entry.get()
        if self.encryption_util and key:
            encrypted_password = self.password_storage.get_password(key)
            if encrypted_password:
                decrypted_password = self.encryption_util.decrypt(encrypted_password)
                messagebox.showinfo("Info", f"Password: {decrypted_password}")
            else:
                messagebox.showerror("Error", "No password found for the given key")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
