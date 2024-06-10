import tkinter as tk
from tkinter import messagebox, simpledialog
from encryption_util import EncryptionUtil
from password_storage import PasswordStorage

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")

        self.encryption_util = None
        self.password_storage = PasswordStorage()
        self.current_page = 0
        self.items_per_page = 10

        self.master_password_frame = tk.Frame(root)
        self.master_password_frame.pack(pady=10)

        self.password_label = tk.Label(self.master_password_frame, text="Master Password:")
        self.password_label.pack(side=tk.LEFT)
        self.password_entry = tk.Entry(self.master_password_frame, show="*")
        self.password_entry.pack(side=tk.LEFT)

        self.login_button = tk.Button(self.master_password_frame, text="Login", command=self.set_master_password)
        self.login_button.pack(side=tk.LEFT)

        self.content_frame = tk.Frame(root)
        self.content_frame.pack(pady=10)

        self.navigation_frame = tk.Frame(root)
        self.navigation_frame.pack(pady=10)

    def set_master_password(self):
        master_password = self.password_entry.get().encode()
        self.encryption_util = EncryptionUtil(master_password)
        self.password_label.pack_forget()
        self.password_entry.pack_forget()
        self.login_button.config(text="Logout", command=self.logout)
        self.display_passwords()

    def logout(self):
        self.encryption_util = None
        self.current_page = 0
        self.clear_content()
        self.master_password_frame.pack(pady=10)
        self.password_label.pack(side=tk.LEFT)
        self.password_entry.pack(side=tk.LEFT)
        self.password_entry.delete(0, tk.END)
        self.login_button.config(text="Login", command=self.set_master_password)

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        for widget in self.navigation_frame.winfo_children():
            widget.destroy()

    def display_passwords(self):
        self.clear_content()
        passwords = self.password_storage.load_passwords()
        keys = list(passwords.keys())
        start = self.current_page * self.items_per_page
        end = start + self.items_per_page
        for i in range(start, min(end, len(keys))):
            key = keys[i]
            self.create_password_entry(key, passwords[key])

        if len(keys) > self.items_per_page:
            self.create_navigation_buttons()

    def create_password_entry(self, key, encrypted_password):
        frame = tk.Frame(self.content_frame)
        frame.pack(fill=tk.X, pady=2)

        key_label = tk.Label(frame, text=key, width=20, anchor='w')
        key_label.pack(side=tk.LEFT)

        password_entry = tk.Entry(frame, show="*", width=20)
        password_entry.insert(0, "*****")
        password_entry.pack(side=tk.LEFT, padx=5)

        view_button = tk.Button(frame, text="View", command=lambda: self.view_password(password_entry, encrypted_password))
        view_button.pack(side=tk.LEFT, padx=5)

    def create_navigation_buttons(self):
        prev_button = tk.Button(self.navigation_frame, text="Previous", command=self.previous_page)
        prev_button.pack(side=tk.LEFT, padx=5)

        next_button = tk.Button(self.navigation_frame, text="Next", command=self.next_page)
        next_button.pack(side=tk.LEFT, padx=5)

    def previous_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.display_passwords()

    def next_page(self):
        self.current_page += 1
        self.display_passwords()

    def save_password(self, key, password):
        if self.encryption_util:
            encrypted_password = self.encryption_util.encrypt(password)
            self.password_storage.save_password(key, encrypted_password)
            self.display_passwords()

    def view_password(self, password_entry, encrypted_password):
        if self.encryption_util:
            decrypted_password = self.encryption_util.decrypt(encrypted_password)
            password_entry.config(show="")
            password_entry.delete(0, tk.END)
            password_entry.insert(0, decrypted_password)
            self.root.after(5000, lambda: password_entry.config(show="*"))

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
