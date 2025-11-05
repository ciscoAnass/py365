import os
import sys
import subprocess
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet
import base64
import hashlib

class AnsibleVaultEditorApp:
    def __init__(self, master):
        self.master = master
        master.title("Ansible Vault Editor")
        master.geometry("800x600")
        
        self.current_vault_file = None
        self.vault_password = None
        
        self.create_menu()
        self.create_main_interface()
        
    def create_menu(self):
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Vault", command=self.open_vault_file)
        file_menu.add_command(label="New Vault", command=self.create_new_vault)
        file_menu.add_separator()
        file_menu.add_command(label="Save", command=self.save_vault_file)
        file_menu.add_command(label="Save As", command=self.save_vault_file_as)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)
        
        vault_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Vault", menu=vault_menu)
        vault_menu.add_command(label="Change Password", command=self.change_vault_password)
        
    def create_main_interface(self):
        self.text_area = tk.Text(self.master, wrap=tk.WORD, font=("Courier", 10))
        self.text_area.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.text_area.config(state=tk.DISABLED)
        
    def open_vault_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Ansible Vault Files", "*.yml *.yaml *.json")])
        if file_path:
            password = simpledialog.askstring("Vault Password", "Enter Vault Password:", show='*')
            if password:
                try:
                    decrypted_content = self.decrypt_vault_file(file_path, password)
                    self.current_vault_file = file_path
                    self.vault_password = password
                    
                    self.text_area.config(state=tk.NORMAL)
                    self.text_area.delete(1.0, tk.END)
                    self.text_area.insert(tk.END, decrypted_content)
                    self.text_area.config(state=tk.DISABLED)
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        
    def create_new_vault(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".yml", filetypes=[("YAML Files", "*.yml")])
        if file_path:
            password = simpledialog.askstring("Vault Password", "Set New Vault Password:", show='*')
            if password:
                try:
                    self.text_area.config(state=tk.NORMAL)
                    self.text_area.delete(1.0, tk.END)
                    self.text_area.config(state=tk.DISABLED)
                    
                    self.current_vault_file = file_path
                    self.vault_password = password
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        
    def save_vault_file(self):
        if not self.current_vault_file or not self.vault_password:
            self.save_vault_file_as()
        else:
            content = self.text_area.get(1.0, tk.END)
            self.encrypt_vault_file(self.current_vault_file, content, self.vault_password)
            messagebox.showinfo("Success", "Vault file saved successfully!")
        
    def save_vault_file_as(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".yml", filetypes=[("YAML Files", "*.yml")])
        if file_path:
            password = simpledialog.askstring("Vault Password", "Set Vault Password:", show='*')
            if password:
                content = self.text_area.get(1.0, tk.END)
                self.encrypt_vault_file(file_path, content, password)
                self.current_vault_file = file_path
                self.vault_password = password
                messagebox.showinfo("Success", "Vault file saved successfully!")
        
    def change_vault_password(self):
        if self.current_vault_file and self.vault_password:
            new_password = simpledialog.askstring("Change Password", "Enter New Vault Password:", show='*')
            if new_password:
                content = self.text_area.get(1.0, tk.END)
                self.encrypt_vault_file(self.current_vault_file, content, new_password)
                self.vault_password = new_password
                messagebox.showinfo("Success", "Vault password changed successfully!")
        else:
            messagebox.showwarning("Warning", "Open a vault file first!")
        
    def decrypt_vault_file(self, file_path, password):
        try:
            result = subprocess.run(
                ['ansible-vault', 'decrypt', '--vault-password-file=/dev/stdin', file_path],
                input=password.encode(),
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                with open(file_path, 'r') as f:
                    decrypted_content = f.read()
                
                subprocess.run(
                    ['ansible-vault', 'encrypt', '--vault-password-file=/dev/stdin', file_path],
                    input=password.encode()
                )
                
                return decrypted_content
            else:
                raise Exception("Decryption failed: " + result.stderr)
        except Exception as e:
            raise Exception(f"Error decrypting vault: {str(e)}")
        
    def encrypt_vault_file(self, file_path, content, password):
        try:
            with open(file_path, 'w') as f:
                f.write(content)
            
            result = subprocess.run(
                ['ansible-vault', 'encrypt', '--vault-password-file=/dev/stdin', file_path],
                input=password.encode(),
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                raise Exception("Encryption failed: " + result.stderr)
        except Exception as e:
            raise Exception(f"Error encrypting vault: {str(e)}")

def main():
    root = tk.Tk()
    app = AnsibleVaultEditorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()