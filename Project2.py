import tkinter as tk

def encrypt():
    message = message_entry.get()
    shift = int(shift_entry.get())

    encrypted_text = ""

    for char in message:
        if char.isupper():
            encrypted_text += chr((ord(char) - 65 + shift) % 26 + 65)

        elif char.islower():
            encrypted_text += chr((ord(char) - 97 + shift) % 26 + 97)

        else:
            encrypted_text += char

    result_label.config(text="Encrypted: " + encrypted_text)


def decrypt():
    message = message_entry.get()
    shift = int(shift_entry.get())

    decrypted_text = ""

    for char in message:
        if char.isupper():
            decrypted_text += chr((ord(char) - 65 - shift) % 26 + 65)

        elif char.islower():
            decrypted_text += chr((ord(char) - 97 - shift) % 26 + 97)

        else:
            decrypted_text += char

    result_label.config(text="Decrypted: " + decrypted_text)


# GUI Window
root = tk.Tk()
root.title("Caesar Cipher Tool")
root.geometry("400x300")

# Title
title = tk.Label(root, text="Basic Encryption & Decryption", font=("Arial", 14, "bold"))
title.pack(pady=10)

# Message Input
tk.Label(root, text="Enter Message").pack()
message_entry = tk.Entry(root, width=35)
message_entry.pack(pady=5)

# Shift Key
tk.Label(root, text="Enter Shift Key").pack()
shift_entry = tk.Entry(root, width=10)
shift_entry.pack(pady=5)

# Buttons
encrypt_btn = tk.Button(root, text="Encrypt 🔒", command=encrypt)
encrypt_btn.pack(pady=5)

decrypt_btn = tk.Button(root, text="Decrypt 🔓", command=decrypt)
decrypt_btn.pack(pady=5)

# Result
result_label = tk.Label(root, text="", font=("Arial", 12))
result_label.pack(pady=15)

# Run GUI
root.mainloop()