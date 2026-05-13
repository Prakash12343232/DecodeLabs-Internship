import tkinter as tk
from tkinter import ttk

def check_strength(event=None):
    password = entry.get()
    score = 0
    suggestions = []

    # Conditions
    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters")

    if any(c.isupper() for c in password):
        score += 1
    else:
        suggestions.append("Add uppercase letter")

    if any(c.islower() for c in password):
        score += 1
    else:
        suggestions.append("Add lowercase letter")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        suggestions.append("Add number")

    if any(not c.isalnum() for c in password):
        score += 1
    else:
        suggestions.append("Use special character (!@#)")

    # Strength Result
    if score <= 2:
        result = "Weak"
        color = "red"
        progress['value'] = 30
    elif score == 3 or score == 4:
        result = "Medium"
        color = "orange"
        progress['value'] = 60
    else:
        result = "Strong"
        color = "green"
        progress['value'] = 100

    label_result.config(text="Strength: " + result, fg=color)

    # Suggestions display
    if suggestions:
        suggestion_text.set("Suggestions: " + ", ".join(suggestions))
    else:
        suggestion_text.set("Perfect password ✅")


def toggle_password():
    if show_var.get():
        entry.config(show="")
    else:
        entry.config(show="*")


# GUI
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("420x320")
root.resizable(False, False)

title = tk.Label(root, text="Password Strength Checker", font=("Arial", 14, "bold"))
title.pack(pady=10)

# Password Entry
entry = tk.Entry(root, width=30, show="*")
entry.pack(pady=5)
entry.bind("<KeyRelease>", check_strength)  # Live checking

# Show password toggle
show_var = tk.BooleanVar()
show_check = tk.Checkbutton(root, text="Show Password 👁️", variable=show_var, command=toggle_password)
show_check.pack()

# Progress bar
progress = ttk.Progressbar(root, length=250, mode='determinate')
progress.pack(pady=10)

# Result label
label_result = tk.Label(root, text="", font=("Arial", 12))
label_result.pack(pady=5)

# Suggestions
suggestion_text = tk.StringVar()
suggestion_label = tk.Label(root, textvariable=suggestion_text, wraplength=350, fg="blue")
suggestion_label.pack(pady=10)

root.mainloop()