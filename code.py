import tkinter as tk
from tkinter import messagebox
import re

def check_password_strength(password):
    score = 0

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1

    # Upper & Lower case letters
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 2

    # Numbers
    if re.search(r"\d", password):
        score += 2

    # Special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 2

    # No common words
    common_words = ["password", "123456", "qwerty", "admin"]
    if any(word in password.lower() for word in common_words):
        return "Weak Password"

    # Strength rating
    if score >= 7:
        return "Strong Password"
    elif score >= 4:
        return "Medium Password"
    else:
        return "Weak Password"

def on_check():
    password = entry.get()
    result = check_password_strength(password)
    if result == "Strong Password":
        result_label.config(text=result, fg="green")
    elif result == "Medium Password":
        result_label.config(text=result, fg="orange")
    else:
        result_label.config(text=result, fg="red")

# GUI Setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("450x250")
root.configure(bg="#dbeafe")

frame = tk.Frame(root, bg="#dbeafe")
frame.place(relx=0.5, rely=0.5, anchor="center")

title_label = tk.Label(frame, text="Enter Password", font=("Helvetica", 14, "bold"), bg="#dbeafe", fg="#1e3a8a")
title_label.pack(pady=10)

entry = tk.Entry(frame, show="*", width=30, font=("Helvetica", 12), bd=2, relief="solid")
entry.pack(pady=5)

check_button = tk.Button(frame, text="Check Strength", command=on_check, font=("Helvetica", 12, "bold"), bg="#3b82f6", fg="white", bd=0, padx=10, pady=5)
check_button.pack(pady=10)

result_label = tk.Label(frame, text="", font=("Helvetica", 14, "bold"), bg="#dbeafe")
result_label.pack(pady=5)

root.mainloop()