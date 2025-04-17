import tkinter as tk
from tkinter import messagebox
import re

def check_password_strength(password, name, dob):
    score = 0
    password_lower = password.lower()

    # Length check
    if len(password) >= 11:
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

    # Common weak words
    common_words = ["password", "123456", "qwerty", "admin"]
    if any(word in password_lower for word in common_words):
        return "Weak Password"

    # Personal info penalty
    name_parts = name.lower().split()
    dob_parts = re.split(r'[-/]', dob)  # Supports formats like 1990-01-01 or 01/01/1990

    personal_info_matches = 0
    for part in name_parts + dob_parts:
        if len(part) >= 3 and part in password_lower:
            personal_info_matches += 1
            score -= 1  # Penalize each matching part

    if personal_info_matches > 0:
        score = max(score, 0)

    # Strength rating
    if score >= 9:
        return "Strong Password"
    elif score >= 7:
        return "Medium Password"
    else:
        return "Weak Password"

def on_check():
    name = name_entry.get()
    dob = dob_entry.get()
    password = password_entry.get()

    if not name or not dob or not password:
        result_label.config(text="Please fill in all fields.", fg="black")
        return

    result = check_password_strength(password, name, dob)
    if result == "Strong Password":
        result_label.config(text=result, fg="green")
    elif result == "Medium Password":
        result_label.config(text=result, fg="orange")
    else:
        result_label.config(text=result, fg="red")

def toggle_password_visibility():
    if password_entry.cget('show') == '':
        password_entry.config(show='*')
        toggle_btn.config(text='👁️')  # Closed eye
    else:
        password_entry.config(show='')
        toggle_btn.config(text='🙈')  # Open eye

# GUI Setup
root = tk.Tk()
root.title("User Info & Password Strength Checker")
root.geometry("500x350")
root.configure(bg="#dbeafe")

frame = tk.Frame(root, bg="#dbeafe")
frame.place(relx=0.5, rely=0.5, anchor="center")

# Name Entry
tk.Label(frame, text="Full Name", font=("Helvetica", 12), bg="#dbeafe", fg="#1e3a8a").pack(pady=(10, 0))
name_entry = tk.Entry(frame, width=30, font=("Helvetica", 12), bd=2, relief="solid")
name_entry.pack(pady=5)

# DOB Entry
tk.Label(frame, text="Date of Birth (YYYY-MM-DD or DD/MM/YYYY)", font=("Helvetica", 12), bg="#dbeafe", fg="#1e3a8a").pack(pady=(10, 0))
dob_entry = tk.Entry(frame, width=30, font=("Helvetica", 12), bd=2, relief="solid")
dob_entry.pack(pady=5)

# Password Entry Label
tk.Label(frame, text="Password", font=("Helvetica", 12), bg="#dbeafe", fg="#1e3a8a").pack(pady=(10, 0))

# Password Entry with toggle
password_frame = tk.Frame(frame, bg="#dbeafe")
password_frame.pack(pady=5)

password_entry = tk.Entry(password_frame, show="*", width=26, font=("Helvetica", 12), bd=2, relief="solid")
password_entry.pack(side="left", padx=(0, 5))

toggle_btn = tk.Button(password_frame, text='👁️', command=toggle_password_visibility, font=("Helvetica", 12), bd=0, bg="#dbeafe", activebackground="#dbeafe")
toggle_btn.pack(side="left")

# Check Button
check_button = tk.Button(frame, text="Check Strength", command=on_check, font=("Helvetica", 12, "bold"), bg="#3b82f6", fg="white", bd=0, padx=10, pady=5)
check_button.pack(pady=15)

# Result Label
result_label = tk.Label(frame, text="", font=("Helvetica", 14, "bold"), bg="#dbeafe")
result_label.pack(pady=5)

root.mainloop()