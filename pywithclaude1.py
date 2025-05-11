import tkinter as tk
from tkinter import ttk, messagebox, font
import re
from datetime import datetime

class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Password Strength Checker")
        self.root.geometry("600x650")
        self.root.configure(bg="#f0f9ff")
        self.root.resizable(True, True)
        
        # Set custom fonts
        self.title_font = font.Font(family="Helvetica", size=16, weight="bold")
        self.header_font = font.Font(family="Helvetica", size=12, weight="bold")
        self.normal_font = font.Font(family="Helvetica", size=11)
        self.button_font = font.Font(family="Helvetica", size=11, weight="bold")
        
        # Create main container
        self.main_frame = tk.Frame(root, bg="#f0f9ff", padx=20, pady=20)
        self.main_frame.pack(fill="both", expand=True)
        
        # Add app title
        self.title_label = tk.Label(
            self.main_frame, 
            text="Secure Password Generator & Checker", 
            font=self.title_font, 
            bg="#f0f9ff", 
            fg="#1e40af"
        )
        self.title_label.pack(pady=(0, 20))
        
        # Create content frame
        self.content_frame = tk.Frame(self.main_frame, bg="#f0f9ff")
        self.content_frame.pack(fill="both", expand=True)
        
        # Create the form
        self.create_input_form()
        
        # Create the results section
        self.create_results_section()
        
        # Create the password suggestions section
        self.create_suggestions_section()
        
        # Create the information section
        self.create_info_section()
        
        # Set initial states
        self.update_password_strength_meter("")
        self.update_feedback([])
    
    def create_input_form(self):
        # Create form frame
        form_frame = tk.LabelFrame(
            self.content_frame, 
            text="Personal Information", 
            font=self.header_font, 
            bg="#f0f9ff", 
            fg="#1e40af", 
            padx=15, 
            pady=15
        )
        form_frame.pack(fill="x", padx=10, pady=10)
        
        # Full Name
        tk.Label(
            form_frame, 
            text="Full Name:", 
            font=self.normal_font, 
            bg="#f0f9ff", 
            fg="#1e3a8a", 
            anchor="w"
        ).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        self.name_entry = tk.Entry(
            form_frame, 
            width=30, 
            font=self.normal_font, 
            bd=2, 
            relief="solid"
        )
        self.name_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        # Date of Birth
        tk.Label(
            form_frame, 
            text="Date of Birth:", 
            font=self.normal_font, 
            bg="#f0f9ff", 
            fg="#1e3a8a", 
            anchor="w"
        ).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        dob_frame = tk.Frame(form_frame, bg="#f0f9ff")
        dob_frame.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        # Day dropdown
        self.day_var = tk.StringVar(value="Day")
        self.day_dropdown = ttk.Combobox(
            dob_frame, 
            textvariable=self.day_var, 
            values=[str(i).zfill(2) for i in range(1, 32)],
            width=5, 
            font=self.normal_font,
            state="readonly"
        )
        self.day_dropdown.pack(side="left", padx=(0, 5))
        
        # Month dropdown
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        self.month_var = tk.StringVar(value="Month")
        self.month_dropdown = ttk.Combobox(
            dob_frame, 
            textvariable=self.month_var, 
            values=months,
            width=7, 
            font=self.normal_font,
            state="readonly"
        )
        self.month_dropdown.pack(side="left", padx=5)
        
        # Year dropdown
        current_year = datetime.now().year
        years = [str(i) for i in range(current_year - 100, current_year + 1)]
        self.year_var = tk.StringVar(value="Year")
        self.year_dropdown = ttk.Combobox(
            dob_frame, 
            textvariable=self.year_var, 
            values=years,
            width=6, 
            font=self.normal_font,
            state="readonly"
        )
        self.year_dropdown.pack(side="left", padx=5)
        
        # Password
        tk.Label(
            form_frame, 
            text="Password:", 
            font=self.normal_font, 
            bg="#f0f9ff", 
            fg="#1e3a8a", 
            anchor="w"
        ).grid(row=2, column=0, padx=5, pady=5, sticky="w")
        
        password_frame = tk.Frame(form_frame, bg="#f0f9ff")
        password_frame.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        
        self.password_entry = tk.Entry(
            password_frame, 
            show="•", 
            width=30, 
            font=self.normal_font, 
            bd=2, 
            relief="solid"
        )
        self.password_entry.pack(side="left", padx=(0, 5))
        
        # Password visibility toggle
        self.toggle_btn = tk.Button(
            password_frame, 
            text='👁️', 
            command=self.toggle_password_visibility, 
            font=self.normal_font, 
            bg="#dbeafe", 
            activebackground="#93c5fd", 
            bd=1, 
            width=2, 
            height=1
        )
        self.toggle_btn.pack(side="left")
        
        # Password confirmation
        tk.Label(
            form_frame, 
            text="Confirm Password:", 
            font=self.normal_font, 
            bg="#f0f9ff", 
            fg="#1e3a8a", 
            anchor="w"
        ).grid(row=3, column=0, padx=5, pady=5, sticky="w")
        
        self.confirm_password_entry = tk.Entry(
            form_frame, 
            show="•", 
            width=30, 
            font=self.normal_font, 
            bd=2, 
            relief="solid"
        )
        self.confirm_password_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        
        # Buttons frame
        buttons_frame = tk.Frame(form_frame, bg="#f0f9ff")
        buttons_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        # Check button
        self.check_button = tk.Button(
            buttons_frame, 
            text="Check Strength", 
            command=self.check_password, 
            font=self.button_font, 
            bg="#3b82f6", 
            fg="white", 
            activebackground="#2563eb", 
            activeforeground="white", 
            bd=0, 
            padx=15, 
            pady=5,
            cursor="hand2"
        )
        self.check_button.pack(side="left", padx=10)
        
        # Generate button
        self.generate_button = tk.Button(
            buttons_frame, 
            text="Generate Strong Password", 
            command=self.generate_password, 
            font=self.button_font, 
            bg="#10b981", 
            fg="white", 
            activebackground="#059669", 
            activeforeground="white", 
            bd=0, 
            padx=15, 
            pady=5,
            cursor="hand2"
        )
        self.generate_button.pack(side="left", padx=10)
        
        # Connect password field to real-time strength checking
        self.password_entry.bind("<KeyRelease>", self.on_password_change)
    
    def create_results_section(self):
        # Create results frame
        results_frame = tk.LabelFrame(
            self.content_frame, 
            text="Password Strength", 
            font=self.header_font, 
            bg="#f0f9ff", 
            fg="#1e40af", 
            padx=15, 
            pady=15
        )
        results_frame.pack(fill="x", padx=10, pady=10)
        
        # Strength meter
        meter_frame = tk.Frame(results_frame, bg="#f0f9ff")
        meter_frame.pack(fill="x", pady=5)
        
        tk.Label(
            meter_frame, 
            text="Strength:", 
            font=self.normal_font, 
            bg="#f0f9ff", 
            fg="#1e3a8a"
        ).pack(side="left", padx=(0, 10))
        
        self.meter_canvas = tk.Canvas(
            meter_frame, 
            width=300, 
            height=20, 
            bg="#e5e7eb", 
            highlightthickness=1, 
            highlightbackground="#d1d5db"
        )
        self.meter_canvas.pack(side="left")
        
        # Strength label
        self.strength_label = tk.Label(
            results_frame, 
            text="No Password", 
            font=self.header_font, 
            bg="#f0f9ff", 
            fg="#6b7280"
        )
        self.strength_label.pack(pady=5)
        
        # Feedback section
        tk.Label(
            results_frame, 
            text="Issues:", 
            font=self.normal_font, 
            bg="#f0f9ff", 
            fg="#1e3a8a",
            anchor="w"
        ).pack(fill="x", pady=(10, 5))
        
        self.feedback_frame = tk.Frame(results_frame, bg="#f0f9ff")
        self.feedback_frame.pack(fill="x")
    
    def create_suggestions_section(self):
        # Create suggestions frame
        suggestions_frame = tk.LabelFrame(
            self.content_frame, 
            text="Password Suggestions", 
            font=self.header_font, 
            bg="#f0f9ff", 
            fg="#1e40af", 
            padx=15, 
            pady=15
        )
        suggestions_frame.pack(fill="x", padx=10, pady=10)
        
        # Suggestions text
        self.suggestions_text = tk.Text(
            suggestions_frame, 
            font=self.normal_font, 
            bg="white", 
            height=3, 
            width=40, 
            wrap="word", 
            state="disabled", 
            bd=2, 
            relief="solid"
        )
        self.suggestions_text.pack(fill="x", pady=5)
        
        # Copy button
        self.copy_button = tk.Button(
            suggestions_frame, 
            text="Copy to Clipboard", 
            command=self.copy_to_clipboard, 
            font=self.normal_font, 
            bg="#dbeafe", 
            activebackground="#93c5fd", 
            bd=1, 
            padx=10, 
            pady=2,
            state="disabled",
            cursor="hand2"
        )
        self.copy_button.pack(anchor="e", pady=5)
    
    def create_info_section(self):
        # Create info frame
        info_frame = tk.LabelFrame(
            self.content_frame, 
            text="Password Security Tips", 
            font=self.header_font, 
            bg="#f0f9ff", 
            fg="#1e40af", 
            padx=15, 
            pady=15
        )
        info_frame.pack(fill="x", padx=10, pady=10)
        
        # Info text
        tips = [
            "• Use at least 12 characters for maximum security",
            "• Mix uppercase and lowercase letters",
            "• Include numbers and special characters",
            "• Avoid personal information in your password",
            "• Don't reuse passwords across different websites",
            "• Consider using a password manager"
        ]
        
        for tip in tips:
            tk.Label(
                info_frame, 
                text=tip, 
                font=self.normal_font, 
                bg="#f0f9ff", 
                fg="#374151", 
                anchor="w",
                justify="left"
            ).pack(fill="x", pady=2)
    
    def toggle_password_visibility(self):
        if self.password_entry.cget('show') == '':
            self.password_entry.config(show='•')
            self.toggle_btn.config(text='👁️')
        else:
            self.password_entry.config(show='')
            self.toggle_btn.config(text='🙈')
    
    def on_password_change(self, event=None):
        password = self.password_entry.get()
        self.check_strength_only(password)
    
    def check_strength_only(self, password):
        score, strength, feedback = self.check_password_strength(password)
        self.update_password_strength_meter(score, strength)
        self.update_feedback(feedback)
    
    def check_password(self):
        name = self.name_entry.get()
        
        # Get date of birth
        day = self.day_var.get()
        month = self.month_var.get()
        year = self.year_var.get()
        
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        # Basic validation
        if not name or day == "Day" or month == "Month" or year == "Year":
            messagebox.showwarning("Incomplete Information", "Please fill in all personal information fields.")
            return
        
        if not password:
            messagebox.showwarning("Missing Password", "Please enter a password.")
            return
        
        if password != confirm_password:
            messagebox.showerror("Password Mismatch", "The passwords do not match. Please try again.")
            self.confirm_password_entry.delete(0, tk.END)
            return
        
        # Format date of birth
        month_num = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].index(month) + 1
        dob = f"{year}-{str(month_num).zfill(2)}-{day}"
        
        # Check password strength
        score, strength, feedback = self.check_password_strength(password, name, dob)
        
        # Update UI
        self.update_password_strength_meter(score, strength)
        self.update_feedback(feedback)
        
        # Show appropriate message
        if strength == "Strong":
            messagebox.showinfo("Password Check", "Your password is strong! Good job!")
        elif strength == "Medium":
            messagebox.showinfo("Password Check", "Your password is medium strength. Consider improving it.")
        else:
            messagebox.showwarning("Password Check", "Your password is weak. Please consider using a stronger password.")
        
        # Generate suggestions
        self.generate_suggestions(password, name, dob)
    
    def check_password_strength(self, password, name="", dob=""):
        score = 0
        feedback = []
        
        if not password:
            return 0, "No Password", []
        
        # Length check
        if len(password) >= 12:
            score += 3
        elif len(password) >= 10:
            score += 2
        elif len(password) >= 8:
            score += 1
            feedback.append("Password should be at least 12 characters long")
        else:
            feedback.append("Password is too short (minimum 8 characters)")
        
        # Complexity checks
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Missing uppercase letters")
        
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Missing lowercase letters")
        
        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("Missing numbers")
        
        # Special characters check with more comprehensive list
        if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", password):
            score += 2
        else:
            feedback.append("Missing special characters")
        
        # Variety check - reward more types of characters
        char_types = 0
        if re.search(r"[A-Z]", password): char_types += 1
        if re.search(r"[a-z]", password): char_types += 1
        if re.search(r"\d", password): char_types += 1
        if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", password): char_types += 1
        
        if char_types >= 4:
            score += 2
        elif char_types == 3:
            score += 1
        
        # Sequence check - penalize sequential characters
        if re.search(r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", 
                    password.lower()):
            score -= 1
            feedback.append("Contains sequential letters")
        
        if re.search(r"(012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210)", password):
            score -= 1
            feedback.append("Contains sequential numbers")
        
        # Repetition check - penalize repeated characters
        if re.search(r"(.)\1{2,}", password):  # Same character 3+ times in a row
            score -= 1
            feedback.append("Contains repeated characters")
        
        # Common patterns check
        if re.search(r"^[A-Z][a-z]+\d{1,4}$", password):  # Capitalized word followed by numbers
            score -= 1
            feedback.append("Uses a common pattern (word+numbers)")
        
        # Common weak passwords check
        common_words = ["password", "123456", "qwerty", "admin", "welcome", "letmein", 
                        "monkey", "abc123", "111111", "12345678", "dragon", "sunshine", 
                        "princess", "football", "baseball", "master", "superman", "batman"]
                        
        password_lower = password.lower()
        if any(word in password_lower for word in common_words):
            score -= 3
            feedback.append("Contains common weak password terms")
        
        # Personal info check
        if name or dob:
            personal_info_penalty = 0
            
            # Name check
            if name:
                name_parts = name.lower().split()
                for part in name_parts:
                    if len(part) >= 3 and part in password_lower:
                        personal_info_penalty += 2
                        feedback.append(f"Contains name component: '{part}'")
            
            # DOB check
            if dob:
                dob_parts = re.split(r'[-/]', dob)
                for part in dob_parts:
                    if len(part) >= 2 and part in password:
                        personal_info_penalty += 1
                        feedback.append("Contains birth date component")
                        break
            
            # Apply penalties
            score -= personal_info_penalty
        
        # Ensure score doesn't go below 0
        score = max(score, 0)
        
        # Determine strength
        if score >= 9:
            strength = "Strong"
        elif score >= 6:
            strength = "Medium"
        else:
            strength = "Weak"
        
        return score, strength, feedback
    
    def update_password_strength_meter(self, score=0, strength="No Password"):
        # Clear previous meter
        self.meter_canvas.delete("all")
        
        # Define colors for different strength levels
        colors = {
            "No Password": "#e5e7eb",
            "Weak": "#ef4444",
            "Medium": "#f59e0b",
            "Strong": "#10b981"
        }
        
        # Define the maximum score for a full bar
        max_score = 12
        
        # Calculate the width of the filled portion
        if score > 0:
            filled_width = min(score / max_score * 300, 300)
        else:
            filled_width = 0
        
        # Draw the filled portion
        if filled_width > 0:
            self.meter_canvas.create_rectangle(
                0, 0, filled_width, 20, 
                fill=colors.get(strength, "#e5e7eb"), 
                outline=""
            )
        
        # Update the strength label
        self.strength_label.config(
            text=strength, 
            fg=colors.get(strength, "#6b7280")
        )
    
    def update_feedback(self, feedback_items):
        # Clear previous feedback
        for widget in self.feedback_frame.winfo_children():
            widget.destroy()
        
        if not feedback_items:
            # Show "No issues found" if there are no feedback items
            if self.password_entry.get():
                tk.Label(
                    self.feedback_frame, 
                    text="✓ No issues found", 
                    font=self.normal_font, 
                    bg="#f0f9ff", 
                    fg="#10b981",
                    anchor="w"
                ).pack(fill="x", pady=2)
            else:
                tk.Label(
                    self.feedback_frame, 
                    text="Enter a password to see feedback", 
                    font=self.normal_font, 
                    bg="#f0f9ff", 
                    fg="#6b7280",
                    anchor="w"
                ).pack(fill="x", pady=2)
        else:
            # Display each feedback item
            for item in feedback_items:
                tk.Label(
                    self.feedback_frame, 
                    text=f"• {item}", 
                    font=self.normal_font, 
                    bg="#f0f9ff", 
                    fg="#ef4444",
                    anchor="w",
                    wraplength=500,
                    justify="left"
                ).pack(fill="x", pady=2)
    
    def generate_password(self):
        import random
        import string
        
        # Get the user's name for avoiding personal info
        name = self.name_entry.get().lower()
        name_parts = name.split() if name else []
        
        # Generate a strong password
        length = random.randint(14, 18)  # Random length between 14 and 18
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        
        # Ensure at least one of each type
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(symbols)
        ]
        
        # Fill the rest randomly, but weighted to have more letters than digits/symbols
        remaining_length = length - len(password)
        char_pool = lowercase * 3 + uppercase * 2 + digits + symbols
        
        # Filter out any characters that might form parts of the name
        if name_parts:
            filtered_pool = ''.join(c for c in char_pool if not any(c in part for part in name_parts))
            if filtered_pool:  # If filtering didn't remove all characters
                char_pool = filtered_pool
        
        password.extend(random.choice(char_pool) for _ in range(remaining_length))
        
        # Shuffle the password
        random.shuffle(password)
        password = ''.join(password)
        
        # Fill the password entry
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.confirm_password_entry.delete(0, tk.END)
        self.confirm_password_entry.insert(0, password)
        
        # Update strength meter
        self.check_strength_only(password)
        
        # Update suggestions
        self.update_suggestions([password])
        
        # Enable copy button
        self.copy_button.config(state="normal")
    
    def generate_suggestions(self, current_password, name="", dob=""):
        """Generate password suggestions based on the current password"""
        import random
        import string
        
        suggestions = []
        current_score, current_strength, feedback = self.check_password_strength(current_password, name, dob)
        
        # If the password is already strong, just generate a new strong alternative
        if current_strength == "Strong" and not feedback:
            self.generate_password()
            return
        
        # Otherwise, try to improve the current password
        improved = list(current_password)
        
        # Add length if needed
        if len(current_password) < 12:
            extra_chars = "!@#$%^&*1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            improved.extend(random.choice(extra_chars) for _ in range(12 - len(current_password)))
        
        # Add special char if needed
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", current_password):
            improved.append(random.choice("!@#$%^&*"))
        
        # Add uppercase if needed
        if not re.search(r"[A-Z]", current_password):
            improved.append(random.choice(string.ascii_uppercase))
        
        # Add number if needed
        if not re.search(r"\d", current_password):
            improved.append(random.choice(string.digits))
        
        # Add lowercase if needed
        if not re.search(r"[a-z]", current_password):
            improved.append(random.choice(string.ascii_lowercase))
        
        # Shuffle the improved password
        random.shuffle(improved)
        suggestion1 = ''.join(improved)
        
        # Generate a completely new password as well
        suggestion2 = self.generate_new_password(name, dob)
        
        # Add the suggestions
        suggestions = [suggestion1, suggestion2]
        self.update_suggestions(suggestions)
    
    def generate_new_password(self, name="", dob=""):
        """Generate a completely new strong password"""
        import random
        import string
        
        # Parse name and dob to avoid using personal info
        name_parts = name.lower().split() if name else []
        dob_parts = re.split(r'[-/]', dob) if dob else []
        
        # Generate a strong but memorable password using words
        words = [
            "apple", "banana", "cherry", "dragon", "eagle", "forest", 
            "garden", "harbor", "island", "journey", "kingdom", "legend",
            "mountain", "nature", "ocean", "planet", "quantum", "river",
            "sunset", "thunder", "universe", "valley", "wonder", "zebra"
        ]
        
        # Filter out words that might be related to the user
        if name_parts or dob_parts:
            filtered_words = []
            for word in words:
                if not any(part in word or word in part for part in name_parts + dob_parts):
                    filtered_words.append(word)
            if filtered_words:  # If filtering didn't remove all words
                words = filtered_words
        
        # Select 2-3 random words
        num_words = random.randint(2, 3)
        selected_words = random.sample(words, num_words)
        
        # Capitalize one of the words
        selected_words[random.randint(0, num_words - 1)] = selected_words[random.randint(0, num_words - 1)].capitalize()
        
        # Add numbers and special chars
        password = ''.join(selected_words)
        password += str(random.randint(10, 99))
        password += random.choice("!@#$%^&*")
        
        return password
    
    def update_suggestions(self, suggestions):
        """Update the suggestions text box with new suggestions"""
        # Clear previous suggestions
        self.suggestions_text.config(state="normal")
        self.suggestions_text.delete(1.0, tk.END)
        
        # Add new suggestions
        for i, suggestion in enumerate(suggestions, 1):
            self.suggestions_text.insert(tk.END, f"{suggestion}\n")
        
        self.suggestions_text.config(state="disabled")
        
        # Enable copy button if there are suggestions
        if suggestions:
            self.copy_button.config(state="normal")
        else:
            self.copy_button.config(state="disabled")
    
    def copy_to_clipboard(self):
        """Copy the first suggestion to clipboard"""
        self.suggestions_text.config(state="normal")
        suggestion = self.suggestions_text.get(1.0, "1.end").strip()
        self.suggestions_text.config(state="disabled")
        
        if suggestion:
            self.root.clipboard_clear()
            self.root.clipboard_append(suggestion)
            
            # Show confirmation
            self.copy_button.config(text="Copied!", bg="#10b981")
            self.root.after(1500, lambda: self.copy_button.config(text="Copy to Clipboard", bg="#dbeafe"))

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()
