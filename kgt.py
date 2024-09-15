import tkinter as tk
from tkinter import scrolledtext, PhotoImage, messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

messages = []


def generate_key_from_password(password):
    # تحويل كلمة المرور إلى مفتاح باستخدام SHA-256
    key = hashlib.sha256(password.encode()).digest()
    # تأكد من أن المفتاح يكون صالحًا لـ Fernet (32 بايت وتنسيق base64)
    return base64.urlsafe_b64encode(key[:32])


def encrypt_message():
    message = entry_message.get("1.0", tk.END).strip()
    password = entry_password.get().strip()

    if message and password:
        try:
            key = generate_key_from_password(password)
            cipher_suite = Fernet(key)
            cipher_text = cipher_suite.encrypt(message.encode())
            text_result.config(state=tk.NORMAL)
            text_result.delete("1.0", tk.END)
            text_result.insert(tk.END, f"Encrypted:\n{cipher_text.decode()}")
            text_result.config(state=tk.DISABLED)
            messages.append(cipher_text.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")
    else:
        messagebox.showwarning("Input Required", "Please enter both a message and a password!")


def decrypt_message():
    cipher_text = entry_message.get("1.0", tk.END).strip().encode()
    password = entry_password.get().strip()

    if cipher_text and password:
        try:
            key = generate_key_from_password(password)
            cipher_suite = Fernet(key)
            plain_text = cipher_suite.decrypt(cipher_text)
            text_result.config(state=tk.NORMAL)
            text_result.delete("1.0", tk.END)
            text_result.insert(tk.END, f"Decrypted:\n{plain_text.decode()}")
            text_result.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
    else:
        messagebox.showwarning("Input Required", "Please enter both the encrypted message and the password!")


def show_saved_messages():
    saved_messages = "\n".join(messages)
    text_result.config(state=tk.NORMAL)
    text_result.delete("1.0", tk.END)
    text_result.insert(tk.END, f"Saved Messages:\n{saved_messages}")
    text_result.config(state=tk.DISABLED)


def copy_to_clipboard():
    result = text_result.get("1.0", tk.END).strip()
    if result:
        window.clipboard_clear()  # مسح الحافظة
        window.clipboard_append(result)  # نسخ النص إلى الحافظة
        messagebox.showinfo("Copied", "Result copied to clipboard!")


# وظيفة للانتقال إلى صفحة التشفير
def show_encryption_page():
    welcome_frame.pack_forget()  # إخفاء إطار الترحيب
    encryption_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)  # إظهار إطار التشفير


# وظيفة للانتقال إلى صفحة الترحيب
def show_welcome_page():
    encryption_frame.pack_forget()  # إخفاء إطار التشفير
    welcome_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)  # إظهار إطار الترحيب


window = tk.Tk()
window.title("Message Encryption")
window.geometry("360x640")

# الصفحة الأولى (صفحة الترحيب)
welcome_frame = tk.Frame(window, bg="white")
welcome_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

try:
    image = PhotoImage(file="n.png")
    label_image = tk.Label(welcome_frame, image=image, bg="white")
    label_image.pack(pady=10)
except Exception as e:
    print(f"Error loading image: {e}")

label_welcome = tk.Label(welcome_frame, text="Welcome to the Encryption App", bg="white", font=("Arial", 18))
label_welcome.pack(pady=10)

button_start = tk.Button(welcome_frame, text="Go to Encryption Page", command=show_encryption_page, bg="#f9d423",
                         font=("Arial", 14), relief=tk.RAISED, bd=2)
button_start.pack(pady=10, fill=tk.X)

# صفحة التشفير
encryption_frame = tk.Frame(window, bg="white")

button_frame = tk.Frame(encryption_frame, bg="white")
button_frame.pack(pady=10, fill=tk.Y, expand=True)

button_encrypt = tk.Button(button_frame, text="Encrypt", command=encrypt_message, bg="#f9d423", font=("Arial", 14),
                           relief=tk.RAISED, bd=2)
button_encrypt.pack(pady=5, fill=tk.X)
button_decrypt = tk.Button(button_frame, text="Decrypt", command=decrypt_message, bg="#f9d423", font=("Arial", 14), relief=tk.RAISED, bd=2)
button_decrypt.pack(pady=5, fill=tk.X)

button_show_saved = tk.Button(button_frame, text="Show Saved Messages", command=show_saved_messages, bg="#f9d423", font=("Arial", 14), relief=tk.RAISED, bd=2)
button_show_saved.pack(pady=5, fill=tk.X)

# زر للنسخ إلى الحافظة
button_copy = tk.Button(button_frame, text="Copy Result", command=copy_to_clipboard, bg="#f9d423", font=("Arial", 14), relief=tk.RAISED, bd=2)
button_copy.pack(pady=5, fill=tk.X)

# زر للعودة إلى صفحة الترحيب
button_back = tk.Button(button_frame, text="Back to Welcome Page", command=show_welcome_page, bg="#f9d423", font=("Arial", 14), relief=tk.RAISED, bd=2)
button_back.pack(pady=5, fill=tk.X)

label_password = tk.Label(encryption_frame, text="Enter Password:", bg="white", font=("Arial", 14))
label_password.pack(pady=5)

entry_password = tk.Entry(encryption_frame, show="*", font=("Arial", 14))
entry_password.pack(pady=5)

label_message = tk.Label(encryption_frame, text="Enter message:", bg="white", font=("Arial", 14))
label_message.pack(pady=5)

entry_message = scrolledtext.ScrolledText(encryption_frame, height=6, width=40, bg="#f7e68b")
entry_message.pack(pady=5)

text_result = scrolledtext.ScrolledText(encryption_frame, height=10, width=40, state=tk.DISABLED, bg="#f7e68b")
text_result.pack(pady=10)

window.mainloop()