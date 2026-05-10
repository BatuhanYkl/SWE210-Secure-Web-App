"""
SWE210 - Secure Web Application
Features: Authentication (PBKDF2+SHA256 hashing), RBAC (Admin/User), AES-256 Encryption
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import hashlib
import hmac
import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ─────────────────────────────────────────────
#  PASSWORD HASHING  (PBKDF2 + SHA-256 + Salt)
# ─────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return base64.b64encode(salt + key).decode()

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its stored hash."""
    decoded = base64.b64decode(stored_hash.encode())
    salt, key = decoded[:32], decoded[32:]
    new_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return hmac.compare_digest(key, new_key)

# ─────────────────────────────────────────────
#  AES-256 ENCRYPTION  (CBC mode)
# ─────────────────────────────────────────────

AES_KEY = os.urandom(32)   # 256-bit key (generated once at startup)

def encrypt_data(plaintext: str) -> str:
    """Encrypt sensitive data with AES-256-CBC."""
    iv = os.urandom(16)
    padded = plaintext.encode()
    # PKCS7 padding
    pad_len = 16 - (len(padded) % 16)
    padded += bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    # Re-run to fix encryptor finalize chaining
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(iv + ct).decode()

def decrypt_data(ciphertext: str) -> str:
    """Decrypt AES-256-CBC encrypted data."""
    raw = base64.b64decode(ciphertext.encode())
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len].decode()

# ─────────────────────────────────────────────
#  IN-MEMORY USER DATABASE
# ─────────────────────────────────────────────

USERS = {
    "admin": {
        "password_hash": hash_password("Admin@1234"),
        "role": "admin",
        "email": encrypt_data("admin@secureapp.com"),
        "phone": encrypt_data("+1-555-0100"),
    },
    "alice": {
        "password_hash": hash_password("Alice@5678"),
        "role": "user",
        "email": encrypt_data("alice@example.com"),
        "phone": encrypt_data("+1-555-0101"),
    },
    "bob": {
        "password_hash": hash_password("Bob@9999"),
        "role": "user",
        "email": encrypt_data("bob@example.com"),
        "phone": encrypt_data("+1-555-0102"),
    },
}

# ─────────────────────────────────────────────
#  ACCESS CONTROL HELPERS
# ─────────────────────────────────────────────

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Access denied: Admins only.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper

# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = USERS.get(username)
        if user and verify_password(password, user["password_hash"]):
            session["username"] = username
            session["role"] = user["role"]
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    username = session["username"]
    user = USERS[username]
    decrypted_email = decrypt_data(user["email"])
    decrypted_phone = decrypt_data(user["phone"])
    return render_template("dashboard.html",
                           username=username,
                           role=session["role"],
                           email=decrypted_email,
                           phone=decrypted_phone,
                           encrypted_email=user["email"],
                           encrypted_phone=user["phone"])

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    users_info = []
    for uname, data in USERS.items():
        users_info.append({
            "username": uname,
            "role": data["role"],
            "email": decrypt_data(data["email"]),
            "phone": decrypt_data(data["phone"]),
            "enc_email": data["email"],
        })
    return render_template("admin.html", users=users_info)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
