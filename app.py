# app.py - COMPLETE BOTHOST WITH ENCRYPTED FILE STORAGE

import os
import json
import subprocess
import signal
import sys
import threading
import time
import logging
import shutil
import zipfile
import re
import math
import glob
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
from functools import wraps
import hashlib
import secrets
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# ── Config ───────────────────────────────────────────────────────────────────
DATA_FILE = "bots_data/bots.json"
USERS_FILE = "bots_data/users.json"
LOGS_DIR = "bots_data/logs"
BOTS_DIR = "bots_data/bots"
ENCRYPTED_DIR = "bots_data/encrypted"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", secrets.token_hex(32))

os.makedirs("bots_data", exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(BOTS_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_DIR, exist_ok=True)

running_processes: dict[str, subprocess.Popen] = {}

# ── Encryption System ──────────────────────────────────────────────────────
def get_encryption_key() -> bytes:
    """Generate or retrieve encryption key"""
    key_file = "bots_data/encryption_key.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        # Generate key from ENCRYPTION_KEY
        salt = b"bothost_salt_2024"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(ENCRYPTION_KEY.encode()))
        with open(key_file, "wb") as f:
            f.write(key)
        return key

def encrypt_data(data: str) -> str:
    """Encrypt data using Fernet"""
    try:
        key = get_encryption_key()
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return data

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data using Fernet"""
    try:
        key = get_encryption_key()
        f = Fernet(key)
        decrypted = f.decrypt(base64.b64decode(encrypted_data))
        return decrypted.decode()
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return encrypted_data

def encrypt_file(file_path: str) -> str:
    """Encrypt a file and save to encrypted directory"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        encrypted_content = encrypt_data(content)
        
        # Save encrypted file
        encrypted_path = os.path.join(ENCRYPTED_DIR, os.path.basename(file_path) + ".enc")
        with open(encrypted_path, 'w', encoding='utf-8') as f:
            f.write(encrypted_content)
        
        return encrypted_path
    except Exception as e:
        logger.error(f"File encryption error: {e}")
        return file_path

def decrypt_file(encrypted_path: str, output_path: str) -> bool:
    """Decrypt a file and save to output path"""
    try:
        with open(encrypted_path, 'r', encoding='utf-8') as f:
            encrypted_content = f.read()
        
        decrypted_content = decrypt_data(encrypted_content)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(decrypted_content)
        
        return True
    except Exception as e:
        logger.error(f"File decryption error: {e}")
        return False

def encrypt_bot_files(bot_id: str) -> bool:
    """Encrypt all files in bot directory"""
    bot_dir = os.path.join(BOTS_DIR, bot_id)
    if not os.path.exists(bot_dir):
        return False
    
    try:
        for root, dirs, files in os.walk(bot_dir):
            for file in files:
                if file.endswith('.enc'):
                    continue
                file_path = os.path.join(root, file)
                # Create encrypted version
                encrypted_content = encrypt_data(open(file_path, 'r', encoding='utf-8', errors='ignore').read())
                enc_path = file_path + '.enc'
                with open(enc_path, 'w', encoding='utf-8') as f:
                    f.write(encrypted_content)
                # Remove original
                os.remove(file_path)
        return True
    except Exception as e:
        logger.error(f"Error encrypting bot files: {e}")
        return False

def decrypt_bot_files(bot_id: str) -> bool:
    """Decrypt all files in bot directory for running"""
    bot_dir = os.path.join(BOTS_DIR, bot_id)
    if not os.path.exists(bot_dir):
        return False
    
    try:
        for root, dirs, files in os.walk(bot_dir):
            for file in files:
                if file.endswith('.enc'):
                    enc_path = os.path.join(root, file)
                    dec_path = enc_path[:-4]  # Remove .enc
                    decrypted_content = decrypt_data(open(enc_path, 'r', encoding='utf-8').read())
                    with open(dec_path, 'w', encoding='utf-8') as f:
                        f.write(decrypted_content)
        return True
    except Exception as e:
        logger.error(f"Error decrypting bot files: {e}")
        return False

# ── Security Check (Light) ──────────────────────────────────────────────────
def is_code_malicious(code: str) -> tuple[bool, str]:
    """Check for malicious code patterns"""
    malicious_patterns = [
        (r'exec\s*\(\s*zlib\.decompress', 'exec(zlib.decompress(...))'),
        (r'exec\s*\(\s*base64\.b64decode', 'exec(base64.b64decode(...))'),
        (r'exec\s*\(\s*__import__', 'exec(__import__)'),
        (r'eval\s*\(\s*__import__', 'eval(__import__)'),
        (r'__import__\s*\(\s*[\'"]os[\'"]\s*\)\.system', 'os.system()'),
        (r'os\.system', 'os.system'),
        (r'eval\s*\(', 'eval()'),
        (r'__import__\s*\(\s*[\'"]subprocess[\'"]\s*\)', 'subprocess import'),
        (r'import\s+os', 'os module'),
        (r'import\s+subprocess', 'subprocess module'),
        (r'import\s+requests', 'requests module'),
        (r'import\s+socket', 'socket module'),
        (r'\.system\(', 'system()'),
        (r'\.popen\(', 'popen()'),
        (r'\.check_output\(', 'check_output()'),
        (r'\.call\(', 'call()'),
        (r'\.__import__\(', '__import__()'),
        (r'exec\s*\(', 'exec()'),
        (r'eval\s*\(', 'eval()'),
        (r'compile\s*\(', 'compile()'),
        (r'__builtins__', '__builtins__'),
    ]
    
    for pattern, msg in malicious_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            return True, msg
    
    base64_count = len(re.findall(r'[A-Za-z0-9+/=]{50,}', code))
    if base64_count > 3:
        return True, f"Excessive base64 strings ({base64_count})"
    
    if 'zlib' in code and ('decompress' in code or 'compress' in code):
        return True, "zlib compression/decompression"
    
    return False, ""

def is_safe_python_file(file_path: str) -> tuple[bool, str]:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        is_malicious, reason = is_code_malicious(content)
        if is_malicious:
            return False, reason
        file_size = os.path.getsize(file_path)
        if file_size > 1024 * 1024:
            return False, "File too large (>1MB)"
        return True, "Safe"
    except Exception as e:
        return False, f"Error reading file: {e}"

# ── User Management ─────────────────────────────────────────────────────────
def load_users() -> dict:
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            return json.load(f)
    default_users = {
        "admin": {
            "password": hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest(),
            "created_at": datetime.now().isoformat(),
            "is_admin": True,
            "bots": [],
            "bot_limit": 999
        }
    }
    save_users(default_users)
    return default_users

def save_users(users: dict) -> None:
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def verify_user(username: str, password: str) -> bool:
    users = load_users()
    if username not in users:
        return False
    return users[username]["password"] == hash_password(password)

def get_user_bots(username: str) -> list:
    users = load_users()
    if username not in users:
        return []
    return users[username].get("bots", [])

def add_bot_to_user(username: str, bot_id: str) -> bool:
    users = load_users()
    if username in users:
        if "bots" not in users[username]:
            users[username]["bots"] = []
        bot_limit = users[username].get("bot_limit", 5)
        if len(users[username]["bots"]) >= bot_limit:
            return False
        if bot_id not in users[username]["bots"]:
            users[username]["bots"].append(bot_id)
        save_users(users)
        return True
    return False

def remove_bot_from_user(username: str, bot_id: str) -> None:
    users = load_users()
    if username in users and "bots" in users[username]:
        if bot_id in users[username]["bots"]:
            users[username]["bots"].remove(bot_id)
        save_users(users)

def get_current_user() -> str:
    return session.get("username", "admin")

def is_admin() -> bool:
    users = load_users()
    username = get_current_user()
    if username not in users:
        return False
    return users[username].get("is_admin", False)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_admin():
            return jsonify({"success": False, "error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

# ── Helpers ───────────────────────────────────────────────────────────────────
def load_bots() -> dict:
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            return json.load(f)
    return {}

def save_bots(bots: dict) -> None:
    with open(DATA_FILE, "w") as f:
        json.dump(bots, f, indent=2)

def get_bot_status(bot_id: str) -> str:
    proc = running_processes.get(bot_id)
    if proc and proc.poll() is None:
        return "running"
    return "stopped"

def tail_log(bot_id: str, lines: int = 50) -> list[str]:
    log_file = os.path.join(LOGS_DIR, f"{bot_id}.log")
    if not os.path.exists(log_file):
        return []
    with open(log_file) as f:
        all_lines = f.readlines()
    return [l.rstrip() for l in all_lines[-lines:]]

def _stream_to_log(proc: subprocess.Popen, log_path: str):
    with open(log_path, "a") as lf:
        for line in proc.stdout:
            lf.write(line)
            lf.flush()

def get_bot_dir(bot_id: str) -> str:
    bot_dir = os.path.join(BOTS_DIR, bot_id)
    os.makedirs(bot_dir, exist_ok=True)
    return bot_dir

def get_main_script(bot_id: str, bots: dict = None) -> str:
    if bots is None:
        bots = load_bots()
    bot_dir = get_bot_dir(bot_id)
    script_path = os.path.join(bot_dir, "bot.py")
    if bot_id in bots:
        old_script = bots[bot_id].get("script", "")
        if old_script and os.path.exists(old_script) and not os.path.exists(script_path):
            if old_script.endswith('.py'):
                try:
                    shutil.copy2(old_script, script_path)
                except Exception:
                    pass
    return script_path

def list_bot_files(bot_id: str, path: str = "") -> list:
    """List files and folders in bot directory"""
    bot_dir = get_bot_dir(bot_id)
    target_dir = os.path.join(bot_dir, path) if path else bot_dir
    items = []
    
    try:
        if not os.path.exists(target_dir):
            return items
            
        for name in sorted(os.listdir(target_dir)):
            if name.startswith('.') or name == '__pycache__':
                continue
                
            full_path = os.path.join(target_dir, name)
            rel_path = os.path.join(path, name) if path else name
            
            # Skip encrypted files in listing (they are hidden)
            if name.endswith('.enc'):
                continue
                
            if os.path.isdir(full_path):
                items.append({
                    "name": name,
                    "path": rel_path,
                    "type": "folder",
                    "modified": datetime.fromtimestamp(os.path.getmtime(full_path)).strftime("%Y-%m-%d %H:%M")
                })
            else:
                stat = os.stat(full_path)
                items.append({
                    "name": name,
                    "path": rel_path,
                    "type": "file",
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                })
    except Exception as e:
        logger.error(f"Error listing files: {e}")
    
    return items

def save_file_encrypted(bot_id: str, filename: str, content: str) -> bool:
    """Save file with encryption"""
    try:
        bot_dir = get_bot_dir(bot_id)
        
        # Create subdirectories if needed
        file_dir = os.path.dirname(filename)
        if file_dir:
            os.makedirs(os.path.join(bot_dir, file_dir), exist_ok=True)
        
        file_path = os.path.join(bot_dir, filename)
        
        # Security: prevent directory traversal
        if not os.path.abspath(file_path).startswith(os.path.abspath(bot_dir)):
            return False
        
        # Encrypt content
        encrypted_content = encrypt_data(content)
        
        # Save encrypted file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(encrypted_content)
        
        return True
    except Exception as e:
        logger.error(f"Error saving encrypted file: {e}")
        return False

def read_file_decrypted(bot_id: str, filename: str) -> tuple[bool, str]:
    """Read and decrypt file"""
    try:
        bot_dir = get_bot_dir(bot_id)
        file_path = os.path.join(bot_dir, filename)
        
        # Security: prevent directory traversal
        if not os.path.abspath(file_path).startswith(os.path.abspath(bot_dir)):
            return False, "Invalid path"
        
        if not os.path.exists(file_path):
            return False, "File not found"
        
        with open(file_path, 'r', encoding='utf-8') as f:
            encrypted_content = f.read()
        
        decrypted_content = decrypt_data(encrypted_content)
        return True, decrypted_content
    except Exception as e:
        logger.error(f"Error reading decrypted file: {e}")
        return False, str(e)

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if verify_user(username, password):
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        error = "Invalid username or password!"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── User Management Routes ──────────────────────────────────────────────────
@app.route("/admin/users")
@login_required
@admin_required
def users_page():
    users = load_users()
    now = datetime.now().isoformat()
    return render_template("users.html", users=users, current_time=now)

@app.route("/api/admin/user/add", methods=["POST"])
@login_required
@admin_required
def add_user():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    is_admin = data.get("is_admin", False)
    duration_days = int(data.get("duration_days", 30))
    bot_limit = int(data.get("bot_limit", 5))

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400

    users = load_users()
    if username in users:
        return jsonify({"success": False, "error": "Username already exists"}), 400

    expiry = (datetime.now() + timedelta(days=duration_days)).isoformat()
    
    users[username] = {
        "password": hash_password(password),
        "created_at": datetime.now().isoformat(),
        "expires_at": expiry,
        "is_admin": is_admin,
        "bots": [],
        "bot_limit": bot_limit
    }
    save_users(users)
    logger.info(f"User added: {username}")
    return jsonify({"success": True, "message": f"User {username} added successfully"})

@app.route("/api/admin/user/<username>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(username):
    if username == "admin":
        return jsonify({"success": False, "error": "Cannot delete admin user"}), 400
    
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "error": "User not found"}), 404
    
    for bot_id in users[username].get("bots", []):
        bot_dir = get_bot_dir(bot_id)
        if os.path.exists(bot_dir):
            shutil.rmtree(bot_dir, ignore_errors=True)
        log_file = os.path.join(LOGS_DIR, f"{bot_id}.log")
        if os.path.exists(log_file):
            os.remove(log_file)
        bots = load_bots()
        if bot_id in bots:
            del bots[bot_id]
            save_bots(bots)
    
    del users[username]
    save_users(users)
    logger.info(f"User deleted: {username}")
    return jsonify({"success": True})

@app.route("/api/admin/user/<username>/reset", methods=["POST"])
@login_required
@admin_required
def reset_user_password(username):
    data = request.json or {}
    new_password = data.get("password", "").strip()
    
    if not new_password:
        return jsonify({"success": False, "error": "New password required"}), 400
    
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "error": "User not found"}), 404
    
    users[username]["password"] = hash_password(new_password)
    save_users(users)
    logger.info(f"Password reset for user: {username}")
    return jsonify({"success": True})

@app.route("/api/admin/user/<username>/extend", methods=["POST"])
@login_required
@admin_required
def extend_user_duration(username):
    data = request.json or {}
    days = int(data.get("days", 30))
    
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "error": "User not found"}), 404
    
    current_expiry = users[username].get("expires_at")
    if current_expiry:
        try:
            current_date = datetime.fromisoformat(current_expiry)
        except:
            current_date = datetime.now()
    else:
        current_date = datetime.now()
    
    new_expiry = current_date + timedelta(days=days)
    users[username]["expires_at"] = new_expiry.isoformat()
    save_users(users)
    logger.info(f"Extended user {username} by {days} days")
    return jsonify({"success": True, "new_expiry": new_expiry.isoformat()})

@app.route("/api/admin/user/<username>/update-limit", methods=["POST"])
@login_required
@admin_required
def update_user_bot_limit(username):
    data = request.json or {}
    bot_limit = int(data.get("bot_limit", 5))
    
    if bot_limit < 0:
        return jsonify({"success": False, "error": "Bot limit cannot be negative"}), 400
    
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "error": "User not found"}), 404
    
    users[username]["bot_limit"] = bot_limit
    save_users(users)
    logger.info(f"Updated bot limit for {username} to {bot_limit}")
    return jsonify({"success": True, "bot_limit": bot_limit})

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def dashboard():
    username = get_current_user()
    users = load_users()
    user_data = users.get(username, {})
    user_bots = user_data.get("bots", [])
    
    all_bots = load_bots()
    if is_admin():
        bots_list = [{"id": bid, **bot} for bid, bot in all_bots.items()]
    else:
        bots_list = []
        for bot_id in user_bots:
            if bot_id in all_bots:
                bot = all_bots[bot_id].copy()
                bot["id"] = bot_id
                if "token" in bot:
                    bot["token"] = bot.get("token", "")
                bots_list.append(bot)
    
    for bot in bots_list:
        bot["status"] = get_bot_status(bot["id"])
    
    return render_template("dashboard.html", 
                         bots=bots_list,
                         username=username,
                         is_admin=is_admin(),
                         expiry=user_data.get("expires_at", "Never"))

# ── Server View ──────────────────────────────────────────────────────────────
@app.route("/server/<bot_id>")
@login_required
def server_view(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return redirect(url_for("dashboard"))
    
    username = get_current_user()
    if not is_admin():
        user_bots = get_user_bots(username)
        if bot_id not in user_bots:
            return "Access denied", 403
    
    bot = bots[bot_id].copy()
    bot["status"] = get_bot_status(bot_id)
    bot["id"] = bot_id
    if "token" in bot:
        bot["token"] = bot.get("token", "")
    get_main_script(bot_id, bots)
    return render_template("server.html", bot=bot, username=username)

# ── API: Add bot ──────────────────────────────────────────────────────────────
@app.route("/api/bot/add", methods=["POST"])
@login_required
def add_bot():
    data = request.json or {}
    name = data.get("name", "").strip()
    token = data.get("token", "").strip()
    code = data.get("code", "").strip()

    if not name or not token or not code:
        return jsonify({"success": False, "error": "Name, token, and code are required"}), 400

    # Check for malicious code (warning only, not blocking)
    is_malicious, reason = is_code_malicious(code)
    if is_malicious:
        logger.warning(f"Malicious code detected in bot '{name}': {reason}")

    bots = load_bots()
    bot_id = f"bot_{int(time.time() * 1000)}"

    bot_dir = get_bot_dir(bot_id)
    script_path = os.path.join(bot_dir, "bot.py")
    
    # Save with encryption
    save_file_encrypted(bot_id, "bot.py", code)

    bots[bot_id] = {
        "id": bot_id,
        "name": name,
        "token": token,
        "script": script_path,
        "created_at": datetime.now().isoformat(),
        "status": "stopped",
        "owner": get_current_user(),
        "encrypted": True
    }
    save_bots(bots)
    
    username = get_current_user()
    if not add_bot_to_user(username, bot_id):
        del bots[bot_id]
        save_bots(bots)
        if os.path.exists(bot_dir):
            shutil.rmtree(bot_dir, ignore_errors=True)
        return jsonify({"success": False, "error": "Bot limit reached for this user"}), 400
    
    logger.info("Bot added: %s (%s) by %s", name, bot_id, get_current_user())
    return jsonify({"success": True, "bot_id": bot_id})

# ── API: Edit bot ─────────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/edit", methods=["POST"])
@login_required
def edit_bot(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403

    data = request.json or {}
    name = data.get("name", "").strip()
    token = data.get("token", "").strip()
    code = data.get("code", "").strip()

    if name: bots[bot_id]["name"] = name
    if token: bots[bot_id]["token"] = token
    if code:
        # Check for malicious code (warning only)
        is_malicious, reason = is_code_malicious(code)
        if is_malicious:
            logger.warning(f"Malicious code in edit bot '{bot_id}': {reason}")
        
        # Save encrypted
        save_file_encrypted(bot_id, "bot.py", code)

    save_bots(bots)
    return jsonify({"success": True})

# ── API: Delete bot ───────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/delete", methods=["POST"])
@login_required
def delete_bot(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403

    if get_bot_status(bot_id) == "running":
        _stop_proc(bot_id)

    bot_dir = get_bot_dir(bot_id)
    if os.path.exists(bot_dir):
        shutil.rmtree(bot_dir, ignore_errors=True)
    log_file = os.path.join(LOGS_DIR, f"{bot_id}.log")
    if os.path.exists(log_file):
        os.remove(log_file)

    remove_bot_from_user(bots[bot_id].get("owner", username), bot_id)

    del bots[bot_id]
    save_bots(bots)
    logger.info("Bot deleted: %s", bot_id)
    return jsonify({"success": True})

# ── API: Start bot ────────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/start", methods=["POST"])
@login_required
def start_bot(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404

    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403

    if get_bot_status(bot_id) == "running":
        return jsonify({"success": False, "error": "Bot already running"})

    bot_dir = get_bot_dir(bot_id)
    script = os.path.join(bot_dir, "bot.py")
    
    if not os.path.exists(script):
        return jsonify({"success": False, "error": "Script file missing"}), 404

    # Decrypt files before running
    try:
        # Read encrypted content and decrypt to temp file
        with open(script, 'r', encoding='utf-8') as f:
            encrypted_content = f.read()
        
        decrypted_content = decrypt_data(encrypted_content)
        
        # Write decrypted to a temp file for execution
        temp_script = os.path.join(bot_dir, "bot_temp.py")
        with open(temp_script, 'w', encoding='utf-8') as f:
            f.write(decrypted_content)
        
        # Check for malicious code in decrypted content
        is_malicious, reason = is_code_malicious(decrypted_content)
        if is_malicious:
            logger.warning(f"Malicious code detected when starting bot: {reason}")
            # Still allow running but log it
        
        token = bots[bot_id].get("token", "")
        env = {**os.environ, "BOT_TOKEN": token, "TELEGRAM_TOKEN": token}
        log_path = os.path.join(LOGS_DIR, f"{bot_id}.log")

        proc = subprocess.Popen(
            [sys.executable, temp_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        running_processes[bot_id] = proc
        t = threading.Thread(target=_stream_to_log, args=(proc, log_path), daemon=True)
        t.start()
        bots[bot_id]["status"] = "running"
        save_bots(bots)
        logger.info("Bot started: %s (PID %s)", bot_id, proc.pid)
        return jsonify({"success": True, "pid": proc.pid})
        
    except Exception as e:
        logger.error("Failed to start bot %s: %s", bot_id, e)
        return jsonify({"success": False, "error": str(e)}), 500

def _stop_proc(bot_id: str):
    proc = running_processes.pop(bot_id, None)
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

# ── API: Stop bot ─────────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/stop", methods=["POST"])
@login_required
def stop_bot(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    if get_bot_status(bot_id) != "running":
        return jsonify({"success": False, "error": "Bot is not running"})
    _stop_proc(bot_id)
    bots[bot_id]["status"] = "stopped"
    save_bots(bots)
    logger.info("Bot stopped: %s", bot_id)
    return jsonify({"success": True})

# ── API: Restart bot ──────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/restart", methods=["POST"])
@login_required
def restart_bot(bot_id):
    if get_bot_status(bot_id) == "running":
        _stop_proc(bot_id)
        time.sleep(1)
    return start_bot(bot_id)

# ── API: Logs ─────────────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/logs")
@login_required
def bot_logs(bot_id):
    lines = int(request.args.get("lines", 50))
    return jsonify({"logs": tail_log(bot_id, lines), "status": get_bot_status(bot_id)})

# ── API: Bot code ─────────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/code")
@login_required
def bot_code(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    script = get_main_script(bot_id, bots)
    code = ""
    if os.path.exists(script):
        success, code = read_file_decrypted(bot_id, "bot.py")
        if not success:
            code = ""
    return jsonify({
        "code": code, 
        "name": bots[bot_id]["name"], 
        "token": bots[bot_id].get("token", "")
    })

# ── API: Status of all bots ───────────────────────────────────────────────────
@app.route("/api/bots/status")
@login_required
def all_status():
    bots = load_bots()
    username = get_current_user()
    user_bots = get_user_bots(username) if not is_admin() else list(bots.keys())
    
    result = {}
    for bid in user_bots:
        if bid in bots:
            result[bid] = get_bot_status(bid)
    return jsonify(result)

# ── File Manager APIs ─────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/files")
@login_required
def api_list_files(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    path = request.args.get("path", "")
    files = list_bot_files(bot_id, path)
    return jsonify({"success": True, "files": files, "path": path})

@app.route("/api/bot/<bot_id>/file/read", methods=["POST"])
@login_required
def api_read_file(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    data = request.json or {}
    filename = secure_filename(data.get("filename", ""))
    if not filename:
        return jsonify({"success": False, "error": "Filename required"}), 400
    
    success, content = read_file_decrypted(bot_id, filename)
    if success:
        return jsonify({"success": True, "content": content, "filename": filename})
    else:
        return jsonify({"success": False, "error": content}), 500

@app.route("/api/bot/<bot_id>/file/save", methods=["POST"])
@login_required
def api_save_file(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    data = request.json or {}
    filename = secure_filename(data.get("filename", ""))
    content = data.get("content", "")
    if not filename:
        return jsonify({"success": False, "error": "Filename required"}), 400
    
    # Check for malicious code (warning only)
    if filename.endswith('.py'):
        is_malicious, reason = is_code_malicious(content)
        if is_malicious:
            logger.warning(f"Malicious code in saved file {filename}: {reason}")
    
    success = save_file_encrypted(bot_id, filename, content)
    if success:
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": "Failed to save file"}), 500

@app.route("/api/bot/<bot_id>/upload", methods=["POST"])
@login_required
def api_upload_file(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected"}), 400
    
    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({"success": False, "error": "Invalid filename"}), 400
    
    bot_dir = get_bot_dir(bot_id)
    
    # Check if file has path (subdirectories)
    file_path_parts = filename.split('/')
    if len(file_path_parts) > 1:
        sub_path = '/'.join(file_path_parts[:-1])
        os.makedirs(os.path.join(bot_dir, sub_path), exist_ok=True)
        filename = '/'.join(file_path_parts)
    
    try:
        content = file.read().decode('utf-8', errors='ignore')
        
        # Check for malicious code
        if filename.endswith('.py'):
            is_malicious, reason = is_code_malicious(content)
            if is_malicious:
                logger.warning(f"Malicious code in uploaded file {filename}: {reason}")
        
        # Save encrypted
        success = save_file_encrypted(bot_id, filename, content)
        if not success:
            return jsonify({"success": False, "error": "Failed to save file"}), 500
        
        # Check if it's a zip file
        extracted = False
        file_path = os.path.join(bot_dir, filename)
        if filename.lower().endswith('.zip'):
            try:
                # Decrypt zip file content first
                success, decrypted_content = read_file_decrypted(bot_id, filename)
                if success:
                    temp_zip = os.path.join("bots_data/temp", f"{bot_id}_{int(time.time())}.zip")
                    with open(temp_zip, 'wb') as f:
                        f.write(decrypted_content.encode())
                    
                    with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                        zip_ref.extractall(bot_dir)
                    extracted = True
                    os.remove(temp_zip)
                    os.remove(file_path)
                    
                    # Encrypt extracted files
                    encrypt_bot_files(bot_id)
                    
                    return jsonify({"success": True, "message": "ZIP uploaded and extracted successfully", "extracted": True})
            except Exception as e:
                logger.error(f"ZIP extraction failed: {e}")
                return jsonify({"success": False, "error": f"Invalid ZIP file: {str(e)}"}), 400
        
        return jsonify({"success": True, "message": "File uploaded successfully", "extracted": False})
        
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({"success": False, "error": f"Upload failed: {str(e)}"}), 500

@app.route("/api/bot/<bot_id>/file/rename", methods=["POST"])
@login_required
def api_rename_file(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    data = request.json or {}
    old_path = data.get("old_path", "")
    new_path = data.get("new_path", "")
    
    if not old_path or not new_path or old_path == new_path:
        return jsonify({"success": False, "error": "Invalid paths"}), 400
    
    bot_dir = get_bot_dir(bot_id)
    old_full = os.path.join(bot_dir, old_path)
    new_full = os.path.join(bot_dir, new_path)
    
    if not os.path.exists(old_full):
        return jsonify({"success": False, "error": "File not found"}), 404
    if os.path.exists(new_full):
        return jsonify({"success": False, "error": "Target already exists"}), 400
    
    os.makedirs(os.path.dirname(new_full), exist_ok=True)
    
    try:
        os.rename(old_full, new_full)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/bot/<bot_id>/file/delete", methods=["POST"])
@login_required
def api_delete_file(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    data = request.json or {}
    file_path = data.get("path", "")
    if not file_path:
        return jsonify({"success": False, "error": "File path required"}), 400
    
    bot_dir = get_bot_dir(bot_id)
    full_path = os.path.join(bot_dir, file_path)
    
    if not os.path.exists(full_path):
        return jsonify({"success": False, "error": "File not found"}), 404
    
    try:
        if os.path.isdir(full_path):
            shutil.rmtree(full_path)
        else:
            os.remove(full_path)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/bot/<bot_id>/folder/create", methods=["POST"])
@login_required
def api_create_folder(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    data = request.json or {}
    folder_path = data.get("path", "")
    if not folder_path:
        return jsonify({"success": False, "error": "Folder path required"}), 400
    
    bot_dir = get_bot_dir(bot_id)
    full_path = os.path.join(bot_dir, folder_path)
    
    try:
        os.makedirs(full_path, exist_ok=True)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/bot/<bot_id>/file/download/<path:filename>")
@login_required
def api_download_file(bot_id, filename):
    bots = load_bots()
    if bot_id not in bots:
        return "Bot not found", 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return "Access denied", 403
    
    bot_dir = get_bot_dir(bot_id)
    return send_from_directory(bot_dir, filename, as_attachment=True)

# ── API: Install requirements.txt ─────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/install", methods=["POST"])
@login_required
def install_requirements(bot_id):
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    
    username = get_current_user()
    if not is_admin() and bots[bot_id].get("owner") != username:
        return jsonify({"success": False, "error": "Access denied"}), 403

    bot_dir = get_bot_dir(bot_id)
    req_file = os.path.join(bot_dir, "requirements.txt")

    if not os.path.exists(req_file):
        return jsonify({"success": False, "error": "requirements.txt not found in bot folder. Upload it first."}), 404

    install_log_path = os.path.join(LOGS_DIR, f"{bot_id}_install.log")

    try:
        # ✅ FIX: Create temp directory if not exists
        temp_dir = "bots_data/temp"
        os.makedirs(temp_dir, exist_ok=True)
        
        # ✅ FIX: Read encrypted requirements.txt
        with open(req_file, 'r', encoding='utf-8', errors='ignore') as f:
            encrypted_content = f.read()
        
        # ✅ FIX: Decrypt content
        try:
            decrypted_content = decrypt_data(encrypted_content)
        except:
            # If not encrypted, use as is
            decrypted_content = encrypted_content
        
        # ✅ FIX: Write to temp file
        temp_req = os.path.join(temp_dir, f"{bot_id}_requirements.txt")
        with open(temp_req, 'w', encoding='utf-8') as f:
            f.write(decrypted_content)
        
        # ✅ FIX: Check if temp file exists
        if not os.path.exists(temp_req):
            return jsonify({"success": False, "error": "Failed to create requirements file"}), 500
        
        with open(install_log_path, "w") as lf:
            lf.write(f"[BotHost] Starting pip install at {datetime.now().isoformat()}\n")
            lf.write(f"[BotHost] Reading: {temp_req}\n\n")

        proc = subprocess.Popen(
            [sys.executable, "-m", "pip", "install", "-r", temp_req, "--no-cache-dir"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        def stream_install_log():
            with open(install_log_path, "a") as lf:
                for line in proc.stdout:
                    lf.write(line)
                    lf.flush()
            proc.wait()
            status = "SUCCESS" if proc.returncode == 0 else f"FAILED (exit {proc.returncode})"
            with open(install_log_path, "a") as lf:
                lf.write(f"\n[BotHost] Install {status} at {datetime.now().isoformat()}\n")
            # ✅ FIX: Clean up temp file
            try:
                if os.path.exists(temp_req):
                    os.remove(temp_req)
            except:
                pass

        t = threading.Thread(target=stream_install_log, daemon=True)
        t.start()

        logger.info("pip install started for bot %s", bot_id)
        return jsonify({"success": True, "message": "Installation started. Check install logs."})
        
    except Exception as e:
        logger.error(f"pip install failed for %s: %s", bot_id, e)
        return jsonify({"success": False, "error": str(e)}), 500

# ── API: Install logs ─────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/install/logs")
@login_required
def install_logs(bot_id):
    install_log_path = os.path.join(LOGS_DIR, f"{bot_id}_install.log")
    if not os.path.exists(install_log_path):
        return jsonify({"logs": [], "done": True})
    with open(install_log_path) as f:
        lines = f.readlines()
    log_lines = [l.rstrip() for l in lines]
    done = any("BotHost] Install" in l and ("SUCCESS" in l or "FAILED" in l) for l in log_lines)
    return jsonify({"logs": log_lines, "done": done})

# ── Cleanup on exit ───────────────────────────────────────────────────────────
def shutdown(*_):
    logger.info("Shutting down – stopping all bots…")
    for bid in list(running_processes.keys()):
        _stop_proc(bid)
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)