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
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
from functools import wraps
import hashlib
import secrets
from werkzeug.utils import secure_filename

# ── Encryption ────────────────────────────────────────────────────────────────
try:
    from cryptography.fernet import Fernet
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── Config ───────────────────────────────────────────────────────────────────
DATA_FILE      = "bots_data/bots.json"
USERS_FILE     = "bots_data/users.json"
KEY_FILE       = "bots_data/.encryption_key"
LOGS_DIR       = "bots_data/logs"
BOTS_DIR       = "bots_data/bots"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# Max 50MB upload
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

os.makedirs("bots_data", exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(BOTS_DIR, exist_ok=True)

# In-memory process registry  {bot_id: subprocess.Popen}
running_processes: dict[str, subprocess.Popen] = {}

# ── Encryption Helpers ────────────────────────────────────────────────────────
def get_or_create_key() -> bytes:
    """Get or create Fernet encryption key."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(KEY_FILE, 0o600)
    return key

def get_cipher():
    if not ENCRYPTION_AVAILABLE:
        return None
    key = get_or_create_key()
    return Fernet(key)

def encrypt_data(data: dict) -> bytes:
    """Encrypt dict to encrypted bytes."""
    if not ENCRYPTION_AVAILABLE:
        return json.dumps(data, indent=2).encode()
    cipher = get_cipher()
    return cipher.encrypt(json.dumps(data).encode())

def decrypt_data(raw: bytes) -> dict:
    """Decrypt bytes to dict."""
    if not ENCRYPTION_AVAILABLE:
        return json.loads(raw)
    cipher = get_cipher()
    try:
        return json.loads(cipher.decrypt(raw))
    except Exception:
        # Fallback: maybe it's plain JSON (migration)
        try:
            return json.loads(raw)
        except Exception:
            return {}

# ── Data Helpers ──────────────────────────────────────────────────────────────
def load_bots() -> dict:
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "rb") as f:
            raw = f.read()
        if raw.strip():
            return decrypt_data(raw)
    return {}

def save_bots(bots: dict) -> None:
    with open(DATA_FILE, "wb") as f:
        f.write(encrypt_data(bots))

def load_users() -> dict:
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "rb") as f:
            raw = f.read()
        if raw.strip():
            return decrypt_data(raw)
    return {}

def save_users(users: dict) -> None:
    with open(USERS_FILE, "wb") as f:
        f.write(encrypt_data(users))

# ── Bot Helpers ───────────────────────────────────────────────────────────────
def get_bot_status(bot_id: str) -> str:
    proc = running_processes.get(bot_id)
    if proc and proc.poll() is None:
        return "running"
    return "stopped"

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        # Check user expiry if not admin
        if not session.get("is_admin"):
            username = session.get("username")
            if username:
                users = load_users()
                user = users.get(username)
                if user:
                    expiry = user.get("expires_at")
                    if expiry and datetime.fromisoformat(expiry) < datetime.now():
                        session.clear()
                        return redirect(url_for("login", error="Account expired"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in") or not session.get("is_admin"):
            return jsonify({"success": False, "error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def tail_log(bot_id: str, lines: int = 50) -> list[str]:
    log_file = os.path.join(LOGS_DIR, f"{bot_id}.log")
    if not os.path.exists(log_file):
        return []
    with open(log_file) as f:
        all_lines = f.readlines()
    return [l.rstrip() for l in all_lines[-lines:]]

def _stream_to_log(proc: subprocess.Popen, log_path: str):
    """Background thread: write stdout+stderr to log file."""
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
            try:
                shutil.copy2(old_script, script_path)
            except Exception:
                pass
    return script_path

def list_bot_files(bot_id: str) -> list:
    bot_dir = get_bot_dir(bot_id)
    files = []
    try:
        for name in sorted(os.listdir(bot_dir)):
            if name.startswith('.') or name == '__pycache__':
                continue
            path = os.path.join(bot_dir, name)
            if os.path.isfile(path):
                stat = os.stat(path)
                files.append({
                    "name": name,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                })
    except Exception:
        pass
    return files

def user_can_access_bot(bot_id: str) -> bool:
    """Check if current session user can access this bot."""
    if session.get("is_admin"):
        return True
    allowed = session.get("allowed_bots")
    if allowed is None:
        return True  # legacy: no restriction
    return bot_id in allowed

# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = request.args.get("error")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        pw = request.form.get("password", "")

        # Check admin
        if username == "admin" and hash_password(pw) == hash_password(ADMIN_PASSWORD):
            session["logged_in"] = True
            session["is_admin"] = True
            session["username"] = "admin"
            return redirect(url_for("dashboard"))

        # Check regular users
        users = load_users()
        user = users.get(username)
        if user and user.get("password_hash") == hash_password(pw):
            # Check expiry
            expiry = user.get("expires_at")
            if expiry and datetime.fromisoformat(expiry) < datetime.now():
                error = "Account expired. Contact admin."
            else:
                session["logged_in"] = True
                session["is_admin"] = False
                session["username"] = username
                session["allowed_bots"] = user.get("allowed_bots", [])
                return redirect(url_for("dashboard"))
        else:
            error = "Wrong username or password!"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def dashboard():
    bots = load_bots()
    is_admin = session.get("is_admin", False)
    allowed = session.get("allowed_bots")

    bot_list = []
    for bid, bot in bots.items():
        if not is_admin and allowed is not None and bid not in allowed:
            continue
        bot["status"] = get_bot_status(bid)
        bot["id"] = bid
        bot_list.append(bot)

    users = load_users() if is_admin else {}
    return render_template("dashboard.html", bots=bot_list, is_admin=is_admin, users=users)

# ── Server View ───────────────────────────────────────────────────────────────
@app.route("/server/<bot_id>")
@login_required
def server_view(bot_id):
    if not user_can_access_bot(bot_id):
        return redirect(url_for("dashboard"))
    bots = load_bots()
    if bot_id not in bots:
        return redirect(url_for("dashboard"))
    bot = bots[bot_id].copy()
    bot["status"] = get_bot_status(bot_id)
    bot["id"] = bot_id
    get_main_script(bot_id, bots)
    return render_template("server.html", bot=bot, is_admin=session.get("is_admin", False))

# ── API: Add bot ──────────────────────────────────────────────────────────────
@app.route("/api/bot/add", methods=["POST"])
@login_required
def add_bot():
    data = request.json or {}
    name  = data.get("name", "").strip()
    token = data.get("token", "").strip()
    code  = data.get("code", "").strip()

    if not name or not token or not code:
        return jsonify({"success": False, "error": "Name, token, and code are required"}), 400

    bots = load_bots()
    bot_id = f"bot_{int(time.time() * 1000)}"

    bot_dir = get_bot_dir(bot_id)
    script_path = os.path.join(bot_dir, "bot.py")
    with open(script_path, "w") as f:
        f.write(code)

    bots[bot_id] = {
        "id":         bot_id,
        "name":       name,
        "token":      token,
        "script":     script_path,
        "created_at": datetime.now().isoformat(),
        "status":     "stopped",
    }
    save_bots(bots)
    logger.info("Bot added: %s (%s)", name, bot_id)
    return jsonify({"success": True, "bot_id": bot_id})

# ── API: Edit bot ─────────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/edit", methods=["POST"])
@login_required
def edit_bot(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404

    data  = request.json or {}
    name  = data.get("name", "").strip()
    token = data.get("token", "").strip()
    code  = data.get("code", "").strip()

    if name:  bots[bot_id]["name"]  = name
    if token: bots[bot_id]["token"] = token
    if code:
        script = bots[bot_id].get("script") or get_main_script(bot_id, bots)
        with open(script, "w") as f:
            f.write(code)

    save_bots(bots)
    return jsonify({"success": True})

# ── API: Delete bot ───────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/delete", methods=["POST"])
@login_required
def delete_bot(bot_id):
    if not session.get("is_admin"):
        return jsonify({"success": False, "error": "Admin only"}), 403
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404

    if get_bot_status(bot_id) == "running":
        _stop_proc(bot_id)

    bot_dir = get_bot_dir(bot_id)
    if os.path.exists(bot_dir):
        shutil.rmtree(bot_dir, ignore_errors=True)
    log_file = os.path.join(LOGS_DIR, f"{bot_id}.log")
    if os.path.exists(log_file):
        os.remove(log_file)

    del bots[bot_id]
    save_bots(bots)
    logger.info("Bot deleted: %s", bot_id)
    return jsonify({"success": True})

# ── API: Start / Stop / Restart ───────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/start", methods=["POST"])
@login_required
def start_bot(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    if get_bot_status(bot_id) == "running":
        return jsonify({"success": False, "error": "Bot already running"})

    script = get_main_script(bot_id, bots)
    if not os.path.exists(script):
        return jsonify({"success": False, "error": "Script file missing"}), 404

    token    = bots[bot_id]["token"]
    env      = {**os.environ, "BOT_TOKEN": token, "TELEGRAM_TOKEN": token}
    log_path = os.path.join(LOGS_DIR, f"{bot_id}.log")

    try:
        proc = subprocess.Popen(
            [sys.executable, script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        running_processes[bot_id] = proc
        t = threading.Thread(target=_stream_to_log, args=(proc, log_path), daemon=True)
        t.start()
        logger.info("Bot started: %s (PID %s)", bot_id, proc.pid)
        return jsonify({"success": True, "pid": proc.pid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def _stop_proc(bot_id: str):
    proc = running_processes.pop(bot_id, None)
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

@app.route("/api/bot/<bot_id>/stop", methods=["POST"])
@login_required
def stop_bot(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    if get_bot_status(bot_id) != "running":
        return jsonify({"success": False, "error": "Bot is not running"})
    _stop_proc(bot_id)
    return jsonify({"success": True})

@app.route("/api/bot/<bot_id>/restart", methods=["POST"])
@login_required
def restart_bot(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    if get_bot_status(bot_id) == "running":
        _stop_proc(bot_id)
        time.sleep(1)
    return start_bot(bot_id)

# ── API: Logs / Code / Status ─────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/logs")
@login_required
def bot_logs(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    lines = int(request.args.get("lines", 50))
    return jsonify({"logs": tail_log(bot_id, lines), "status": get_bot_status(bot_id)})

@app.route("/api/bot/<bot_id>/code")
@login_required
def bot_code(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    script = get_main_script(bot_id, bots)
    code = ""
    if os.path.exists(script):
        with open(script) as f:
            code = f.read()
    return jsonify({"code": code, "name": bots[bot_id]["name"], "token": bots[bot_id]["token"]})

@app.route("/api/bots/status")
@login_required
def all_status():
    bots = load_bots()
    result = {bid: get_bot_status(bid) for bid in bots}
    return jsonify(result)

# ── File Manager APIs ─────────────────────────────────────────────────────────
@app.route("/api/bot/<bot_id>/files")
@login_required
def api_list_files(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    return jsonify({"success": True, "files": list_bot_files(bot_id)})

@app.route("/api/bot/<bot_id>/file/read", methods=["POST"])
@login_required
def api_read_file(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    data = request.json or {}
    filename = secure_filename(data.get("filename", ""))
    if not filename:
        return jsonify({"success": False, "error": "Filename required"}), 400
    file_path = os.path.join(get_bot_dir(bot_id), filename)
    if not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "File not found"}), 404
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return jsonify({"success": True, "content": content, "filename": filename})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/bot/<bot_id>/file/save", methods=["POST"])
@login_required
def api_save_file(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    data = request.json or {}
    filename = secure_filename(data.get("filename", ""))
    content = data.get("content", "")
    if not filename:
        return jsonify({"success": False, "error": "Filename required"}), 400
    file_path = os.path.join(get_bot_dir(bot_id), filename)
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/bot/<bot_id>/upload", methods=["POST"])
@login_required
def api_upload_file(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file in request. Use field name 'file'"}), 400
    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"success": False, "error": "Empty filename"}), 400
    filename = secure_filename(file.filename)
    bot_dir = get_bot_dir(bot_id)
    file_path = os.path.join(bot_dir, filename)
    try:
        file.save(file_path)
        extracted = False
        if filename.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(bot_dir)
                extracted = True
            except Exception as zip_err:
                logger.warning("Zip extract failed: %s", zip_err)
        return jsonify({"success": True, "filename": filename, "extracted": extracted})
    except Exception as e:
        logger.error("Upload failed for bot %s: %s", bot_id, e)
        return jsonify({"success": False, "error": str(e)}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({"success": False, "error": "File too large. Max size is 50MB."}), 413

@app.route("/api/bot/<bot_id>/file/rename", methods=["POST"])
@login_required
def api_rename_file(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    data = request.json or {}
    old_name = secure_filename(data.get("old_name", ""))
    new_name = secure_filename(data.get("new_name", ""))
    if not old_name or not new_name or old_name == new_name:
        return jsonify({"success": False, "error": "Invalid names"}), 400
    bot_dir = get_bot_dir(bot_id)
    old_path = os.path.join(bot_dir, old_name)
    new_path = os.path.join(bot_dir, new_name)
    if not os.path.exists(old_path):
        return jsonify({"success": False, "error": "File not found"}), 404
    if os.path.exists(new_path):
        return jsonify({"success": False, "error": "Target name already exists"}), 400
    try:
        os.rename(old_path, new_path)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/bot/<bot_id>/file/delete", methods=["POST"])
@login_required
def api_delete_file(bot_id):
    if not user_can_access_bot(bot_id):
        return jsonify({"success": False, "error": "Access denied"}), 403
    bots = load_bots()
    if bot_id not in bots:
        return jsonify({"success": False, "error": "Bot not found"}), 404
    data = request.json or {}
    filename = secure_filename(data.get("filename", ""))
    if not filename:
        return jsonify({"success": False, "error": "Filename required"}), 400
    file_path = os.path.join(get_bot_dir(bot_id), filename)
    if not os.path.exists(file_path):
        return jsonify({"success": False, "error": "File not found"}), 404
    try:
        os.remove(file_path)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/bot/<bot_id>/file/download/<filename>")
@login_required
def api_download_file(bot_id, filename):
    if not user_can_access_bot(bot_id):
        return "Access denied", 403
    bots = load_bots()
    if bot_id not in bots:
        return "Bot not found", 404
    filename = secure_filename(filename)
    bot_dir = get_bot_dir(bot_id)
    return send_from_directory(bot_dir, filename, as_attachment=True)

# ── Admin: User Management ────────────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    users = load_users()
    bots = load_bots()
    # Don't expose password hashes
    safe = []
    for uname, u in users.items():
        safe.append({
            "username": uname,
            "created_at": u.get("created_at"),
            "expires_at": u.get("expires_at"),
            "allowed_bots": u.get("allowed_bots", []),
        })
    bot_list = [{"id": bid, "name": b["name"]} for bid, b in bots.items()]
    return jsonify({"success": True, "users": safe, "bots": bot_list})

@app.route("/api/admin/user/create", methods=["POST"])
@admin_required
def admin_create_user():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    allowed_bots = data.get("allowed_bots", [])
    duration_days = data.get("duration_days")  # None = unlimited

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400
    if username == "admin":
        return jsonify({"success": False, "error": "Cannot create user named 'admin'"}), 400

    users = load_users()
    if username in users:
        return jsonify({"success": False, "error": "Username already exists"}), 400

    expires_at = None
    if duration_days:
        expires_at = (datetime.now() + timedelta(days=int(duration_days))).isoformat()

    users[username] = {
        "password_hash": hash_password(password),
        "created_at": datetime.now().isoformat(),
        "expires_at": expires_at,
        "allowed_bots": allowed_bots,
    }
    save_users(users)
    logger.info("User created: %s", username)
    return jsonify({"success": True})

@app.route("/api/admin/user/delete", methods=["POST"])
@admin_required
def admin_delete_user():
    data = request.json or {}
    username = data.get("username", "").strip()
    if not username or username == "admin":
        return jsonify({"success": False, "error": "Invalid username"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "error": "User not found"}), 404
    del users[username]
    save_users(users)
    return jsonify({"success": True})

@app.route("/api/admin/user/update", methods=["POST"])
@admin_required
def admin_update_user():
    data = request.json or {}
    username = data.get("username", "").strip()
    if not username or username == "admin":
        return jsonify({"success": False, "error": "Invalid username"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "error": "User not found"}), 404

    if "password" in data and data["password"]:
        users[username]["password_hash"] = hash_password(data["password"])
    if "allowed_bots" in data:
        users[username]["allowed_bots"] = data["allowed_bots"]
    if "duration_days" in data:
        dd = data["duration_days"]
        if dd:
            users[username]["expires_at"] = (datetime.now() + timedelta(days=int(dd))).isoformat()
        else:
            users[username]["expires_at"] = None

    save_users(users)
    return jsonify({"success": True})

# ── Cleanup ───────────────────────────────────────────────────────────────────
def shutdown(*_):
    logger.info("Shutting down – stopping all bots…")
    for bid in list(running_processes.keys()):
        _stop_proc(bid)
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT,  shutdown)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
