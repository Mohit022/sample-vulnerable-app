import sqlite3
import subprocess
import json
import os
import hashlib
from flask import Flask, request, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient

app = Flask(__name__)

# -----------------------------------------------------------------------
# FIX (CWE-798): Removed hardcoded API token — load from environment only
# -----------------------------------------------------------------------
API_TOKEN = os.environ.get("API_TOKEN", "")

# MongoDB connection
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["app_db"]
users_collection = mongo_db["users"]

# -----------------------------------------------------------------------
# FIX (CWE-732): Moved DB out of world-readable /tmp to a restricted path
# -----------------------------------------------------------------------
DB_PATH = os.environ.get("DB_PATH", "/var/lib/app/app_users.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cur = conn.cursor()
cur.execute(
    "CREATE TABLE IF NOT EXISTS users "
    "(id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
)
conn.commit()

# -----------------------------------------------------------------------
# Rate limiter (CWE-307 / missing rate-limit on auth + SSTI endpoints)
# -----------------------------------------------------------------------
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)


# -----------------------------------------------------------------------
# FIX (CWE-256): Hash passwords with SHA-256 before storage.
# In production use bcrypt or argon2 instead.
# -----------------------------------------------------------------------
def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def add_user(username: str, password: str) -> None:
    # FIX (CWE-89): Parameterized query — no more string formatting
    hashed = _hash_password(password)
    cur.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hashed),
    )
    conn.commit()


def get_user(username: str):
    # FIX (CWE-89): Parameterized query
    cur.execute(
        "SELECT id, username FROM users WHERE username = ?",
        (username,),
    )
    return cur.fetchall()


def run_shell(command: str) -> str:
    # FIX (CWE-78): shell=False with explicit argument list — no sh -c injection
    allowed_commands = {"echo", "whoami", "date", "uptime"}
    parts = command.split()
    if not parts or parts[0] not in allowed_commands:
        raise ValueError(f"Command '{parts[0] if parts else ''}' is not allowed.")
    result = subprocess.run(parts, capture_output=True, text=True, shell=False, timeout=10)
    return result.stdout


def deserialize_blob(blob: bytes):
    # FIX (CWE-502): Replaced pickle.loads with safe JSON parsing
    return json.loads(blob)


# -----------------------------------------------------------------------
# FIX (CWE-94 / SSTI): name passed as context variable, never embedded
# in the template string before rendering.
# Rate-limited to 30 req/min to prevent fuzzing.
# -----------------------------------------------------------------------
@app.route("/greet")
@limiter.limit("30 per minute")
def greet():
    name = request.args.get("name", "World")
    # Safe: Jinja2 auto-escapes {{ name }} — user input never interpolated
    # into the template source itself.
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)


# -----------------------------------------------------------------------
# FIX (CWE-943 / NoSQL Injection): Validate that username and password
# are plain strings before passing to pymongo.
# Rate-limited to 10 req/min to prevent credential stuffing.
# -----------------------------------------------------------------------
@app.route("/user")
@limiter.limit("10 per minute")
def get_mongo_user():
    username = request.args.get("username")
    password = request.args.get("password")

    # Reject non-string types (e.g. dicts injected via query params like ?username[$ne]=x)
    if not isinstance(username, str) or not isinstance(password, str):
        return "Invalid input.", 400
    if not username or not password:
        return "Missing credentials.", 400

    # Hash password before comparison to match stored hashed value
    hashed = _hash_password(password)
    user = users_collection.find_one({"username": username, "password": hashed})
    if user:
        return f"Welcome, {user.get('username')}!"
    return "User not found.", 404


if __name__ == "__main__":
    # Seed with hashed passwords
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    print("API_TOKEN configured:", bool(API_TOKEN))
    print(get_user("alice"))
    print(run_shell("echo Hello"))
    app.run(host="0.0.0.0", port=5000)
