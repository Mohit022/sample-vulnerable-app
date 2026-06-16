import sqlite3
import subprocess
import pickle
import os
from flask import Flask, request, render_template_string
from pymongo import MongoClient
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Rate limiter — keyed by client IP
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# MongoDB connection (Issue 6: NoSQL Injection)
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["app_db"]
users_collection = mongo_db["users"]

# hardcoded API token (Issue 1)
API_TOKEN = "AKIAEXAMPLERAWTOKEN12345"

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # SQL injection vulnerability via string formatting (Issue 3)
    sql = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, password)
    cur.execute(sql)
    conn.commit()

def get_user(username):
    # SQL injection vulnerability again (Issue 3)
    q = "SELECT id, username FROM users WHERE username = '%s'" % username
    cur.execute(q)
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input (Issue 4)
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # insecure deserialization of untrusted data (Issue 5)
    return pickle.loads(blob)

# -----------------------------------------------------------------------
# Issue 6: SSTI via Jinja2 render_template_string()
# Payload: ?name={{config}} leaks config; ?name={{''.__class__.__mro__[1].__subclasses__()}} -> RCE
# Rate limit: 10 requests/minute per IP — limits SSTI brute-force/enumeration attempts
# -----------------------------------------------------------------------
@app.route("/greet")
@limiter.limit("10 per minute")
def greet():
    name = request.args.get("name", "World")
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)  # VULNERABLE


# -----------------------------------------------------------------------
# Issue 7: NoSQL Injection via unsanitized MongoDB query
# Payload: ?username[$ne]=x&password[$ne]=x -> authentication bypass
# Rate limit: 5 requests/minute per IP — prevents brute-force auth attacks
# -----------------------------------------------------------------------
@app.route("/user")
@limiter.limit("5 per minute")
def get_mongo_user():
    username = request.args.get("username")
    password = request.args.get("password")
    user = users_collection.find_one({"username": username, "password": password})  # VULNERABLE
    if user:
        return f"Welcome, {user.get('username')}!"
    return "User not found.", 404


if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Demonstrate risky calls
    print("API_TOKEN in use:", API_TOKEN)
    print(get_user("alice' OR '1'='1"))  # demonstrates SQLi payload
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize an arbitrary blob (will likely raise)
        deserialize_blob(b"not-a-valid-pickle")
    except Exception as e:
        print("Deserialization error:", e)
