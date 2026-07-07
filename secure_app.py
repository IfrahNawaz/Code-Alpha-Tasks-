from flask import Flask, request, render_template_string, escape
import sqlite3
import subprocess
import os
import bcrypt
import re

app = Flask(__name__)

# FIX 1: Load secret from environment, not hardcoded
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

DB_NAME = "users.db"
SAFE_FILES_DIR = os.path.abspath("./files")

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)")
    conn.commit()
    conn.close()

def hash_password(password: str) -> bytes:
    # FIX: Strong hashing with bcrypt (includes salt automatically)
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # FIX: Parameterized query prevents SQL Injection
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if row and verify_password(password, row[0]):
            return f"Welcome {escape(username)}!"
        return "Login failed"
    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit">
        </form>
    '''

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # FIX: escape() prevents XSS by encoding HTML special characters
    template = f"<h1>Hello {escape(name)}</h1>"
    return render_template_string(template)

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    # FIX: Strict allow-list validation + no shell=True, no string interpolation
    if not re.match(r'^[a-zA-Z0-9\.\-]+$', host):
        return "Invalid host", 400
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True, text=True, timeout=5
        )
        return f"<pre>{escape(result.stdout)}</pre>"
    except subprocess.TimeoutExpired:
        return "Request timed out", 408

@app.route('/file')
def read_file():
    filename = request.args.get('name', '')
    # FIX: Resolve path and confirm it stays inside the safe directory
    requested_path = os.path.abspath(os.path.join(SAFE_FILES_DIR, filename))
    if not requested_path.startswith(SAFE_FILES_DIR):
        return "Access denied", 403
    if not os.path.isfile(requested_path):
        return "File not found", 404
    with open(requested_path) as f:
        return escape(f.read())

if __name__ == '__main__':
    init_db()
    # FIX: Debug off, bind to localhost only in dev; use a real WSGI server in prod
    app.run(host='127.0.0.1', debug=False)
