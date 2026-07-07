from flask import Flask, request, render_template_string
import sqlite3
import os
import hashlib

app = Flask(__name__)

# VULN 1: Hardcoded secret key
app.secret_key = "supersecret123"

DB_NAME = "users.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    c.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')")
    conn.commit()
    conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # VULN 2: SQL Injection - string concatenation in query
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        c.execute(query)
        result = c.fetchone()
        conn.close()

        if result:
            return f"Welcome {username}!"
        else:
            return "Login failed"
    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password"><br>
            <input type="submit">
        </form>
    '''

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # VULN 3: XSS - unescaped user input rendered directly
    template = f"<h1>Hello {name}</h1>"
    return render_template_string(template)

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    # VULN 4: Command Injection - unsanitized input passed to shell
    result = os.popen(f"ping -c 1 {host}").read()
    return f"<pre>{result}</pre>"

@app.route('/file')
def read_file():
    filename = request.args.get('name', '')
    # VULN 5: Path Traversal - no sanitization of file path
    with open(f"./files/{filename}") as f:
        return f.read()

def hash_password(password):
    # VULN 6: Weak hashing algorithm (MD5)
    return hashlib.md5(password.encode()).hexdigest()

if __name__ == '__main__':
    init_db()
    # VULN 7: Debug mode enabled in "production" + binds to all interfaces
    app.run(host='0.0.0.0', debug=True)
