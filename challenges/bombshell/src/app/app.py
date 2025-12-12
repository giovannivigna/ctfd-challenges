from flask import Flask, request, session, redirect, url_for, render_template_string
import os
import subprocess
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = open('/flag').read()

DB_FILE = 'users.db'

# Initialize database
def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT)''')
        conn.commit()
        conn.close()

init_db()

# Simple template for login and registration
TEMPLATE = """
<!doctype html>
<title>Bombshell</title>
<h2>{{title}}</h2>
{% if error %}
<p style="color:red">{{error}}</p>
{% endif %}
<form method="POST">
    Username: <input type="text" name="username"><br>
    Password: <input type="password" name="password"><br>
    <input type="submit" value="{{button}}">
</form>
<a href="{{link}}">{{link_text}}</a>
"""

@app.route('/')
def index():
    if 'user' in session:
        return f"Hello, {session['user']}! <br><a href='/scan'>Run System Scan</a> | <a href='/logout'>Logout</a>"
    return "Welcome! <a href='/login'>Login</a> or <a href='/register'>Register</a>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        conn.close()

        if result and result[0] == hashlib.sha256(password.encode()).hexdigest():
            session['user'] = username
            return redirect(url_for('index'))
        else:
            return render_template_string(TEMPLATE, title="Login", button="Login", link="/register", link_text="Register", error="Invalid credentials")
    return render_template_string(TEMPLATE, title="Login", button="Login", link="/register", link_text="Register", error=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashlib.sha256(password.encode()).hexdigest()))
            conn.commit()
        except sqlite3.IntegrityError:
            return render_template_string(TEMPLATE, title="Register", button="Register", link="/login", link_text="Login", error="User already exists")

        conn.close()
        return redirect(url_for('login'))
    return render_template_string(TEMPLATE, title="Register", button="Register", link="/login", link_text="Login", error=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        target = request.form['target']

        cmd = f"ping -c 1 {target}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = e.output

        return f"<pre>{output.decode()}</pre><a href='/scan'>Back</a>"

    return """
    <h2>System Scan Based on the ping utility</h2>
    <form method="POST">
        Target IP/Host: <input type="text" name="target">
        <input type="submit" value="Run Scan">
    </form>
    <a href="/">Home</a>
    """

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=12721)