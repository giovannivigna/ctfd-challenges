import sqlite3
from flask import Flask, request, render_template, redirect, url_for, session, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "super_secret_key"

FLAG = open("/flag").read().strip()

# Initialize database
def init_db():
    with sqlite3.connect("database.db") as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS feedback (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        message TEXT NOT NULL)''')
        conn.commit()

init_db()

# Database helper function
def query_db(query, args=(), one=False):
    with sqlite3.connect("database.db") as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query, args)
        rv = cur.fetchall()
        return (rv[0] if rv else None) if one else rv


@app.route("/")
def home():
    if "user" in session:
        return f"Welcome {session['user']}! <br><a href='/feedback'>Leave Feedback</a> | <a href='/logout'>Logout</a>"
    return "<a href='/login'>Login</a> | <a href='/register'>Register</a>"


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])
        try:
            with sqlite3.connect("database.db") as conn:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                conn.commit()
            return redirect(url_for("login"))
        except:
            return "User already exists!"
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
        
        if user and check_password_hash(user["password"], password):
            session["user"] = username
            return redirect(url_for("home"))
        return "Invalid credentials!"
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        message = request.form["message"]
        username = session["user"]

        # Store feedback in DB
        with sqlite3.connect("database.db") as conn:
            conn.execute("INSERT INTO feedback (username, message) VALUES (?, ?)", (username, message))
            conn.commit()

        # 🚨 Vulnerable: Directly injecting user input into a template
        return render_template_string(f"<h1>Thank you, {username}!</h1><p>Your feedback: {message}</p>")

    return render_template("feedback.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1526, debug=False)