from flask import Flask, request, session, redirect, url_for, render_template_string, make_response
import hashlib
import os
import logging

# Admin credentials
ADMIN_PASSWORD_HASH = "5da030effde1751151e85f5e542d6a5bd15cc933212ce268fcfd53ee9358eb4e"
ADMIN_USER_AGENT = "MotorolaStarTAC/1.0"

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.logger.setLevel(logging.DEBUG)

# In-memory storage for messages and users
users = {}
users["admin"] = ADMIN_PASSWORD_HASH
messages = []

# Prepare flag
FLAG_PATH = "/flag"


index_template = """
<h2>Public Message Board</h2>
{% for message in messages %}
    <p><b>{{ message['user'] }}</b>: {{ message['content'] }}</p>
{% endfor %}

<h3>{% if session.username %}Welcome, {{ session.username }}{% else %}Not logged in{% endif %}</h3>

{% if session.username %}
    <form action="/logout" method="POST"><button type="submit">Logout</button></form>

    <h4>Post Message</h4>
    <form action="/post" method="POST">
        <textarea name="content"></textarea>
        <button type="submit">Post</button>
    </form>

    {% if session.username == 'admin' %}
        <h4>Admin: Post from file</h4>
        <form action="/admin_post" method="POST">
            <input type="text" name="filename" placeholder="File to read">
            <button type="submit">Post File Content</button>
        </form>
    {% endif %}
{% else %}
    <h4>Login</h4>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>

    <h4>Register</h4>
    <form action="/register" method="POST">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Register</button>
    </form>
{% endif %}
"""

@app.route("/")
def index():
    username = session.get("username")
    status = request.cookies.get("status")
    if username == "admin" or status == "admin":
        visible_messages = messages  # Admin sees everything
    else:
        visible_messages = [m for m in messages if m['user'] != 'admin']  # Regular users only see user posts
    return render_template_string(index_template, messages=visible_messages)

@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    if username in users:
        return "User already exists!"
    users[username] = hashlib.sha256(password.encode()).hexdigest()
    return redirect(url_for("index"))

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    if username == "admin":
        if hashlib.sha256(password.encode()).hexdigest() != ADMIN_PASSWORD_HASH:
            return "Invalid credentials!", 403
    else:
        if username not in users or users[username] != hashlib.sha256(password.encode()).hexdigest():
            return "Invalid credentials!", 403

    session["username"] = username
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("username", username)
    return resp

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("username", None)
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("username", "", expires=0)
    return resp

@app.route("/post", methods=["POST"])
def post_message():
    username = request.cookies.get("username")
    if not username:
        return "Not authenticated!", 403
    content = request.form["content"]
    messages.append({"user": username, "content": content})
    return redirect(url_for("index"))

@app.route("/admin_post", methods=["POST"])
def admin_post():
    username = request.cookies.get("username")
    status = "user" # default
    if (username == "admin"):
        status = "admin"
    else:
        try:
            status = request.cookies.get("status")
        except:
            status = "user"
    user_agent = request.headers.get("User-Agent") 
    app.logger.debug(f"Received request from {username} using {user_agent} with status {status}")
    if status != "admin":
        return "Only admin can use this feature!", 403
    if user_agent != ADMIN_USER_AGENT:
        return "Invalid User-Agent!", 403
        
    filename = request.form["filename"]
    app.logger.debug(f"Opening file {filename} for posting...")
    try:
        with open(filename, "r") as f:
            content = f.read().strip()
    except FileNotFoundError:
        content = f"FILE {filename} NOT FOUND"
    messages.append({"user": "admin", "content": content})
    return redirect(url_for("index"))
    
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5544)