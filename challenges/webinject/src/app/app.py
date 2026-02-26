from flask import Flask, g, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# Define the database location
DATABASE = "app.db"  # Persistent file

# Initialize the database with a users table
def init_db():
    if not os.path.exists(DATABASE):  # Only initialize if database file does not exist
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
            cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")
            conn.commit()

# Get the SQLite database connection for the current thread
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

# Close the database connection when the request ends
@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# Vulnerable login route
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Vulnerable query (prone to SQL injection)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        db = get_db()
        cursor = db.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        
        with open("/flag", "r") as f:
            flag = f.read().strip()

        if user:
            return f"""<h1>Welcome, {user['username']}!</h1>
            <p>The flag is {flag}</p>"""
        
        else:
            return """<h1>Login failed!</h1>
            <p>I have logged your IP address and I started a search... I am coming for you!</p>"""

    return render_template_string('''
        <h1>Flag vault</h1>
        <p>Welcome to the flag vault.</p>
        <p>Access is restricted. All abuses will be prosecuted.</p>
                                
                                  
        <form method="POST">                            
            <label>Username: <input type="text" name="username"></label><br>
            <label>Password: <input type="password" name="password"></label><br>
            <button type="submit">Login</button>
        </form>
    ''')

if __name__ == "__main__":
    # Initialize the database when the app starts
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
