from flask import Flask, request
import sqlite3

app = Flask(__name__)

# Dummy database setup
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return '''
    <form method="POST" action="/search">
        <input name="username" type="text" placeholder="Enter username"/>
        <input type="submit" value="Search"/>
    </form> 
    '''

@app.route('/search', methods=['POST'])
def search():
    username = request.form['username']
    conn = get_db_connection()
    # Vulnerable SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    users = conn.execute(query).fetchall()
    conn.close()

    output = '<h2>Search Results</h2>'
    for user in users:
        output += f"<p>First Name: {user['first']}, Last Name: {user['last']}, Username: {user['username']}</p>"

    return output

if __name__ == '__main__':
    app.run(debug=True)
