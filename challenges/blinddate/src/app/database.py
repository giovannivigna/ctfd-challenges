import sqlite3

connection = sqlite3.connect('database.db')
cursor = connection.cursor()

# Drop existing tables if they exist
cursor.execute('DROP TABLE IF EXISTS users')
cursor.execute('DROP TABLE IF EXISTS secret_info')

# Create the 'users' table
cursor.execute('''
    CREATE TABLE users (
        first TEXT,
        last TEXT,
        username TEXT PRIMARY KEY
    )
''')

# Create the 'secret_info' table
cursor.execute('''
    CREATE TABLE secret_info (
        username TEXT PRIMARY KEY,       
        ssn TEXT,
        dob TEXT,
        password TEXT
    )
''')

# Insert dummy data into 'users'
cursor.execute("INSERT INTO users (first, last, username) VALUES ('Alice', 'Wonderland', 'alice')")
cursor.execute("INSERT INTO users (first, last, username) VALUES ('Bob', 'Builder', 'bob')")
cursor.execute("INSERT INTO users (first, last, username) VALUES ('Charlie', 'Chocolate', 'charlie')")

# Insert dummy data into 'secret_info'
cursor.execute("INSERT INTO secret_info (username, ssn, dob, password) VALUES ('alice', '123-45-6789', '01-01-1980', 'madhatter')")
cursor.execute("INSERT INTO secret_info (username, ssn, dob, password) VALUES ('bob', '987-65-4321', '12-31-1990', 'canwefixit')")
cursor.execute("INSERT INTO secret_info (username, ssn, dob, password) VALUES ('charlie', '112-56-8888', '02-28-1969', 'ictf{BlindSearchingIsStillSearching}')")

connection.commit()
connection.close()
