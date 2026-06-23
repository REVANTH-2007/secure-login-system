from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
import sqlite3
import re

app = Flask(__name__)
app.secret_key = "super_secret_key"

bcrypt = Bcrypt(app)

# Database Setup
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

init_db()

# Home
@app.route('/')
def home():
    return redirect('/login')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not re.match(r'^[A-Za-z0-9_]{3,20}$', username):
            flash("Invalid username")
            return redirect('/register')

        if len(password) < 6:
            flash("Password must be at least 6 characters")
            return redirect('/register')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users(username,email,password) VALUES(?,?,?)",
                (username, email, hashed_password)
            )

            conn.commit()
            conn.close()

            flash("Registration Successful")
            return redirect('/login')

        except Exception:
            flash("User already exists")
            return redirect('/register')

    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[3], password):
            session['user'] = username
            return redirect('/dashboard')

        flash("Invalid Credentials")

    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
def dashboard():

    if 'user' not in session:
        return redirect('/login')

    return render_template('dashboard.html', user=session['user'])

# Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged Out Successfully")
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
