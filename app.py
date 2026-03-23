from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secretkey"

def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# Create table
def create_table():
    conn = get_db()
    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        is_verified BOOLEAN DEFAULT FALSE
    )
    ''')
    conn.close()

create_table()

# Home
@app.route("/")
def home():
    return redirect("/login")

# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        conn = get_db()
        try:
            conn.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                         (name, email, password))
            conn.commit()
            flash("Registered! Please verify email.")
            return redirect("/verify")
        except:
            flash("Email already exists!")
        finally:
            conn.close()

    return render_template("register.html")

# EMAIL VERIFY (DEMO)
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        email = request.form["email"]
        conn = get_db()
        conn.execute("UPDATE users SET is_verified=1 WHERE email=?", (email,))
        conn.commit()
        conn.close()
        flash("Email Verified! Please Login.")
        return redirect("/login")
    return render_template("verify.html")

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()

        if user:
            if user["is_verified"] == False:
                flash("Please verify your email first!")
                return redirect("/verify")

            if check_password_hash(user["password"], password):
                session["user"] = user["name"]
                session["role"] = user["role"]
                session["id"] = user["id"]
                return redirect("/dashboard")

        flash("Invalid Credentials!")

    return render_template("login.html")

# DASHBOARD
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return render_template("dashboard.html", user=session["user"])

# PROFILE
@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect("/login")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["id"],)).fetchone()
    conn.close()

    return render_template("profile.html", user=user)

# ADMIN PANEL
@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return redirect("/dashboard")

    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()

    return render_template("admin.html", users=users)

# DELETE USER
@app.route("/delete/<int:id>")
def delete(id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect("/admin")

# EDIT USER
@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit(id):
    conn = get_db()

    if request.method == "POST":
        name = request.form["name"]
        conn.execute("UPDATE users SET name=? WHERE id=?", (name, id))
        conn.commit()
        conn.close()
        return redirect("/admin")

    user = conn.execute("SELECT * FROM users WHERE id=?", (id,)).fetchone()
    conn.close()
    return render_template("edit_user.html", user=user)

# RESET PASSWORD
@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        email = request.form["email"]
        new_pass = generate_password_hash(request.form["password"])

        conn = get_db()
        conn.execute("UPDATE users SET password=? WHERE email=?", (new_pass, email))
        conn.commit()
        conn.close()

        flash("Password Reset Successful!")
        return redirect("/login")

    return render_template("reset_password.html")

# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)