from datetime import datetime
import re
import sqlite3
from functools import wraps

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "task3-professional-auth-app"
app.config["DATABASE"] = "database.db"

EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
PASSWORD_RULES = (
    "Password must be at least 8 characters long and include uppercase, "
    "lowercase, and a number."
)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_verified INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            roll_number TEXT NOT NULL UNIQUE,
            course TEXT NOT NULL,
            year_level TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            created_by INTEGER,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
        """
    )
    db.commit()
    ensure_column("role", "TEXT NOT NULL DEFAULT 'user'")
    ensure_column("is_verified", "INTEGER NOT NULL DEFAULT 0")
    ensure_created_at_column()
    ensure_default_admin()


def ensure_column(column_name, definition):
    db = get_db()
    columns = {column["name"] for column in db.execute("PRAGMA table_info(users)").fetchall()}
    if column_name not in columns:
        db.execute(f"ALTER TABLE users ADD COLUMN {column_name} {definition}")
        db.commit()


def ensure_created_at_column():
    db = get_db()
    columns = {column["name"] for column in db.execute("PRAGMA table_info(users)").fetchall()}
    if "created_at" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
        db.execute(
            """
            UPDATE users
            SET created_at = ?
            WHERE created_at IS NULL OR TRIM(created_at) = ''
            """,
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
        )
        db.commit()


def ensure_default_admin():
    db = get_db()
    admin = db.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1").fetchone()
    if admin:
        return

    db.execute(
        """
        INSERT OR IGNORE INTO users (name, email, password, role, is_verified, created_at)
        VALUES (?, ?, ?, 'admin', 1, ?)
        """,
        (
            "System Admin",
            "admin@task3.local",
            generate_password_hash("Admin123"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    db.commit()


def validate_email(email):
    return bool(EMAIL_PATTERN.match(email or ""))


def validate_password(password):
    if len(password or "") < 8:
        return False
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    return has_upper and has_lower and has_digit


def validate_student_form(full_name, roll_number, course, year_level, email, phone):
    if len(full_name) < 3:
        return "Student name must contain at least 3 characters."
    if len(roll_number) < 2:
        return "Roll number is required."
    if len(course) < 2:
        return "Course name is required."
    if len(year_level) < 1:
        return "Year or semester is required."
    if not validate_email(email):
        return "Please enter a valid student email address."
    if len(phone) < 10:
        return "Phone number should contain at least 10 digits."
    return None


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Administrator access is required for that page.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped_view


@app.before_request
def load_logged_in_user():
    g.current_user = None
    user_id = session.get("user_id")
    if user_id:
        g.current_user = get_db().execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if g.current_user is None:
            session.clear()


@app.context_processor
def inject_now():
    return {"now": datetime.now()}


@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("students"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or len(name) < 3:
            flash("Please enter a valid full name with at least 3 characters.", "warning")
        elif not validate_email(email):
            flash("Please enter a valid email address.", "warning")
        elif not validate_password(password):
            flash(PASSWORD_RULES, "warning")
        elif password != confirm_password:
            flash("Password and confirm password do not match.", "warning")
        else:
            db = get_db()
            existing_user = db.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()
            if existing_user:
                flash("That email is already registered. Please log in instead.", "danger")
            else:
                db.execute(
                    """
                    INSERT INTO users (name, email, password, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        name,
                        email,
                        generate_password_hash(password),
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ),
                )
                db.commit()
                flash("Registration successful. Please verify your email to activate the account.", "success")
                return redirect(url_for("verify"))

    return render_template("register.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not validate_email(email):
            flash("Enter the same valid email address used during registration.", "warning")
        else:
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user is None:
                flash("No account was found for that email.", "danger")
            elif user["is_verified"]:
                flash("This account is already verified. Please log in.", "info")
                return redirect(url_for("login"))
            else:
                db.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
                db.commit()
                flash("Email verified successfully. You can log in now.", "success")
                return redirect(url_for("login"))

    return render_template("verify.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user is None or not check_password_hash(user["password"], password):
            flash("Invalid email or password.", "danger")
        elif not user["is_verified"]:
            flash("Please verify your email before logging in.", "warning")
            return redirect(url_for("verify"))
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(url_for("students"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user_count = db.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
    verified_count = db.execute(
        "SELECT COUNT(*) AS total FROM users WHERE is_verified = 1"
    ).fetchone()["total"]
    student_count = db.execute("SELECT COUNT(*) AS total FROM students").fetchone()["total"]
    recent_users = db.execute(
        """
        SELECT name, email, role, is_verified, created_at
        FROM users
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 5
        """
    ).fetchall()

    return render_template(
        "dashboard.html",
        stats={
            "user_count": user_count,
            "verified_count": verified_count,
            "student_count": student_count,
            "admin_count": db.execute(
                "SELECT COUNT(*) AS total FROM users WHERE role = 'admin'"
            ).fetchone()["total"],
        },
        recent_users=recent_users,
    )


@app.route("/students", methods=["GET", "POST"])
@login_required
def students():
    db = get_db()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        roll_number = request.form.get("roll_number", "").strip().upper()
        course = request.form.get("course", "").strip()
        year_level = request.form.get("year_level", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()

        validation_error = validate_student_form(
            full_name, roll_number, course, year_level, email, phone
        )

        if validation_error:
            flash(validation_error, "warning")
        else:
            existing_student = db.execute(
                "SELECT id FROM students WHERE roll_number = ?", (roll_number,)
            ).fetchone()
            if existing_student:
                flash("That roll number already exists. Please use a unique roll number.", "danger")
            else:
                db.execute(
                    """
                    INSERT INTO students (
                        full_name, roll_number, course, year_level, email, phone, created_by, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        full_name,
                        roll_number,
                        course,
                        year_level,
                        email,
                        phone,
                        session["user_id"],
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ),
                )
                db.commit()
                flash("Student added successfully.", "success")
                return redirect(url_for("students"))

    search = request.args.get("search", "").strip()
    if search:
        student_rows = db.execute(
            """
            SELECT students.*, users.name AS creator_name
            FROM students
            LEFT JOIN users ON users.id = students.created_by
            WHERE full_name LIKE ? OR roll_number LIKE ? OR course LIKE ? OR year_level LIKE ?
            ORDER BY datetime(students.created_at) DESC, students.id DESC
            """,
            (f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"),
        ).fetchall()
    else:
        student_rows = db.execute(
            """
            SELECT students.*, users.name AS creator_name
            FROM students
            LEFT JOIN users ON users.id = students.created_by
            ORDER BY datetime(students.created_at) DESC, students.id DESC
            """
        ).fetchall()

    return render_template("students.html", students=student_rows, search=search)


@app.route("/students/edit/<int:student_id>", methods=["GET", "POST"])
@login_required
def edit_student(student_id):
    db = get_db()
    student = db.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()

    if student is None:
        flash("Student record not found.", "danger")
        return redirect(url_for("students"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        roll_number = request.form.get("roll_number", "").strip().upper()
        course = request.form.get("course", "").strip()
        year_level = request.form.get("year_level", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()

        validation_error = validate_student_form(
            full_name, roll_number, course, year_level, email, phone
        )

        if validation_error:
            flash(validation_error, "warning")
        else:
            duplicate = db.execute(
                "SELECT id FROM students WHERE roll_number = ? AND id != ?",
                (roll_number, student_id),
            ).fetchone()
            if duplicate:
                flash("Another student already uses that roll number.", "danger")
            else:
                db.execute(
                    """
                    UPDATE students
                    SET full_name = ?, roll_number = ?, course = ?, year_level = ?, email = ?, phone = ?
                    WHERE id = ?
                    """,
                    (full_name, roll_number, course, year_level, email, phone, student_id),
                )
                db.commit()
                flash("Student details updated successfully.", "success")
                return redirect(url_for("students"))

    return render_template("edit_student.html", student=student)


@app.route("/students/delete/<int:student_id>", methods=["POST"])
@login_required
def delete_student(student_id):
    db = get_db()
    deleted = db.execute("DELETE FROM students WHERE id = ?", (student_id,))
    db.commit()

    if deleted.rowcount:
        flash("Student deleted successfully.", "info")
    else:
        flash("Student record not found.", "danger")
    return redirect(url_for("students"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if len(name) < 3:
            flash("Name should contain at least 3 characters.", "warning")
        else:
            db.execute("UPDATE users SET name = ? WHERE id = ?", (name, user["id"]))
            db.commit()
            session["user_name"] = name
            flash("Profile updated successfully.", "success")
            return redirect(url_for("profile"))

    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("profile.html", user=user)


@app.route("/admin")
@login_required
@admin_required
def admin():
    search = request.args.get("search", "").strip()
    db = get_db()

    if search:
        users = db.execute(
            """
            SELECT * FROM users
            WHERE name LIKE ? OR email LIKE ? OR role LIKE ?
            ORDER BY datetime(created_at) DESC, id DESC
            """,
            (f"%{search}%", f"%{search}%", f"%{search}%"),
        ).fetchall()
    else:
        users = db.execute(
            "SELECT * FROM users ORDER BY datetime(created_at) DESC, id DESC"
        ).fetchall()

    return render_template("admin.html", users=users, search=search)


@app.route("/edit/<int:user_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        flash("User not found.", "danger")
        return redirect(url_for("admin"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        role = request.form.get("role", "user").strip().lower()
        is_verified = 1 if request.form.get("is_verified") == "1" else 0

        if len(name) < 3:
            flash("Name should contain at least 3 characters.", "warning")
        elif role not in {"admin", "user"}:
            flash("Please choose a valid role.", "warning")
        else:
            db.execute(
                """
                UPDATE users
                SET name = ?, role = ?, is_verified = ?
                WHERE id = ?
                """,
                (name, role, is_verified, user_id),
            )
            db.commit()

            if session.get("user_id") == user_id:
                session["user_name"] = name
                session["role"] = role

            flash("User details updated successfully.", "success")
            if session.get("user_id") == user_id and role != "admin":
                return redirect(url_for("dashboard"))
            return redirect(url_for("admin"))

    return render_template("edit_user.html", user=user)


@app.route("/delete/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete(user_id):
    if session.get("user_id") == user_id:
        flash("You cannot delete the currently logged-in admin account.", "danger")
        return redirect(url_for("admin"))

    db = get_db()
    deleted = db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()

    if deleted.rowcount:
        flash("User deleted successfully.", "info")
    else:
        flash("User not found.", "danger")
    return redirect(url_for("admin"))


@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not validate_email(email):
            flash("Please enter a valid email address.", "warning")
        elif not validate_password(password):
            flash(PASSWORD_RULES, "warning")
        elif password != confirm_password:
            flash("Password and confirm password do not match.", "warning")
        else:
            db = get_db()
            user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if user is None:
                flash("No account exists with that email address.", "danger")
            else:
                db.execute(
                    "UPDATE users SET password = ? WHERE email = ?",
                    (generate_password_hash(password), email),
                )
                db.commit()
                flash("Password reset successful. Please log in with your new password.", "success")
                return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True)
