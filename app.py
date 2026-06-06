import sqlite3
import hashlib
import os
from flask import Flask, request, session, redirect, url_for, render_template, g, send_from_directory

# VULN #5: Hardcoded secret key — anyone who reads the code can forge session cookies
app = Flask(__name__)
app.secret_key = "supersecret123"

DATABASE = "notevault.db"
UPLOAD_FOLDER = "uploads"


# ---------- DB helpers ----------

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            filename TEXT
        )
    """)
    db.commit()
    db.close()


# ---------- Auth ----------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form.get("email", "")

        # VULN #3: MD5 password hashing — trivially crackable
        hashed = hashlib.md5(password.encode()).hexdigest()

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                (username, hashed, email),
            )
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            error = "Username already taken"

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    # VULN #5 (part 2): No rate limiting — unlimited brute-force attempts
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        hashed = hashlib.md5(password.encode()).hexdigest()

        db = get_db()
        # VULN #1: SQL Injection in login
        user = db.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, hashed)
).fetchone()


        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- Dashboard ----------

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    search = request.args.get("q", "")

    if search:
        # VULN #1 (also here): SQL Injection in search
        # Payload: q = ' UNION SELECT id,1,username,password,NULL FROM users --
        query = f"SELECT * FROM notes WHERE user_id = {session['user_id']} AND title LIKE '%{search}%'"
        notes = db.execute(query).fetchall()
    else:
        notes = db.execute(
            "SELECT * FROM notes WHERE user_id = ?", (session["user_id"],)
        ).fetchall()

    return render_template("dashboard.html", notes=notes, search=search)


# ---------- Notes ----------

@app.route("/note/new", methods=["GET", "POST"])
def new_note():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        # VULN #4: XSS — content stored and rendered without sanitization
        content = request.form["content"]

        filename = None
        if "file" in request.files:
            f = request.files["file"]
            if f.filename:
                # VULN #6: Path Traversal — filename not sanitized
                # Payload: filename = "../../app.py"
                filename = f.filename
                f.save(os.path.join(UPLOAD_FOLDER, filename))

        db = get_db()
        db.execute(
            "INSERT INTO notes (user_id, title, content, filename) VALUES (?, ?, ?, ?)",
            (session["user_id"], title, content, filename),
        )
        db.commit()
        return redirect(url_for("dashboard"))

    return render_template("new_note.html")


@app.route("/note/<int:note_id>")
def view_note(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    # VULN #2: IDOR — no ownership check, any logged-in user can view any note
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()

    if not note:
        return "Note not found", 404

    return render_template("view_note.html", note=note)


@app.route("/note/<int:note_id>/delete", methods=["POST"])
def delete_note(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    # VULN #2: IDOR — no ownership check on delete either
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # VULN #6: Path Traversal served here too
    return send_from_directory(UPLOAD_FOLDER, filename)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
