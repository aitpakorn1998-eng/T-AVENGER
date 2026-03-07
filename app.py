import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")
IMAGE_DIR = os.path.join(BASE_DIR, "static", "images")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)

    default_users = [
        ("Admin1", "7Kf2Qp91"),
        ("Admin2", "vM4xT8rA"),
        ("Admin3", "B6qZ1LpR"),
        ("Admin4", "W9dF3sTx"),
        ("Admin5", "nE2K8yQa"),
        ("Admin6", "P5gH1LmZ"),
        ("Admin7", "rT7xJ4wN"),
        ("Admin8", "Y3sK6vPb"),
        ("Admin9", "hQ2L9dRf"),
        ("Admin10", "Z8mF4xTa"),
        ("Admin11", "jR6sW3pQ"),
        ("Admin12", "kT9n2LxV"),
        ("Admin13", "X4vP7yHd"),
        ("Admin14", "D3fG8sKa"),
        ("Admin15", "bN5L2QwR"),
        ("Admin16", "uP7xC4zM"),
    ]

    for username, password in default_users:
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing = cur.fetchone()
        if not existing:
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )

    conn.commit()
    conn.close()


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def get_image_list():
    if not os.path.exists(IMAGE_DIR):
        return []

    allowed_ext = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
    ignore_files = {"favicon.ico"}

    files = []
    for file_name in os.listdir(IMAGE_DIR):
        full_path = os.path.join(IMAGE_DIR, file_name)

        if not os.path.isfile(full_path):
            continue

        _, ext = os.path.splitext(file_name.lower())
        if ext in allowed_ext and file_name.lower() not in ignore_files:
            files.append(file_name)

    files.sort()
    return files


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("กรุณากรอกชื่อผู้ใช้และรหัสผ่าน")
            return render_template("login.html")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))

        flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    images = get_image_list()

    if not images:
        return "ไม่พบรูปในโฟลเดอร์ static/images"

    image = images[0]
    return render_template(
        "index.html",
        image=image,
        images=images,
        username=session.get("username", "")
    )


with app.app_context():
    init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)