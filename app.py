import os
import sqlite3
import secrets
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

GAME_UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads", "games")
BONUS_UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads", "bonus")

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}

os.makedirs(GAME_UPLOAD_DIR, exist_ok=True)
os.makedirs(BONUS_UPLOAD_DIR, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def allowed_file(filename):
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS


def clean_name(filename):
    return secure_filename(filename)


def random_name(filename):
    name, ext = os.path.splitext(clean_name(filename))
    token = secrets.token_hex(4)
    return f"{name}_{token}{ext.lower()}"


def get_files_from(folder_path):
    files = []
    if not os.path.exists(folder_path):
        return files

    for file_name in os.listdir(folder_path):
        full_path = os.path.join(folder_path, file_name)
        if os.path.isfile(full_path) and allowed_file(file_name):
            files.append(file_name)

    files.sort(key=lambda x: x.lower())
    return files


def get_game_images():
    return get_files_from(GAME_UPLOAD_DIR)


def get_bonus_images():
    return get_files_from(BONUS_UPLOAD_DIR)


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

    cur.execute("PRAGMA table_info(users)")
    columns = [row["name"] for row in cur.fetchall()]

    if "is_admin" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")

    if "is_owner" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN is_owner INTEGER NOT NULL DEFAULT 0")

    if "show_random" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN show_random INTEGER NOT NULL DEFAULT 1")

    if "show_manage" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN show_manage INTEGER NOT NULL DEFAULT 0")

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
            cur.execute("""
                INSERT INTO users (
                    username, password_hash, is_admin, is_owner,
                    show_random, show_manage
                ) VALUES (?, ?, 1, 0, 1, 0)
            """, (username, generate_password_hash(password)))
        else:
            cur.execute("""
                UPDATE users
                SET is_admin = 1,
                    is_owner = 0,
                    show_random = 1,
                    show_manage = 0
                WHERE username = ?
            """, (username,))

    owner_username = "nico"
    owner_password = "nico123"

    cur.execute("SELECT id FROM users WHERE username = ?", (owner_username,))
    owner = cur.fetchone()

    if not owner:
        cur.execute("""
            INSERT INTO users (
                username, password_hash, is_admin, is_owner,
                show_random, show_manage
            ) VALUES (?, ?, 1, 1, 1, 1)
        """, (owner_username, generate_password_hash(owner_password)))
    else:
        cur.execute("""
            UPDATE users
            SET is_admin = 1,
                is_owner = 1,
                show_random = 1,
                show_manage = 1
            WHERE username = ?
        """, (owner_username,))

    conn.commit()
    conn.close()


def get_user_by_id(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()
    return user


def refresh_session_user():
    if "user_id" not in session:
        return

    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return

    session["username"] = user["username"]
    session["is_admin"] = bool(user["is_admin"])
    session["is_owner"] = bool(user["is_owner"])
    session["show_random"] = bool(user["show_random"])
    session["show_manage"] = bool(user["show_manage"])


def first_allowed_page():
    if session.get("show_random"):
        return url_for("random_page")
    if session.get("show_manage"):
        return url_for("manage_page")
    return url_for("logout")


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        refresh_session_user()
        return func(*args, **kwargs)
    return wrapper


def manage_access_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        refresh_session_user()

        if not session.get("is_owner"):
            flash("เฉพาะ Owner เท่านั้นที่เข้าเมนูจัดการได้")
            return redirect(first_allowed_page())

        return func(*args, **kwargs)
    return wrapper


def render_common(template_name, **kwargs):
    refresh_session_user()
    return render_template(
        template_name,
        username=session.get("username", ""),
        is_admin=session.get("is_admin", False),
        is_owner=session.get("is_owner", False),
        show_random=session.get("show_random", True),
        show_manage=session.get("show_manage", False),
        current_user_id=session.get("user_id"),
        **kwargs
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        refresh_session_user()
        return redirect(first_allowed_page())

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
            session["is_admin"] = bool(user["is_admin"])
            session["is_owner"] = bool(user["is_owner"])
            session["show_random"] = bool(user["show_random"])
            session["show_manage"] = bool(user["show_manage"])
            return redirect(first_allowed_page())

        flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def home():
    return redirect(first_allowed_page())


@app.route("/random")
@login_required
def random_page():
    if not session.get("show_random"):
        flash("บัญชีนี้ถูกปิดการมองเห็นหัวข้อสุ่มเกม")
        return redirect(first_allowed_page())

    game_images = get_game_images()
    bonus_images = get_bonus_images()

    return render_common(
        "random.html",
        game_images=game_images,
        bonus_images=bonus_images,
        first_game=game_images[0] if game_images else "",
        first_bonus=bonus_images[0] if bonus_images else ""
    )


@app.route("/manage")
@manage_access_required
def manage_page():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, username, is_admin, is_owner, show_random, show_manage
        FROM users
        ORDER BY id ASC
    """)
    users = cur.fetchall()
    conn.close()

    return render_common(
        "manage.html",
        users=users,
        game_images=get_game_images(),
        bonus_images=get_bonus_images()
    )


@app.route("/manage/add-user", methods=["POST"])
@manage_access_required
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    is_admin = 1 if request.form.get("is_admin") == "1" else 0
    show_random = 1 if request.form.get("show_random") == "1" else 0
    show_manage = 1 if request.form.get("show_manage") == "1" else 0

    if not username or not password:
        flash("กรุณากรอกชื่อผู้ใช้และรหัสผ่านให้ครบ")
        return redirect(url_for("manage_page"))

    if username.lower() != "nico":
        show_manage = 0

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    existing = cur.fetchone()
    if existing:
        conn.close()
        flash("ชื่อผู้ใช้นี้มีอยู่แล้ว")
        return redirect(url_for("manage_page"))

    is_owner = 1 if username.lower() == "nico" else 0

    cur.execute("""
        INSERT INTO users (
            username, password_hash, is_admin, is_owner,
            show_random, show_manage
        ) VALUES (?, ?, ?, ?, ?, ?)
    """, (
        username,
        generate_password_hash(password),
        is_admin,
        is_owner,
        show_random,
        show_manage
    ))

    conn.commit()
    conn.close()

    flash(f"เพิ่มผู้ใช้ {username} เรียบร้อย")
    return redirect(url_for("manage_page"))


@app.route("/manage/reset-password", methods=["POST"])
@manage_access_required
def reset_password():
    user_id = request.form.get("user_id", "").strip()
    new_password = request.form.get("new_password", "").strip()

    if not user_id or not new_password:
        flash("กรุณาเลือกผู้ใช้และกรอกรหัสผ่านใหม่")
        return redirect(url_for("manage_page"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()

    if not user:
        conn.close()
        flash("ไม่พบผู้ใช้")
        return redirect(url_for("manage_page"))

    cur.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), user_id)
    )
    conn.commit()
    conn.close()

    flash(f"รีเซ็ตรหัสผ่านให้ {user['username']} แล้ว")
    return redirect(url_for("manage_page"))


@app.route("/manage/update-user", methods=["POST"])
@manage_access_required
def update_user():
    user_id = request.form.get("user_id", "").strip()
    username = request.form.get("username", "").strip()
    is_admin = 1 if request.form.get("is_admin") == "1" else 0
    show_random = 1 if request.form.get("show_random") == "1" else 0
    show_manage = 1 if request.form.get("show_manage") == "1" else 0

    if not user_id or not username:
        flash("ข้อมูลไม่ครบ")
        return redirect(url_for("manage_page"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()

    if not user:
        conn.close()
        flash("ไม่พบผู้ใช้")
        return redirect(url_for("manage_page"))

    cur.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, user_id))
    duplicate = cur.fetchone()
    if duplicate:
        conn.close()
        flash("ชื่อผู้ใช้นี้ถูกใช้ไปแล้ว")
        return redirect(url_for("manage_page"))

    current_user_id = session.get("user_id")
    is_owner = 1 if username.lower() == "nico" else 0

    if is_owner != 1:
        show_manage = 0

    if int(user_id) == int(current_user_id):
        if is_owner != 1:
            conn.close()
            flash("บัญชี Owner ที่กำลังใช้งานอยู่ต้องเป็น nico เท่านั้น")
            return redirect(url_for("manage_page"))

        if show_manage != 1:
            conn.close()
            flash("ไม่สามารถปิดเมนูจัดการของบัญชี Owner ที่กำลังใช้งานอยู่ได้")
            return redirect(url_for("manage_page"))

    cur.execute("""
        UPDATE users
        SET username = ?, is_admin = ?, is_owner = ?, show_random = ?, show_manage = ?
        WHERE id = ?
    """, (
        username,
        is_admin,
        is_owner,
        show_random,
        show_manage,
        user_id
    ))

    conn.commit()
    conn.close()

    if int(user_id) == int(current_user_id):
        refresh_session_user()

    flash(f"อัปเดตข้อมูลผู้ใช้ {username} แล้ว")
    return redirect(url_for("manage_page"))


@app.route("/manage/upload-game", methods=["POST"])
@manage_access_required
def upload_game():
    files = request.files.getlist("game_files")

    if not files or files[0].filename == "":
        flash("กรุณาเลือกรูปเกมก่อนอัปโหลด")
        return redirect(url_for("manage_page"))

    uploaded_count = 0

    for file in files:
        if file and file.filename and allowed_file(file.filename):
            filename = random_name(file.filename)
            file.save(os.path.join(GAME_UPLOAD_DIR, filename))
            uploaded_count += 1

    if uploaded_count == 0:
        flash("อัปโหลดรูปเกมไม่สำเร็จ")
    else:
        flash(f"อัปโหลดรูปเกมสำเร็จ {uploaded_count} ไฟล์")

    return redirect(url_for("manage_page"))


@app.route("/manage/upload-bonus", methods=["POST"])
@manage_access_required
def upload_bonus():
    files = request.files.getlist("bonus_files")

    if not files or files[0].filename == "":
        flash("กรุณาเลือกรูปโบนัสก่อนอัปโหลด")
        return redirect(url_for("manage_page"))

    uploaded_count = 0

    for file in files:
        if file and file.filename and allowed_file(file.filename):
            filename = random_name(file.filename)
            file.save(os.path.join(BONUS_UPLOAD_DIR, filename))
            uploaded_count += 1

    if uploaded_count == 0:
        flash("อัปโหลดรูปโบนัสไม่สำเร็จ")
    else:
        flash(f"อัปโหลดรูปโบนัสสำเร็จ {uploaded_count} ไฟล์")

    return redirect(url_for("manage_page"))


@app.route("/manage/delete-game/<filename>", methods=["POST"])
@manage_access_required
def delete_game(filename):
    file_path = os.path.join(GAME_UPLOAD_DIR, filename)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        os.remove(file_path)
        flash(f"ลบรูปเกม {filename} แล้ว")
    else:
        flash("ไม่พบไฟล์รูปเกม")
    return redirect(url_for("manage_page"))


@app.route("/manage/delete-bonus/<filename>", methods=["POST"])
@manage_access_required
def delete_bonus(filename):
    file_path = os.path.join(BONUS_UPLOAD_DIR, filename)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        os.remove(file_path)
        flash(f"ลบรูปโบนัส {filename} แล้ว")
    else:
        flash("ไม่พบไฟล์รูปโบนัส")
    return redirect(url_for("manage_page"))


with app.app_context():
    init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
