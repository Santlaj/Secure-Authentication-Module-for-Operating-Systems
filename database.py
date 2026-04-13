import sqlite3
import datetime

DB_NAME = "users.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def create_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        otp_secret TEXT,
        attempts INTEGER DEFAULT 0,
        locked INTEGER DEFAULT 0
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip TEXT,
        browser TEXT,
        login_time TEXT,
        active INTEGER DEFAULT 1
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        token TEXT,
        created_at TEXT,
        used INTEGER DEFAULT 0
    )
    """)

    conn.commit()
    conn.close()


def get_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_email(email):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user


def add_user(username, password, email, otp_secret):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password, email, otp_secret) VALUES (?, ?, ?, ?)",
        (username, password, email, otp_secret),
    )
    conn.commit()
    conn.close()


def update_attempts(username, attempts):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET attempts=? WHERE username=?", (attempts, username))
    conn.commit()
    conn.close()


def lock_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET locked=1 WHERE username=?", (username,))
    conn.commit()
    conn.close()


def update_password(username, new_hashed):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password=?, attempts=0, locked=0 WHERE username=?", (new_hashed, username))
    conn.commit()
    conn.close()


# Sessions

def create_session(username, ip, browser):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO sessions (username, ip, browser, login_time, active) VALUES (?, ?, ?, ?, 1)",
        (username, ip, browser, now),
    )
    session_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return session_id


def get_active_sessions(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE username=? AND active=1 ORDER BY login_time DESC", (username,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def revoke_session(session_id, username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sessions SET active=0 WHERE id=? AND username=?", (session_id, username))
    conn.commit()
    conn.close()


def revoke_all_sessions(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sessions SET active=0 WHERE username=?", (username,))
    conn.commit()
    conn.close()


# Reset Tokens

def save_reset_token(username, token):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO reset_tokens (username, token, created_at, used) VALUES (?, ?, ?, 0)",
        (username, token, now),
    )
    conn.commit()
    conn.close()


def get_reset_token(token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reset_tokens WHERE token=? AND used=0", (token,))
    row = cursor.fetchone()
    conn.close()
    return row


def mark_token_used(token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE reset_tokens SET used=1 WHERE token=?", (token,))
    conn.commit()
    conn.close()
