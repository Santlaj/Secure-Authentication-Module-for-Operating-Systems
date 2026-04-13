from flask import Flask, render_template, request, redirect, session
import pyotp
import datetime
from database import (
    create_db, add_user, get_user, get_user_by_email,
    update_attempts, lock_user, update_password,
    create_session, get_active_sessions, revoke_session, revoke_all_sessions,
    save_reset_token, get_reset_token, mark_token_used
)
from security import (
    hash_password, check_password,
    generate_otp, verify_otp,
    log_event, send_email_otp,
    generate_reset_token, send_reset_email,
    generate_qr_code
)

app = Flask(__name__)
app.secret_key = "supersecretkey"

create_db()


@app.route("/")
def home():
    return redirect("/login")


# ================= REGISTER =================

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]

        if get_user(username):
            error = "Username already exists."
        else:
            hashed = hash_password(password)
            otp_secret = pyotp.random_base32()
            add_user(username, hashed, email, otp_secret)
            log_event(f"New user registered: {username}")
            return redirect("/login")

    return render_template("register.html", error=error)


# ================= LOGIN =================

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = get_user(username)

        if not user:
            error = "Invalid username or password."
        elif user["locked"] == 1:
            error = "Account locked due to too many failed attempts."
        elif check_password(password, user["password"]):
            session["username"] = username
            session["otp_secret"] = user["otp_secret"]
            otp = generate_otp(user["otp_secret"])
            send_email_otp(user["email"], otp)
            log_event(f"Password correct for {username}")
            return redirect("/otp")
        else:
            attempts = user["attempts"] + 1
            update_attempts(username, attempts)
            if attempts >= 3:
                lock_user(username)
                error = "Account locked due to too many failed attempts."
            else:
                error = f"Invalid username or password. ({3 - attempts} attempts left)"
            log_event(f"Failed login for {username}")

    return render_template("login.html", error=error)


# ================= OTP =================

@app.route("/otp", methods=["GET", "POST"])
def otp():
    if "username" not in session:
        return redirect("/login")
    error = None
    if request.method == "POST":
        otp_input = request.form["otp"]
        secret = session.get("otp_secret")
        if verify_otp(secret, otp_input):
            username = session["username"]
            ip = request.remote_addr
            browser = request.user_agent.string[:120]
            sid = create_session(username, ip, browser)
            session["session_id"] = sid
            log_event(f"OTP verified for {username} from {ip}")
            return redirect("/dashboard")
        else:
            error = "Invalid or expired OTP. Try again."
            log_event(f"Wrong OTP attempt for {session.get('username')}")

    return render_template("otp.html", error=error)


# ================= DASHBOARD =================

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")
    return render_template("dashboard.html", user=session["username"])


# ================= SESSION MANAGEMENT =================

@app.route("/sessions")
def sessions():
    if "username" not in session:
        return redirect("/login")
    active_sessions = get_active_sessions(session["username"])
    current_sid = session.get("session_id")
    return render_template("sessions.html", sessions=active_sessions, current_sid=current_sid)


@app.route("/sessions/revoke/<int:sid>")
def revoke(sid):
    if "username" not in session:
        return redirect("/login")
    revoke_session(sid, session["username"])
    log_event(f"Session {sid} revoked by {session['username']}")
    return redirect("/sessions")


@app.route("/sessions/revoke_all")
def revoke_all():
    if "username" not in session:
        return redirect("/login")
    revoke_all_sessions(session["username"])
    session.clear()
    return redirect("/login")


# ================= QR CODE / 2FA SETUP =================

@app.route("/setup_2fa")
def setup_2fa():
    if "username" not in session:
        return redirect("/login")
    user = get_user(session["username"])
    qr_b64 = generate_qr_code(session["username"], user["otp_secret"])
    secret = user["otp_secret"]
    return render_template("setup_2fa.html", qr_b64=qr_b64, secret=secret)


# ================= PASSWORD RESET =================

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    message = None
    if request.method == "POST":
        email = request.form["email"]
        user = get_user_by_email(email)
        if user:
            token = generate_reset_token()
            save_reset_token(user["username"], token)
            reset_link = f"http://127.0.0.1:5002/reset_password/{token}"
            send_reset_email(email, reset_link)
            log_event(f"Password reset requested for {user['username']}")
        message = "If that email exists, a reset link has been sent."
    return render_template("forgot_password.html", message=message)


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    record = get_reset_token(token)
    error = None

    if not record:
        return render_template("reset_password.html", invalid=True)

    # Check 15 min expiry
    created = datetime.datetime.strptime(record["created_at"], "%Y-%m-%d %H:%M:%S")
    if (datetime.datetime.now() - created).seconds > 900:
        return render_template("reset_password.html", invalid=True)

    if request.method == "POST":
        new_password = request.form["password"]
        confirm = request.form["confirm"]
        if new_password != confirm:
            error = "Passwords do not match."
        elif len(new_password) < 6:
            error = "Password must be at least 6 characters."
        else:
            hashed = hash_password(new_password)
            update_password(record["username"], hashed)
            mark_token_used(token)
            log_event(f"Password reset successful for {record['username']}")
            return redirect("/login")

    return render_template("reset_password.html", token=token, invalid=False, error=error)


# ================= AUDIT LOG =================

@app.route("/audit_log")
def audit_log():
    if "username" not in session:
        return redirect("/login")
    logs = []
    try:
        with open("logs/auth.log", "r") as f:
            lines = f.readlines()
            for line in reversed(lines[-200:]):
                line = line.strip()
                if line and " - " in line:
                    parts = line.split(" - ", 1)
                    if len(parts) == 2:
                        logs.append({"time": parts[0], "event": parts[1]})
    except FileNotFoundError:
        pass
    return render_template("audit_log.html", logs=logs)


# ================= LOGOUT =================

@app.route("/logout")
def logout():
    if "session_id" in session:
        revoke_session(session["session_id"], session.get("username"))
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
