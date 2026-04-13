import bcrypt
import pyotp
import logging
import os
import smtplib
import secrets
import io
import base64
import qrcode
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=f"{LOG_DIR}/auth.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)


def send_email_otp(to_email, otp):
    try:
        msg = MIMEText(f"Your OTP is: {otp}\n\nThis code expires in 30 seconds.")
        msg["Subject"] = "Your Secure Login OTP"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = to_email
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        print("OTP email sent successfully")
    except Exception as e:
        print("Email Error:", e)


def send_reset_email(to_email, reset_link):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Password Reset - SecureAuth"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = to_email
        body = f"""Hello,

You requested a password reset for your SecureAuth account.

Click the link below to reset your password:
{reset_link}

This link is valid for 15 minutes. If you did not request this, ignore this email.

- SecureAuth System
"""
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        print("Reset email sent")
    except Exception as e:
        print("Reset Email Error:", e)


def hash_password(password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed.decode()


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


def generate_otp(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()


def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp, valid_window=1)


def generate_reset_token():
    return secrets.token_urlsafe(32)


def generate_qr_code(username, secret):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="SecureAuth")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode("utf-8")
    return encoded


def log_event(message):
    logging.info(message)
