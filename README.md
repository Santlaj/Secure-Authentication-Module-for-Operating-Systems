# Secure Authentication Module

A Flask-based multi-factor authentication system.

## Features
- Password hashing with bcrypt
- TOTP-based two-factor authentication (email OTP + Authenticator App)
- Account lockout after 3 failed attempts
- QR code setup for Google Authenticator / Authy
- Password reset via email
- Active session management (view & revoke)
- Audit log viewer
- Bootstrap 5 styled UI

## Setup

1. Install dependencies:
   pip install -r requirements.txt

2. Edit .env with your Gmail credentials:
   EMAIL_ADDRESS=your@gmail.com
   EMAIL_PASSWORD=your_app_password

3. Run:
   python app.py

4. Open http://127.0.0.1:5000
