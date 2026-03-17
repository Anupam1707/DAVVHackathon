import os
import random
import streamlit as st
from datetime import datetime, timedelta
from dotenv import load_dotenv

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Optional .env support (kept alongside Streamlit secrets).
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'), override=False)

def _get_secret(key: str, default=None):
    return st.secrets.get(key, os.getenv(key, default))

# OTP behavior configuration
OTP_EXPIRY_MINUTES = int(_get_secret('OTP_EXPIRY_MINUTES', '5'))
GMAIL_USER = _get_secret('GMAIL_USER')
GMAIL_APP_PASSWORD = _get_secret('GMAIL_APP_PASSWORD')


def _is_mock_mode() -> bool:
    """Returns True when Gmail credentials are not configured (mock/testing mode)."""
    return not bool(GMAIL_USER and GMAIL_APP_PASSWORD)


def is_mock_mode() -> bool:
    """Public helper to check whether the app is running in mock mode."""
    return _is_mock_mode()


def _get_otp_store():
    if 'otp_store' not in st.session_state:
        st.session_state.otp_store = {}
    return st.session_state.otp_store


def send_email_otp(email: str, otp: str) -> bool:
    """Send OTP via Gmail SMTP."""
    if _is_mock_mode():
        return False

    msg = MIMEMultipart()
    msg['From'] = GMAIL_USER
    msg['To'] = email
    msg['Subject'] = 'Your Guardian OTP Code'

    body = f"""
    Your Guardian OTP is: {otp}

    This code expires in {OTP_EXPIRY_MINUTES} minutes.

    Do not share this code with anyone.
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        text = msg.as_string()
        server.sendmail(GMAIL_USER, email, text)
        server.quit()
        return True
    except smtplib.SMTPAuthenticationError as auth_err:
        error_msg = f"[Gmail OTP] Authentication failed for {GMAIL_USER}: {auth_err}. If you have 2FA enabled, use an App Password instead of your regular password. Generate one at: https://myaccount.google.com/apppasswords"
        st.session_state.gmail_last_error = error_msg
        print(error_msg)
        return False
    except Exception as e:
        error_msg = f"[Gmail OTP] Failed to send to {email}: {e}"
        st.session_state.gmail_last_error = error_msg
        print(error_msg)
        return False


def send_otp(email: str):
    """Generate & send a 6-digit OTP via email."""
    otp = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)

    store = _get_otp_store()
    store[email] = {
        'otp': otp,
        'expires_at': expires_at
    }

    if _is_mock_mode():
        # In mock mode, log the OTP
        print(f"[MOCK EMAIL] OTP for {email}: {otp}")
        return True

    success = send_email_otp(email, otp)
    if not success:
        print(f"[Gmail OTP] Failed to send OTP to {email}.")

    return success


def check_otp(email: str, code: str):
    """Validate OTP and expire it after use."""
    store = _get_otp_store()
    entry = store.get(email)

    if not entry:
        return False

    if entry.get('expires_at') and datetime.utcnow() > entry['expires_at']:
        # Expired
        del store[email]
        return False

    if entry.get('otp') == code:
        del store[email]
        return True

    return False


def get_latest_otp(email: str):
    """Used by the UI to show the latest OTP in mock mode."""
    if _is_mock_mode():
        store = _get_otp_store()
        entry = store.get(email)
        if entry and datetime.utcnow() <= entry.get('expires_at', datetime.utcnow()):
            return entry.get('otp')
    return None

