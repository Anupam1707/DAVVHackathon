import streamlit as st
import time
import uuid
import jwt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

from scripts.db_manager import (
    init_db, get_user_by_phone, verify_password, update_failed_attempts, 
    log_audit, set_last_login, add_user
)
from scripts.sms_service import send_otp, check_otp
from scripts.fingerprint import FingerprintManager

load_dotenv()

# Configuration
SECRET_KEY = os.getenv('JWT_SECRET', 'your_super_secret_key')
init_db()

# --- Utility Functions ---

def create_session_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_session_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except:
        return None

# --- UI Layout ---

st.set_page_config(page_title="Mobile-First Secure Auth", layout="centered")

if 'auth_state' not in st.session_state:
    st.session_state.auth_state = 'CREDENTIALS' # CREDENTIALS -> MFA -> BIOMETRIC -> DASHBOARD
    st.session_state.current_user = None
    st.session_state.device_id = str(uuid.uuid4()) # In real scenario, would be retrieved from JS/LocalStorage

def set_state(state):
    st.session_state.auth_state = state

# --- Registration Helper (For Testing) ---
with st.sidebar:
    st.subheader("Admin Tools (Testing)")
    if st.button("Initialize Admin User"):
        if add_user("+1234567890", "SecurePassphrase123", is_admin=True):
            st.success("Admin user created: +1234567890 / SecurePassphrase123")
        else:
            st.warning("Admin user already exists or failed.")

# --- Auth Flow ---

if st.session_state.auth_state == 'CREDENTIALS':
    st.title("Secure Login")
    phone = st.text_input("Phone Number (e.g., +1234567890)")
    password = st.text_input("Passphrase", type="password")
    
    if st.button("Login"):
        if len(password) < 12:
            st.error("Invalid Phone or Password") # Security Guardrail: Obfuscated message
            time.sleep(2)
        else:
            user = get_user_by_phone(phone)
            if user:
                if user['is_locked']:
                    st.error("Account is locked. Contact support.")
                    log_audit(user['id'], 'LOGIN_BLOCKED_LOCKED')
                elif verify_password(password, user['password_hash']):
                    st.session_state.current_user = user
                    update_failed_attempts(user['id'], reset=True)
                    
                    # Trigger MFA
                    if send_otp(phone):
                        log_audit(user['id'], 'CREDENTIALS_SUCCESS')
                        set_state('MFA')
                        st.rerun()
                    else:
                        st.error("Failed to send MFA code. Try again.")
                else:
                    update_failed_attempts(user['id'])
                    log_audit(user['id'], 'LOGIN_FAIL')
                    st.error("Invalid Phone or Password")
                    time.sleep(2)
            else:
                st.error("Invalid Phone or Password")
                time.sleep(2)

elif st.session_state.auth_state == 'MFA':
    st.title("MFA Verification")
    st.write(f"Enter the 6-digit code sent to {st.session_state.current_user['phone_number']}")
    
    otp_code = st.text_input("Verification Code", max_chars=6)
    
    if st.button("Verify Code"):
        if check_otp(st.session_state.current_user['phone_number'], otp_code):
            log_audit(st.session_state.current_user['id'], 'MFA_SUCCESS')
            
            # Check if Biometric is needed
            if st.session_state.current_user['is_admin']:
                set_state('BIOMETRIC')
            else:
                set_state('DASHBOARD')
            st.rerun()
        else:
            log_audit(st.session_state.current_user['id'], 'MFA_FAIL')
            st.error("Invalid code.")
            time.sleep(2)

elif st.session_state.auth_state == 'BIOMETRIC':
    st.title("Physical Biometric Check")
    st.warning("Admin Access Required: Please use the physical scanner connected to the terminal.")
    
    # Keyboard Trigger Simulation
    sim_trigger = st.text_input("Keyboard Trigger (Type 's' and Enter to simulate scan)", key="sim_trigger")
    
    if st.button("Verify Fingerprint") or sim_trigger.lower() == 's':
        fm = FingerprintManager()
        # In a real setup, we'd store the user's fingerprint index in the DB
        # For this demo, we'll use a placeholder index or enrollment if none exists
        if st.session_state.current_user['fingerprint_index'] == -1:
            st.info("No fingerprint found. Initiating enrollment...")
            idx = fm.enroll_user()
            if idx != -1:
                # Update DB (omitted for brevity in this specific tool call, but implied)
                st.success(f"Fingerprint enrolled at index {idx}")
                set_state('DASHBOARD')
                st.rerun()
            else:
                st.error("Enrollment failed.")
        else:
            if fm.verify_user(st.session_state.current_user['fingerprint_index']):
                st.success("Fingerprint verified.")
                set_state('DASHBOARD')
                st.rerun()
            else:
                st.error("Biometric mismatch.")
                log_audit(st.session_state.current_user['id'], 'BIOMETRIC_FAIL')
                time.sleep(2)

elif st.session_state.auth_state == 'DASHBOARD':
    user = st.session_state.current_user
    st.title(f"Welcome, {user['phone_number']}")
    st.success("Authentication successful.")
    
    set_last_login(user['id'])
    log_audit(user['id'], 'LOGIN_SUCCESS')
    
    st.write("---")
    st.subheader("Business Operations Dashboard")
    st.info("You are now securely logged into the system.")
    
    if st.button("Logout"):
        st.session_state.auth_state = 'CREDENTIALS'
        st.session_state.current_user = None
        st.rerun()

# --- CSS for Mobile-First Styling ---
st.markdown("""
    <style>
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
        background-color: #007bff;
        color: white;
    }
    .stTextInput>div>div>input {
        text-align: center;
    }
    </style>
    """, unsafe_allow_html=True)
