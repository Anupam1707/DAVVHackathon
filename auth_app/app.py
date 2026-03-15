import streamlit as st
import time
import uuid
import jwt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

from scripts.db_manager import (
    init_db, get_user_by_phone, verify_password, update_failed_attempts, 
    log_audit, set_last_login, add_user, user_exists
)
from scripts.sms_service import send_otp, check_otp, get_latest_otp
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
    st.session_state.temp_reg_data = {} # To hold registration data during MFA

def set_state(state):
    st.session_state.auth_state = state

# --- Sidebar Tools ---
with st.sidebar:
    st.header("📱 Virtual Phone")
    st.info("Incoming SMS will appear here for free.")
    
    # Check for both Login and Registration phone numbers
    active_phone = None
    if st.session_state.current_user:
        active_phone = st.session_state.current_user['phone_number']
    elif st.session_state.temp_reg_data:
        active_phone = st.session_state.temp_reg_data.get('phone')
    
    if active_phone:
        otp = get_latest_otp(active_phone)
        if otp:
            st.success(f"**From: System**\n\nYour 6-digit code is: `{otp}`")
        else:
            st.write("No unread messages.")
    else:
        st.write("Waiting for phone number input...")

    st.markdown("---")
    st.subheader("System Tools")
    if st.button("Logout", key="logout_sidebar"):
        st.session_state.auth_state = 'CREDENTIALS'
        st.session_state.current_user = None
        st.rerun()

# --- Auth Flow ---

# 1. Login State
if st.session_state.auth_state == 'CREDENTIALS':
    st.title("Secure Login")
    phone = st.text_input("Phone Number (e.g., +1234567890)")
    password = st.text_input("Passphrase", type="password")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Login"):
            if len(password) < 12:
                st.error("Invalid Phone or Password")
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
    with col2:
        if st.button("New User? Register"):
            set_state('REGISTER_CREDENTIALS')
            st.rerun()

# 2. Registration State
elif st.session_state.auth_state == 'REGISTER_CREDENTIALS':
    st.title("New Registration")
    new_phone = st.text_input("Mobile Number")
    new_pass = st.text_input("Choose Passphrase (min 12 characters)", type="password")
    confirm_pass = st.text_input("Confirm Passphrase", type="password")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Sign Up"):
            if len(new_pass) < 12:
                st.error("Passphrase must be at least 12 characters.")
            elif new_pass != confirm_pass:
                st.error("Passphrases do not match.")
            elif user_exists(new_phone):
                st.error("An account with this phone already exists.")
            else:
                if send_otp(new_phone):
                    st.session_state.temp_reg_data = {
                        'phone': new_phone,
                        'password': new_pass
                    }
                    set_state('REGISTER_MFA')
                    st.rerun()
                else:
                    st.error("Failed to send verification SMS.")
    with col2:
        if st.button("Back to Login"):
            set_state('CREDENTIALS')
            st.rerun()

# 3. Registration MFA
elif st.session_state.auth_state == 'REGISTER_MFA':
    st.title("Verify Phone")
    st.write(f"Verifying: {st.session_state.temp_reg_data.get('phone')}")
    reg_code = st.text_input("Enter 6-digit verification code", max_chars=6)
    
    if st.button("Verify & Create Account"):
        phone = st.session_state.temp_reg_data['phone']
        password = st.session_state.temp_reg_data['password']
        
        if check_otp(phone, reg_code):
            if add_user(phone, password):
                st.success("Account created successfully!")
                time.sleep(1.5)
                set_state('CREDENTIALS')
                st.rerun()
            else:
                st.error("Error saving user. Please try again.")
        else:
            st.error("Invalid verification code.")

# 4. Login MFA
elif st.session_state.auth_state == 'MFA':
    st.title("MFA Verification")
    st.write(f"Enter the 6-digit code sent to {st.session_state.current_user['phone_number']}")
    otp_code = st.text_input("Verification Code", max_chars=6)
    
    if st.button("Verify Code"):
        if check_otp(st.session_state.current_user['phone_number'], otp_code):
            log_audit(st.session_state.current_user['id'], 'MFA_SUCCESS')
            if st.session_state.current_user['is_admin']:
                set_state('BIOMETRIC')
            else:
                set_state('DASHBOARD')
            st.rerun()
        else:
            log_audit(st.session_state.current_user['id'], 'MFA_FAIL')
            st.error("Invalid code.")
            time.sleep(2)

# 5. Biometric
elif st.session_state.auth_state == 'BIOMETRIC':
    st.title("Physical Biometric Check")
    st.warning("Admin Access Required: Please use physical scanner or simulate with 's'.")
    sim_trigger = st.text_input("Keyboard Trigger (Type 's' and Enter to simulate scan)", key="sim_trigger")
    
    if st.button("Verify Fingerprint") or sim_trigger.lower() == 's':
        fm = FingerprintManager()
        if st.session_state.current_user['fingerprint_index'] == -1:
            st.info("No fingerprint found. Initiating enrollment...")
            idx = fm.enroll_user()
            if idx != -1:
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

# 6. Dashboard
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
