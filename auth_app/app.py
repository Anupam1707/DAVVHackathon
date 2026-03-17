import streamlit as st
import time
import uuid
import jwt
import os
import pandas as pd
from datetime import datetime, timedelta
from dotenv import load_dotenv

from scripts.db_manager import (
    init_db, get_user_by_email, verify_password, update_failed_attempts,
    log_audit, set_last_login, add_user, user_exists, update_fingerprint_index,
    get_all_users, toggle_user_lock, toggle_user_admin, get_all_audit_logs,
    update_user_details, delete_user, factory_reset, get_user_audit_logs
)
from scripts.email_service import send_otp, check_otp, get_latest_otp, is_mock_mode
from scripts.fingerprint import FingerprintManager

# Optional .env support (kept alongside Streamlit secrets).
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'), override=False)


def get_secret(key: str, default=None):
    return st.secrets.get(key, os.getenv(key, default))

# Configuration
SECRET_KEY = get_secret('JWT_SECRET', 'your_super_secret_key')
init_db()

DEFAULT_USER_EMAIL = "anupamkanoongo@gmail.com"
DEFAULT_DEFAULT_PASSWORD = "AdminPassword123"

# Ensure default account exists on every app boot.
if not user_exists(DEFAULT_USER_EMAIL):
    add_user(DEFAULT_USER_EMAIL, DEFAULT_DEFAULT_PASSWORD, is_admin=True)
else:
    existing_default_user = get_user_by_email(DEFAULT_USER_EMAIL)
    if existing_default_user and not existing_default_user['is_admin']:
        toggle_user_admin(existing_default_user['id'], True)

# --- Page Config ---
st.set_page_config(
    page_title="Guardian | Secure Auth",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Advanced CSS ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    
    /* App Background */
    .stApp {
        background: radial-gradient(circle at 50% 0%, #0c1a2e 0%, #010409 70%) !important;
        background-attachment: fixed !important;
        color: #f0f6fc;
    }
    
    /* Main Content Container & Glassmorphism */
    .st-emotion-cache-1r6slb0, .st-emotion-cache-12w0qpk {
        background: rgba(13, 17, 23, 0.4);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border-radius: 24px;
        border: 1px solid rgba(48, 54, 61, 0.5);
        padding: 2.5rem;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
    }
    
    /* Glowing Inputs */
    .stTextInput>div>div>input {
        background: rgba(1, 4, 9, 0.5) !important;
        color: #c9d1d9 !important;
        border-radius: 12px !important;
        border: 1px solid #30363d !important;
        padding: 1.2rem !important;
        transition: all 0.2s;
        font-size: 1rem !important;
    }
    .stTextInput>div>div>input:focus {
        border-color: #58a6ff !important;
        box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.2) !important;
    }
    
    /* Premium Buttons */
    .stButton>button {
        width: 100%;
        border-radius: 12px;
        height: 3.5rem;
        background: linear-gradient(135deg, #1f6feb 0%, #00d4ff 100%);
        color: white;
        font-weight: 600;
        font-size: 1rem;
        border: none;
        transition: all 0.3s;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        box-shadow: 0 10px 20px -10px rgba(31, 111, 235, 0.5);
    }
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 20px 25px -5px rgba(31, 111, 235, 0.4);
        background: linear-gradient(135deg, #388bfd 0%, #33fbff 100%);
    }
    .stButton>button:active {
        transform: translateY(1px);
    }
    
    /* Titles & Branding */
    .logo-text {
        font-size: 3rem;
        font-weight: 800;
        background: linear-gradient(to right, #58a6ff, #00d4ff, #7ee787);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
        letter-spacing: -1px;
    }
    </style>
    """, unsafe_allow_html=True)

def generate_token(user_id: int, email: str):
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# --- Session State Management ---
if 'auth_state' not in st.session_state:
    st.session_state.auth_state = 'CREDENTIALS'
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'temp_reg_data' not in st.session_state:
    st.session_state.temp_reg_data = {}
if 'last_active_email' not in st.session_state:
    st.session_state.last_active_email = None
if 'virtual_inbox' not in st.session_state:
    st.session_state.virtual_inbox = {}
if 'session_token' not in st.session_state:
    st.session_state.session_token = None

def set_state(state):
    st.session_state.auth_state = state

# --- Sidebar ---
with st.sidebar:
    st.markdown('<p class="logo-text" style="font-size:3rem; letter-spacing:-2px;">GUARDIAN</p>', unsafe_allow_html=True)
    st.divider()

    current_user = st.session_state.get('current_user')
    if current_user and st.session_state.get('auth_state') == 'DASHBOARD':
        st.markdown(f"**👤 {current_user['email']}**")
        st.caption("🟢 Session Active")
        st.caption(f"Role: {'Admin' if current_user['is_admin'] else 'User'}")
        st.divider()
        if st.button("🚪 Logout", use_container_width=True):
            log_audit(current_user['id'], "LOGOUT")
            st.session_state.auth_state = 'CREDENTIALS'
            st.session_state.current_user = None
            st.session_state.last_active_email = None
            st.session_state.session_token = None
            st.rerun()
    else:
        st.caption("🔒 Not signed in")

# --- Main Flow ---
if st.session_state.auth_state == 'CREDENTIALS':
    st.markdown('<p class="logo-text">Sign In</p>', unsafe_allow_html=True)
    st.write("Enter your credentials.")
    
    email = st.text_input("Email", placeholder="your.email@gmail.com")
    password = st.text_input("Security Passphrase", type="password")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Identify Device"):
            user = get_user_by_email(email)
            if user:
                if user['is_locked']:
                    st.error("❌ Hardware Locked.")
                elif verify_password(password, user['password_hash']):
                    update_failed_attempts(user['id'], reset=True)
                    log_audit(user['id'], "LOGIN_ATTEMPT_SUCCESS")
                    st.session_state.last_active_email = email
                    st.session_state.current_user = user
                    if send_otp(email):
                        set_state('MFA')
                        st.rerun()
                    else:
                        err = st.session_state.get('gmail_last_error')
                        if err:
                            st.error(f"Failed to send OTP: {err}")
                        else:
                            st.error("Failed to send OTP (unknown error).")
                else:
                    update_failed_attempts(user['id'])
                    log_audit(user['id'], "LOGIN_ATTEMPT_FAILURE")
                    time.sleep(2)  # Rate limiting on failure
                    st.error("Invalid Credentials.")
            else:
                log_audit(None, f"LOGIN_ATTEMPT_UNKNOWN_EMAIL: {email}")
                time.sleep(2)  # Rate limiting on failure
                st.error("Invalid Credentials.")
    with col2:
        if st.button("Enroll New Device"):
            set_state('REGISTER_CREDENTIALS')
            st.rerun()

elif st.session_state.auth_state == 'REGISTER_CREDENTIALS':
    st.markdown('<p class="logo-text">Enrollment</p>', unsafe_allow_html=True)
    st.info("💡 Passphrase must be at least 12 characters long.")
    new_email = st.text_input("Email Address", placeholder="your.email@gmail.com")
    new_pass = st.text_input("Passphrase", type="password")
    confirm = st.text_input("Confirm", type="password")
    
    if st.button("Begin Link"):
        if len(new_pass) >= 12 and new_pass == confirm and not user_exists(new_email):
            st.session_state.last_active_email = new_email
            st.session_state.temp_reg_data = {'email': new_email, 'password': new_pass}
            log_audit(None, f"REGISTRATION_STARTED: {new_email}")
            if send_otp(new_email):
                set_state('REGISTER_MFA')
                st.rerun()
            else:
                err = st.session_state.get('gmail_last_error')
                if err:
                    st.error(f"Failed to send OTP: {err}")
                else:
                    st.error("Failed to send OTP (unknown error).")
        else:
            st.error("Check requirements and try again.")
    if st.button("Back"):
        set_state('CREDENTIALS')
        st.rerun()

elif st.session_state.auth_state in ['REGISTER_MFA', 'MFA']:
    st.markdown('<p class="logo-text">MFA Challenge</p>', unsafe_allow_html=True)
    st.info(f"Signal active for {st.session_state.last_active_email}")
    otp_code = st.text_input("Verification Code", max_chars=6)
    
    if st.button("Verify"):
        if check_otp(st.session_state.last_active_email, otp_code):
            log_audit(st.session_state.current_user['id'] if st.session_state.current_user else None, "MFA_VERIFIED")
            if st.session_state.auth_state == 'REGISTER_MFA':
                set_state('REGISTER_BIOMETRIC')
            else:
                set_state('BIOMETRIC')
            st.rerun()
        else:
            log_audit(st.session_state.current_user['id'] if st.session_state.current_user else None, "MFA_FAILED")
            time.sleep(2)
            st.error("Invalid code.")

elif st.session_state.auth_state in ['REGISTER_BIOMETRIC', 'BIOMETRIC']:
    st.markdown('<p class="logo-text">Biometric Scan</p>', unsafe_allow_html=True)
    st.write("🔒 **Waiting for hardware signal...**")
    
    if st.button("🔴 Touch Sensor to Authorize"):
        with st.status("🧬 Scanning fingerprint...", expanded=True) as status:
            progress_bar = st.progress(0)
            for percent_complete in range(100):
                time.sleep(0.02)
                progress_bar.progress(percent_complete + 1)
            
            fm = FingerprintManager()
            if st.session_state.auth_state == 'REGISTER_BIOMETRIC':
                idx = fm.enroll_user()
                if idx != -1:
                    add_user(st.session_state.temp_reg_data['email'], st.session_state.temp_reg_data['password'], fingerprint_index=idx)
                    log_audit(None, f"USER_ENROLLED: {st.session_state.temp_reg_data['email']}")
                    status.update(label="✅ Identity Verified!", state="complete")
                    time.sleep(1)
                    set_state('CREDENTIALS')
                else:
                    status.update(label="❌ Enrollment Failed", state="error")
                    st.error("Biometric enrollment failed.")
            else:
                user = st.session_state.current_user
                if user['fingerprint_index'] == -1:
                    idx = fm.enroll_user()
                    update_fingerprint_index(user['id'], idx)
                    log_audit(user['id'], "BIOMETRIC_ENROLLED_ON_LOGIN")
                    set_last_login(user['id'])
                    st.session_state.session_token = generate_token(user['id'], user['email'])
                    status.update(label="✅ New Profile Linked!", state="complete")
                    time.sleep(1)
                    set_state('DASHBOARD')
                else:
                    if fm.verify_user(user['fingerprint_index']):
                        log_audit(user['id'], "BIOMETRIC_VERIFIED")
                        set_last_login(user['id'])
                        st.session_state.session_token = generate_token(user['id'], user['email'])
                        status.update(label="✅ Access Granted!", state="complete")
                        time.sleep(1)
                        set_state('DASHBOARD')
                    else:
                        log_audit(user['id'], "BIOMETRIC_FAILED")
                        status.update(label="❌ Match Failed", state="error")
                        time.sleep(2)
                        st.error("Biometric verification failed.")
            st.rerun()

elif st.session_state.auth_state == 'DASHBOARD':
    user = st.session_state.current_user
    st.markdown(f'<p class="logo-text">Authenticated: {user["email"]}</p>', unsafe_allow_html=True)
    
    tabs = st.tabs(["🔒 Operations", "🛡️ Security Health", "⚙️ Admin"] if user['is_admin'] else ["🔒 Operations", "🛡️ Security Health"])
    
    with tabs[0]:
        st.success("Session Verified.")
        st.metric("System Security Level", "ELITE", "MAX")
        if st.session_state.session_token:
            with st.expander("🔑 Session Token"):
                st.code(st.session_state.session_token, language="jwt")
    
    with tabs[1]:
        st.subheader("Triple-Layer Health")
        st.progress(100, "Layer 1: Bcrypt-12")
        st.progress(100, "Layer 2: Virtual SMS")
        st.progress(100, "Layer 3: Biometric")
        st.info("JWT session token issued.")
        
        st.subheader("Personal Audit History")
        user_logs = get_user_audit_logs(user['id'], limit=100)
        if user_logs:
            st.dataframe(pd.DataFrame(user_logs))
        else:
            st.write("No logs found.")

    if user['is_admin']:
        with tabs[2]:
            st.subheader("👥 System Directory")
            all_users = get_all_users()
            st.dataframe(pd.DataFrame(all_users))
            
            st.divider()
            
            col_admin_a, col_admin_b = st.columns(2)
            
            with col_admin_a:
                st.subheader("➕ Quick Enroll")
                admin_new_email = st.text_input("New Email", key="admin_add_email")
                admin_new_pass = st.text_input("Passphrase", type="password", key="admin_add_pass")
                if st.button("Create User"):
                    if len(admin_new_pass) >= 12 and not user_exists(admin_new_email):
                        add_user(admin_new_email, admin_new_pass)
                        log_audit(user['id'], f"ADMIN_ADDED_USER: {admin_new_email}")
                        st.success("User created.")
                        st.rerun()
                    else:
                        st.error("Invalid email or weak password.")

            with col_admin_b:
                st.subheader("🛠️ Manage Selected User")
                t_id = st.number_input("User ID to manage", min_value=1, step=1)
                
                # Management buttons in a grid
                m_col1, m_col2 = st.columns(2)
                with m_col1:
                    if st.button("❌ Purge User"):
                        delete_user(t_id)
                        log_audit(user['id'], f"USER_DELETED: {t_id}")
                        st.rerun()
                    if st.button("🔓 Unlock User"):
                        toggle_user_lock(t_id, False)
                        update_failed_attempts(t_id, reset=True)
                        log_audit(user['id'], f"USER_UNLOCKED: {t_id}")
                        st.rerun()
                    if st.button("🔒 Lock User"):
                        toggle_user_lock(t_id, True)
                        log_audit(user['id'], f"USER_LOCKED: {t_id}")
                        st.rerun()
                
                with m_col2:
                    if st.button("⭐ Promote Admin"):
                        toggle_user_admin(t_id, True)
                        log_audit(user['id'], f"USER_PROMOTED: {t_id}")
                        st.rerun()
                    if st.button("📉 Demote Admin"):
                        toggle_user_admin(t_id, False)
                        log_audit(user['id'], f"USER_DEMOTED: {t_id}")
                        st.rerun()

            st.divider()
            st.subheader("📜 System Audit Logs")
            logs = get_all_audit_logs(limit=20)
            st.dataframe(pd.DataFrame(logs))

            st.divider()
            st.subheader("⚠️ Danger Zone")
            if st.button("☣️ Factory Reset", key="admin_factory_reset"):
                factory_reset()
                add_user(DEFAULT_USER_EMAIL, DEFAULT_DEFAULT_PASSWORD, is_admin=True)
                st.session_state.auth_state = 'CREDENTIALS'
                st.session_state.current_user = None
                st.session_state.last_active_email = None
                st.session_state.virtual_inbox = {}
                st.session_state.session_token = None
                st.success("System wiped and default accounts re-initialized.")
                time.sleep(1)
                st.rerun()
