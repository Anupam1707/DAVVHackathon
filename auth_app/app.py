import streamlit as st
import time
import uuid
import jwt
import os
import pandas as pd
from datetime import datetime, timedelta
from dotenv import load_dotenv

from scripts.db_manager import (
    init_db, get_user_by_phone, verify_password, update_failed_attempts, 
    log_audit, set_last_login, add_user, user_exists, update_fingerprint_index,
    get_all_users, toggle_user_lock, toggle_user_admin, get_all_audit_logs,
    update_user_details, delete_user
)
from scripts.sms_service import send_otp, check_otp, get_latest_otp
from scripts.fingerprint import FingerprintManager

load_dotenv()

# Configuration
SECRET_KEY = os.getenv('JWT_SECRET', 'your_super_secret_key')
init_db()

# --- Page Config ---
st.set_page_config(
    page_title="Guardian | Secure Auth",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Advanced CSS for Glassmorphism & Modern UI ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* Main Container Styling */
    .main {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        color: #f8fafc;
    }
    
    /* Card Styling */
    .st-emotion-cache-1r6slb0, .st-emotion-cache-12w0qpk {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        border-radius: 16px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 2rem;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
    }

    /* Button Styling */
    .stButton>button {
        width: 100%;
        border-radius: 12px;
        height: 3.5rem;
        background: linear-gradient(90deg, #6366f1 0%, #a855f7 100%);
        color: white;
        font-weight: 600;
        border: none;
        transition: all 0.3s ease;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 20px -10px #6366f1;
        background: linear-gradient(90deg, #4f46e5 0%, #9333ea 100%);
    }

    /* Input Styling */
    .stTextInput>div>div>input {
        background: rgba(255, 255, 255, 0.05) !important;
        color: white !important;
        border-radius: 10px !important;
        border: 1px solid rgba(255, 255, 255, 0.2) !important;
        padding: 1rem !important;
    }

    /* Virtual Phone Styling */
    .phone-container {
        background: #000;
        border: 8px solid #333;
        border-radius: 40px;
        padding: 20px;
        margin-top: 20px;
        min-height: 400px;
        box-shadow: inset 0 0 10px rgba(255,255,255,0.1);
    }
    
    .message-bubble {
        background: #2563eb;
        color: white;
        padding: 12px 16px;
        border-radius: 20px 20px 20px 0;
        margin-bottom: 10px;
        font-size: 0.9rem;
        box-shadow: 2px 2px 5px rgba(0,0,0,0.2);
    }

    /* Stat Cards */
    .stat-card {
        background: rgba(255, 255, 255, 0.03);
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 4px solid #6366f1;
    }
    
    /* Logo Styling */
    .logo-text {
        font-size: 2.5rem;
        font-weight: 800;
        background: linear-gradient(90deg, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 1rem;
    }
    </style>
    """, unsafe_allow_html=True)

# --- Session State Logic ---
if 'auth_state' not in st.session_state:
    st.session_state.auth_state = 'CREDENTIALS'
    st.session_state.current_user = None
    st.session_state.temp_reg_data = {}

def set_state(state):
    st.session_state.auth_state = state

# --- Sidebar: The "Virtual Device" ---
with st.sidebar:
    st.markdown('<p class="logo-text">GUARDIAN</p>', unsafe_allow_html=True)
    st.write("🔒 **Mobile Hardware Auth**")
    st.divider()
    
    st.subheader("📱 Device Inbox")
    active_phone = None
    if st.session_state.current_user:
        active_phone = st.session_state.current_user['phone_number']
    elif st.session_state.temp_reg_data:
        active_phone = st.session_state.temp_reg_data.get('phone')
    
    st.markdown('<div class="phone-container">', unsafe_allow_html=True)
    if active_phone:
        otp = get_latest_otp(active_phone)
        if otp:
            st.markdown(f"""
                <div class="message-bubble">
                    <b>System Alert</b><br>
                    Your secure verification code is: <b>{otp}</b><br>
                    <small>Expires in 5 minutes</small>
                </div>
            """, unsafe_allow_html=True)
        else:
            st.write("💬 *Waiting for incoming signals...*")
    else:
        st.write("📵 *Connect a device by entering a phone number.*")
    st.markdown('</div>', unsafe_allow_html=True)

    st.divider()
    with st.expander("🛠️ Advanced Settings"):
        if st.button("Initialize Master Admin"):
            if add_user("+1000", "AdminPassword123", is_admin=True):
                st.success("Master Admin initialized.")
            else:
                st.info("System already initialized.")
        
        if st.button("🔴 System Reset"):
            st.session_state.auth_state = 'CREDENTIALS'
            st.session_state.current_user = None
            st.rerun()

# --- Main Auth Flow ---

def render_login():
    st.markdown('<p class="logo-text">Sign In</p>', unsafe_allow_html=True)
    st.write("Enter your hardware-linked credentials to continue.")
    
    with st.container():
        phone = st.text_input("Device ID / Phone Number", placeholder="+1XXXXXXXXXX")
        password = st.text_input("Security Passphrase", type="password", placeholder="Minimum 12 characters")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Identify Device"):
                if len(password) < 12:
                    st.error("Invalid Credentials. Please retry.")
                    time.sleep(1)
                else:
                    user = get_user_by_phone(phone)
                    if user:
                        if user['is_locked']:
                            st.error("❌ Hardware Locked. Contact Security.")
                            log_audit(user['id'], 'LOGIN_BLOCKED_LOCKED')
                        elif verify_password(password, user['password_hash']):
                            st.session_state.current_user = user
                            update_failed_attempts(user['id'], reset=True)
                            if send_otp(phone):
                                log_audit(user['id'], 'CREDENTIALS_SUCCESS')
                                set_state('MFA')
                                st.rerun()
                        else:
                            update_failed_attempts(user['id'])
                            log_audit(user['id'], 'LOGIN_FAIL')
                            st.error("Invalid Credentials.")
                    else:
                        st.error("Invalid Credentials.")
        with col2:
            if st.button("Enroll New Device"):
                set_state('REGISTER_CREDENTIALS')
                st.rerun()

def render_register():
    st.markdown('<p class="logo-text">Device Enrollment</p>', unsafe_allow_html=True)
    st.write("Link your physical phone to a new secure account.")
    
    with st.container():
        new_phone = st.text_input("Mobile Number")
        new_pass = st.text_input("Security Passphrase", type="password")
        confirm_pass = st.text_input("Confirm Passphrase", type="password")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Begin Link"):
                if len(new_pass) < 12:
                    st.error("Passphrase is too weak.")
                elif new_pass != confirm_pass:
                    st.error("Mismatched Passphrase.")
                elif user_exists(new_phone):
                    st.error("Device already linked.")
                else:
                    if send_otp(new_phone):
                        st.session_state.temp_reg_data = {'phone': new_phone, 'password': new_pass}
                        set_state('REGISTER_MFA')
                        st.rerun()
        with col2:
            if st.button("Cancel"):
                set_state('CREDENTIALS')
                st.rerun()

# --- Logic Router ---
if st.session_state.auth_state == 'CREDENTIALS':
    render_login()

elif st.session_state.auth_state == 'REGISTER_CREDENTIALS':
    render_register()

elif st.session_state.auth_state == 'REGISTER_MFA' or st.session_state.auth_state == 'MFA':
    st.markdown('<p class="logo-text">MFA Challenge</p>', unsafe_allow_html=True)
    st.write("A secure signal has been sent to your device sidebar.")
    
    otp_code = st.text_input("6-Digit Transmission Code", max_chars=6)
    
    if st.button("Decrypt & Verify"):
        target_phone = st.session_state.current_user['phone_number'] if st.session_state.current_user else st.session_state.temp_reg_data['phone']
        
        if check_otp(target_phone, otp_code):
            if st.session_state.auth_state == 'REGISTER_MFA':
                set_state('REGISTER_BIOMETRIC')
            else:
                log_audit(st.session_state.current_user['id'], 'MFA_SUCCESS')
                set_state('BIOMETRIC')
            st.rerun()
        else:
            st.error("Signal corruption: Invalid code.")

elif st.session_state.auth_state == 'REGISTER_BIOMETRIC' or st.session_state.auth_state == 'BIOMETRIC':
    st.markdown('<p class="logo-text">Biometric Scan</p>', unsafe_allow_html=True)
    st.info("Initiating hardware biometric handshake...")
    
    sim_trigger = st.text_input("Keyboard Scan (Type 's' to simulate)", key="bio_sim")
    
    if st.button("Authorize Biometrics") or sim_trigger.lower() == 's':
        fm = FingerprintManager()
        if st.session_state.auth_state == 'REGISTER_BIOMETRIC':
            idx = fm.enroll_user()
            if idx != -1:
                if add_user(st.session_state.temp_reg_data['phone'], st.session_state.temp_reg_data['password'], fingerprint_index=idx):
                    st.success("Hardware Binding Complete!")
                    time.sleep(1)
                    set_state('CREDENTIALS')
                    st.rerun()
        else:
            user = st.session_state.current_user
            if user['fingerprint_index'] == -1:
                st.info("First-time setup detected...")
                idx = fm.enroll_user()
                update_fingerprint_index(user['id'], idx)
                set_state('DASHBOARD')
            else:
                if fm.verify_user(user['fingerprint_index']):
                    st.success("Access Granted.")
                    set_state('DASHBOARD')
                else:
                    st.error("Biometric mismatch.")
                    log_audit(user['id'], 'BIOMETRIC_FAIL')
            st.rerun()

elif st.session_state.auth_state == 'DASHBOARD':
    user = st.session_state.current_user
    st.markdown(f'<p class="logo-text">Welcome, User {user["id"]}</p>', unsafe_allow_html=True)
    
    # Header Stats
    s1, s2, s3 = st.columns(3)
    with s1:
        st.markdown('<div class="stat-card"><b>Security Status</b><br><span style="color:#22c55e">● ACTIVE</span></div>', unsafe_allow_html=True)
    with s2:
        st.markdown(f'<div class="stat-card"><b>Last Access</b><br>{user["last_login"] if user["last_login"] else "First Session"}</div>', unsafe_allow_html=True)
    with s3:
        st.markdown('<div class="stat-card"><b>Linked Device</b><br>Physical Serial #104</div>', unsafe_allow_html=True)

    st.divider()
    
    tabs = st.tabs(["🔒 Operations", "🛡️ Security Health", "⚙️ Admin Control"] if user['is_admin'] else ["🔒 Operations", "🛡️ Security Health"])
    
    with tabs[0]:
        st.subheader("Protected Business Systems")
        st.info("System is ready for encrypted data operations.")
        c1, c2, c3 = st.columns(3)
        c1.metric("Cloud Uptime", "99.9%", "+0.01%")
        c2.metric("Encryption Key", "AES-256", "ROTATING")
        c3.metric("Network Delay", "12ms", "-2ms")

    with tabs[1]:
        st.subheader("Security Health Check")
        st.write("Your account is utilizing **Triple-Layer** defense.")
        st.progress(100, text="Layer 1: Credentials (bcrypt-12)")
        st.progress(100, text="Layer 2: SMS Verification (Virtual)")
        st.progress(100, text="Layer 3: Biometric Scan (Linked)")
        st.success("Your security score is: **Elite (98/100)**")

    if user['is_admin']:
        with tabs[2]:
            st.subheader("Global User Command")
            users = get_all_users()
            df = pd.DataFrame(users, columns=['ID', 'Phone', 'Locked', 'Admin', 'Bio_Idx', 'Login', 'Created'])
            st.dataframe(df, use_container_width=True)
            
            st.divider()
            ac1, ac2 = st.columns([1, 2])
            with ac1:
                t_id = st.number_input("Target User ID", min_value=1, step=1)
                action = st.selectbox("Command", ["No Action", "Toggle Lock", "Toggle Admin", "Update Phone", "Reset Password", "TERMINATE ACCOUNT"])
                
                if st.button("Deploy Command"):
                    if action == "Toggle Lock":
                        current = [u['is_locked'] for u in users if u['id'] == t_id][0]
                        toggle_user_lock(t_id, not current)
                        st.success("Lock status updated.")
                    elif action == "Toggle Admin":
                        current = [u['is_admin'] for u in users if u['id'] == t_id][0]
                        toggle_user_admin(t_id, not current)
                        st.success("Privileges updated.")
                    elif action == "TERMINATE ACCOUNT":
                        delete_user(t_id)
                        st.error("User purged from system.")
                    st.rerun()
            
            with ac2:
                st.write("### Live Audit Feed")
                logs = get_all_audit_logs(20)
                st.table(pd.DataFrame(logs))
                st.download_button("📥 Export Audit Data", data=pd.DataFrame(logs).to_csv(), file_name="audit_logs.csv", mime="text/csv")

    st.divider()
    if st.button("Terminate Session"):
        st.session_state.auth_state = 'CREDENTIALS'
        st.session_state.current_user = None
        st.rerun()
