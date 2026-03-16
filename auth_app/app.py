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
    update_user_details, delete_user, factory_reset, get_user_audit_logs
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

# --- Advanced CSS ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    .main {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        color: #f8fafc;
    }
    .st-emotion-cache-1r6slb0, .st-emotion-cache-12w0qpk {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        border-radius: 16px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 2rem;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
    }
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
    .stTextInput>div>div>input {
        background: rgba(255, 255, 255, 0.05) !important;
        color: white !important;
        border-radius: 10px !important;
        border: 1px solid rgba(255, 255, 255, 0.2) !important;
        padding: 1rem !important;
    }
    .phone-container {
        background: #000;
        border: 12px solid #222;
        border-radius: 45px;
        padding: 10px;
        margin-top: 10px;
        height: 500px;
        box-shadow: 0 20px 50px rgba(0,0,0,0.5);
        position: relative;
    }
    .phone-screen {
        background: #f4f4f4;
        height: 100%;
        border-radius: 35px;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        color: #333;
    }
    .sms-header {
        background: #ffffff;
        padding: 20px 15px 10px 15px;
        border-bottom: 1px solid #ddd;
        text-align: center;
        font-weight: 700;
        font-size: 1.1rem;
        color: #000;
    }
    .sms-contact {
        display: flex;
        align-items: center;
        padding: 10px;
        background: #fff;
        margin-bottom: 10px;
    }
    .avatar {
        width: 35px;
        height: 35px;
        background: #ccc;
        border-radius: 50%;
        margin-right: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.8rem;
        color: white;
        font-weight: bold;
    }
    .message-list {
        padding: 10px;
        flex-grow: 1;
    }
    .message-bubble {
        background: #e9e9eb;
        color: black;
        padding: 10px 14px;
        border-radius: 18px;
        margin-bottom: 8px;
        font-size: 0.85rem;
        max-width: 85%;
        align-self: flex-start;
        line-height: 1.4;
        position: relative;
    }
    .message-bubble.blue {
        background: #007aff;
        color: white;
    }
    .sms-time {
        font-size: 0.7rem;
        color: #999;
        margin-top: 4px;
        text-align: right;
    }
    .stat-card {
        background: rgba(255, 255, 255, 0.03);
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 4px solid #6366f1;
    }
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

def generate_token(user_id: int, phone: str):
    payload = {
        'user_id': user_id,
        'phone': phone,
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
if 'last_active_phone' not in st.session_state:
    st.session_state.last_active_phone = None
if 'virtual_inbox' not in st.session_state:
    st.session_state.virtual_inbox = {}
if 'session_token' not in st.session_state:
    st.session_state.session_token = None

def set_state(state):
    st.session_state.auth_state = state

# --- Sidebar: The Virtual Phone ---
with st.sidebar:
    st.markdown('<p class="logo-text">GUARDIAN</p>', unsafe_allow_html=True)
    st.write("🔒 **Mobile Hardware Auth**")
    st.divider()
    
    st.subheader("📱 Device Inbox")
    
    # Track which phone number we should look for messages for
    phone_to_watch = st.session_state.last_active_phone
    
    st.markdown("""
        <div class="phone-container">
            <div class="phone-screen">
                <div class="sms-header">Messages</div>
    """, unsafe_allow_html=True)

    if phone_to_watch:
        st.markdown(f"""
            <div class="sms-contact">
                <div class="avatar" style="background:#007aff">G</div>
                <div style="font-size:0.9rem; font-weight:600">Guardian Auth</div>
            </div>
            <div class="message-list">
        """, unsafe_allow_html=True)
        
        otp = get_latest_otp(phone_to_watch)
        if otp:
            st.markdown(f"""
                <div class="message-bubble">
                    Your verification code is <b>{otp}</b>. Valid for 5 minutes.
                    <div class="sms-time">Now</div>
                </div>
            """, unsafe_allow_html=True)
            if st.button("📋 Copy OTP", key="copy_otp_btn", use_container_width=True):
                # Placeholder for clipboard copy - will show success
                st.toast(f"OTP {otp} copied!")
        else:
            st.markdown("""
                <div style="text-align:center; padding-top:40px; color:#999; font-size:0.8rem">
                    No messages yet from {phone_to_watch}
                </div>
            """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.markdown("""
            <div style="text-align:center; padding-top:100px; color:#999; font-size:0.9rem">
                📵 Connect Device
            </div>
        """, unsafe_allow_html=True)

    st.markdown('</div></div>', unsafe_allow_html=True)

    st.divider()
    with st.expander("🛠️ Advanced Settings"):
        if st.button("☣️ Factory Reset"):
            factory_reset()
            # Auto-initialize master admin after factory reset
            add_user("+1000", "AdminPassword123", is_admin=True)
            
            st.session_state.auth_state = 'CREDENTIALS'
            st.session_state.current_user = None
            st.session_state.last_active_phone = None
            st.session_state.virtual_inbox = {}
            st.session_state.session_token = None
            st.success("System wiped. Master Admin (+1000) auto-initialized.")
            time.sleep(1)
            st.rerun()

# --- Main Flow ---
if st.session_state.auth_state == 'CREDENTIALS':
    st.markdown('<p class="logo-text">Sign In</p>', unsafe_allow_html=True)
    st.write("Enter your hardware-linked credentials.")
    
    phone = st.text_input("Device ID / Phone Number", placeholder="+1XXXXXXXXXX")
    password = st.text_input("Security Passphrase", type="password")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Identify Device"):
            user = get_user_by_phone(phone)
            if user:
                if user['is_locked']:
                    st.error("❌ Hardware Locked.")
                elif verify_password(password, user['password_hash']):
                    update_failed_attempts(user['id'], reset=True)
                    log_audit(user['id'], "LOGIN_ATTEMPT_SUCCESS")
                    st.session_state.last_active_phone = phone
                    st.session_state.current_user = user
                    if send_otp(phone):
                        set_state('MFA')
                        st.rerun()
                else:
                    update_failed_attempts(user['id'])
                    log_audit(user['id'], "LOGIN_ATTEMPT_FAILURE")
                    time.sleep(2)  # Rate limiting on failure
                    st.error("Invalid Credentials.")
            else:
                log_audit(None, f"LOGIN_ATTEMPT_UNKNOWN_PHONE: {phone}")
                time.sleep(2)  # Rate limiting on failure
                st.error("Invalid Credentials.")
    with col2:
        if st.button("Enroll New Device"):
            set_state('REGISTER_CREDENTIALS')
            st.rerun()

elif st.session_state.auth_state == 'REGISTER_CREDENTIALS':
    st.markdown('<p class="logo-text">Enrollment</p>', unsafe_allow_html=True)
    st.info("💡 Passphrase must be at least 12 characters long.")
    new_phone = st.text_input("Mobile Number", placeholder="+1XXXXXXXXXX")
    new_pass = st.text_input("Passphrase", type="password")
    confirm = st.text_input("Confirm", type="password")
    
    if st.button("Begin Link"):
        if len(new_pass) >= 12 and new_pass == confirm and not user_exists(new_phone):
            st.session_state.last_active_phone = new_phone
            st.session_state.temp_reg_data = {'phone': new_phone, 'password': new_pass}
            log_audit(None, f"REGISTRATION_STARTED: {new_phone}")
            if send_otp(new_phone):
                set_state('REGISTER_MFA')
                st.rerun()
        else:
            st.error("Check requirements and try again.")
    if st.button("Back"):
        set_state('CREDENTIALS')
        st.rerun()

elif st.session_state.auth_state in ['REGISTER_MFA', 'MFA']:
    st.markdown('<p class="logo-text">MFA Challenge</p>', unsafe_allow_html=True)
    st.info(f"Signal active for {st.session_state.last_active_phone}")
    otp_code = st.text_input("Verification Code", max_chars=6)
    
    if st.button("Verify"):
        if check_otp(st.session_state.last_active_phone, otp_code):
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
    sim = st.text_input("Keyboard Scan ('s' to simulate)", key="bio_sim")
    
    if st.button("Authorize") or sim.lower() == 's':
        fm = FingerprintManager()
        if st.session_state.auth_state == 'REGISTER_BIOMETRIC':
            idx = fm.enroll_user()
            if idx != -1:
                add_user(st.session_state.temp_reg_data['phone'], st.session_state.temp_reg_data['password'], fingerprint_index=idx)
                log_audit(None, f"USER_ENROLLED: {st.session_state.temp_reg_data['phone']}")
                set_state('CREDENTIALS')
            else:
                st.error("Biometric enrollment failed.")
        else:
            user = st.session_state.current_user
            if user['fingerprint_index'] == -1:
                idx = fm.enroll_user()
                update_fingerprint_index(user['id'], idx)
                log_audit(user['id'], "BIOMETRIC_ENROLLED_ON_LOGIN")
                set_last_login(user['id'])
                st.session_state.session_token = generate_token(user['id'], user['phone_number'])
                set_state('DASHBOARD')
            else:
                if fm.verify_user(user['fingerprint_index']):
                    log_audit(user['id'], "BIOMETRIC_VERIFIED")
                    set_last_login(user['id'])
                    st.session_state.session_token = generate_token(user['id'], user['phone_number'])
                    set_state('DASHBOARD')
                else:
                    log_audit(user['id'], "BIOMETRIC_FAILED")
                    time.sleep(2)
                    st.error("Biometric verification failed.")
        st.rerun()

elif st.session_state.auth_state == 'DASHBOARD':
    user = st.session_state.current_user
    st.markdown(f'<p class="logo-text">Authenticated: {user["phone_number"]}</p>', unsafe_allow_html=True)
    
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
                admin_new_phone = st.text_input("New Phone", key="admin_add_phone")
                admin_new_pass = st.text_input("Passphrase", type="password", key="admin_add_pass")
                if st.button("Create User"):
                    if len(admin_new_pass) >= 12 and not user_exists(admin_new_phone):
                        add_user(admin_new_phone, admin_new_pass)
                        log_audit(user['id'], f"ADMIN_ADDED_USER: {admin_new_phone}")
                        st.success("User created.")
                        st.rerun()
                    else:
                        st.error("Invalid phone or weak password.")

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

    if st.button("Logout"):
        log_audit(user['id'], "LOGOUT")
        st.session_state.auth_state = 'CREDENTIALS'
        st.session_state.current_user = None
        st.session_state.last_active_phone = None
        st.session_state.session_token = None
        st.rerun()
