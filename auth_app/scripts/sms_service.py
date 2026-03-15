import random
import streamlit as st

def send_otp(phone_number: str):
    """
    Simulates sending a 6-digit code by storing it in a session-safe virtual inbox.
    """
    if 'virtual_inbox' not in st.session_state:
        st.session_state.virtual_inbox = {}
        
    otp = str(random.randint(100000, 999999))
    st.session_state.virtual_inbox[phone_number] = otp
    
    # Also print to terminal for backup
    print(f"[VIRTUAL SMS] OTP for {phone_number}: {otp}")
    return True

def check_otp(phone_number: str, code: str):
    """
    Checks the session-safe virtual inbox for a matching code.
    """
    if 'virtual_inbox' in st.session_state:
        inbox = st.session_state.virtual_inbox
        if phone_number in inbox and inbox[phone_number] == code:
            # Clear the code after successful verification for security
            del st.session_state.virtual_inbox[phone_number]
            return True
    return False

def get_latest_otp(phone_number: str):
    """
    Helper for the UI to 'peek' into the inbox.
    """
    if 'virtual_inbox' in st.session_state:
        return st.session_state.virtual_inbox.get(phone_number)
    return None
