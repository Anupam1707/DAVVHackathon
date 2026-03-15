import random

# Global dictionary to act as the "network" holding sent messages
# In a real app, this would be a database, but for a demo, a global works.
VIRTUAL_INBOX = {}

def send_otp(phone_number: str):
    """
    Simulates sending a 6-digit code by storing it in a virtual inbox.
    """
    otp = str(random.randint(100000, 999999))
    VIRTUAL_INBOX[phone_number] = {
        'code': otp,
        'timestamp': None # Could add expiry logic here
    }
    print(f"[VIRTUAL SMS] OTP for {phone_number}: {otp}")
    return True

def check_otp(phone_number: str, code: str):
    """
    Checks the virtual inbox for a matching code.
    """
    if phone_number in VIRTUAL_INBOX:
        stored_code = VIRTUAL_INBOX[phone_number]['code']
        if code == stored_code:
            # Clear the inbox after successful use
            del VIRTUAL_INBOX[phone_number]
            return True
    return False

def get_latest_otp(phone_number: str):
    """
    Helper for the UI to 'peek' into the inbox.
    """
    return VIRTUAL_INBOX.get(phone_number, {}).get('code')
