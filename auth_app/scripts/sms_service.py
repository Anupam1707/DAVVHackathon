import os
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from dotenv import load_dotenv

load_dotenv()

TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_VERIFY_SERVICE_SID = os.getenv('TWILIO_VERIFY_SERVICE_SID')

# Mock mode if credentials are missing
IS_MOCK = not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SERVICE_SID])

if not IS_MOCK:
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def send_otp(phone_number: str):
    """
    Triggers Twilio to send a 6-digit code.
    """
    if IS_MOCK:
        print(f"[MOCK SMS] Sending OTP to {phone_number}: 123456")
        return True
    
    try:
        verification = client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID) \
            .verifications \
            .create(to=phone_number, channel='sms')
        return verification.status == 'pending'
    except TwilioRestException as e:
        print(f"Twilio Error: {e}")
        return False

def check_otp(phone_number: str, code: str):
    """
    Returns True if the code matches and hasn't expired.
    """
    if IS_MOCK:
        return code == "123456"
    
    try:
        verification_check = client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID) \
            .verification_checks \
            .create(to=phone_number, code=code)
        return verification_check.status == 'approved'
    except TwilioRestException as e:
        print(f"Twilio Error: {e}")
        return False
