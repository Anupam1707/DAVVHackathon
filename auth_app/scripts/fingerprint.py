import os
import time
from dotenv import load_dotenv

load_dotenv()

# Attempt to import pyfingerprint
try:
    from pyfingerprint.pyfingerprint import PyFingerprint
    PYFINGERPRINT_AVAILABLE = True
except ImportError:
    PYFINGERPRINT_AVAILABLE = False

SERIAL_PORT = os.getenv('FINGERPRINT_SERIAL_PORT', '/dev/ttyUSB0')

class FingerprintManager:
    def __init__(self, port=SERIAL_PORT, baudrate=57600):
        self.f = None
        self.mock_mode = not PYFINGERPRINT_AVAILABLE
        
        if PYFINGERPRINT_AVAILABLE:
            try:
                self.f = PyFingerprint(port, baudrate, 0xFFFFFFFF, 0x0000)
                if not self.f.verifyPassword():
                    raise Exception('Invalid fingerprint sensor password')
            except Exception as e:
                print(f"Fingerprint Sensor Error: {e}. Switching to Mock Mode.")
                self.mock_mode = True
        else:
            print("pyfingerprint library not found. Running in Mock Mode.")

    def verify_user(self, expected_index: int) -> bool:
        """
        Triggers the sensor to wait for a finger, captures the image,
        and compares it to the template stored at expected_index.
        """
        if self.mock_mode:
            print(f"[MOCK FINGERPRINT] Waiting for finger (checking index {expected_index})...")
            time.sleep(2)
            return True # In mock mode, we assume success
            
        try:
            print('Waiting for finger...')
            while not self.f.readImage():
                pass

            self.f.convertImage(0x01)
            result = self.f.searchTemplate()

            positionNumber = result[0]
            accuracyScore = result[1]

            if positionNumber == expected_index:
                return True
            return False
        except Exception as e:
            print(f"Verification Error: {e}")
            return False

    def enroll_user(self) -> int:
        """
        Captures finger twice to create a new template and returns the storage index.
        """
        if self.mock_mode:
            print("[MOCK FINGERPRINT] Enrolling user...")
            time.sleep(2)
            return 1 # Return mock index
            
        try:
            print('Waiting for finger to enroll (1/2)...')
            while not self.f.readImage():
                pass
            self.f.convertImage(0x01)
            
            print('Remove finger...')
            time.sleep(2)
            
            print('Waiting for same finger again (2/2)...')
            while not self.f.readImage():
                pass
            self.f.convertImage(0x02)
            
            if self.f.compareCharacteristics() == 0:
                raise Exception('Fingers do not match')

            self.f.createTemplate()
            positionNumber = self.f.storeModel()
            
            return positionNumber
        except Exception as e:
            print(f"Enrollment Error: {e}")
            return -1

if __name__ == "__main__":
    # Test
    fm = FingerprintManager()
    print("Mock Mode:", fm.mock_mode)
