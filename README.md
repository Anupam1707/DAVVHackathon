# Mobile-First Secure Auth (No-Web/No-Email Edition)

## 📌 Project Overview
A high-security authentication system designed for small businesses where security is tied directly to **Physical Hardware** and **Phone Numbers**. This system eliminates the need for company emails or websites, focusing on a multi-layered defense strategy for mobile-first environments.

## 👥 Team Members
*   **Anupam**
*   **Aishwarya**
*   **Khushvardhan**

## 🛡️ Security Architecture

### 1. Credential Layer (bcrypt)
*   **Implementation**: Password hashing using `bcrypt` with **12 salt rounds**.
*   **Policy**: Enforced 12-character minimum passphrase policy.
*   **Protection**: Generic error messages to prevent user enumeration.

### 2. SMS MFA Layer (Twilio Verify)
*   **Service**: Twilio Verify API for secure 6-digit OTP delivery.
*   **Logic**: 
    *   3-strike lockout policy (`is_locked = 1`).
    *   Exponential backoff on failed attempts to mitigate brute-force.

### 3. Physical Biometric Layer (PyFingerprint)
*   **Hardware Interface**: Serial communication (typically `/dev/ttyUSB0`) for fingerprint sensors.
*   **Simulation Mode**: Includes a keyboard-based trigger (Type 's') for environments without physical hardware.
*   **Role-Based**: Mandatory for 'Admin' accounts to prevent unauthorized lateral movement.

### 4. Audit & Session Management
*   **Audit Logging**: Every success, failure, and lockout is logged in a local SQLite `audit_logs` table.
*   **Session Security**: Signed JWT tokens for session state management.
*   **Rate Limiting**: 2-second forced delay on all failed login attempts.

---

## 📂 Project Structure
```text
/auth_app
  /data
    auth.db          # SQLite Database (Auto-initialized)
  /scripts
    fingerprint.py   # Fingerprint hardware logic & Simulation
    sms_service.py   # Twilio API integration & Mock mode
    db_manager.py    # SQL queries, bcrypt hashing, and User locking
  app.py             # Main Streamlit Entry Point
  requirements.txt   # Project Dependencies
  .env.example       # Environment Configuration Template
```

## 🚀 Getting Started

### 1. Prerequisites
*   Python 3.8+
*   (Optional) Twilio Account for real SMS.
*   (Optional) Fingerprint Sensor for hardware verification.

### 2. Installation
```bash
pip install -r auth_app/requirements.txt
```

### 3. Configuration
Rename `.env.example` to `.env` and add your credentials:
```bash
TWILIO_ACCOUNT_SID=your_sid
TWILIO_AUTH_TOKEN=your_token
TWILIO_VERIFY_SERVICE_SID=your_service_sid
JWT_SECRET=your_random_secret
```
*Note: If credentials are missing, the app defaults to **Mock Mode** (OTP is `123456`).*

### 4. Run the App
```bash
streamlit run auth_app/app.py
```

## 🧪 Testing the Flow
1.  Open the app and use the **"Initialize Admin User"** button in the sidebar.
2.  Login with:
    *   **Phone**: `+1234567890`
    *   **Passphrase**: `SecurePassphrase123`
3.  Enter the MFA code (If in Mock Mode, use `123456`).
4.  For the Biometric step, either click "Verify Fingerprint" or type **'s'** in the trigger box and press Enter.
