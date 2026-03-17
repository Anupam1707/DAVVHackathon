# Mobile-First Secure Auth (No-Web/No-Email Edition)

## 📌 Project Overview
A high-security authentication system designed for small businesses where security is tied directly to **Email Addresses** and **Physical Hardware**. This system eliminates the need for company emails or websites, focusing on a multi-layered defense strategy for email-first environments.

## 👥 Team Members
*   **Anupam**
*   **Aishwarya**
*   **Khushvardhan**

## 🛡️ Security Architecture

### 1. Credential Layer (bcrypt)
*   **Implementation**: Password hashing using `bcrypt` with **12 salt rounds**.
*   **Policy**: Enforced 12-character minimum passphrase policy.
*   **Protection**: Generic error messages to prevent user enumeration.

### 2. Email MFA Layer (Gmail SMTP)
*   **Service**: Gmail SMTP for secure 6-digit OTP delivery via email.
*   **Logic**:
    *   3-strike lockout policy (`is_locked = 1`).
    *   Expiring 6-digit codes (default 5 minutes).
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
    email_service.py # Gmail SMTP integration & Mock mode
    db_manager.py    # SQL queries, bcrypt hashing, and User locking
  app.py             # Main Streamlit Entry Point
  requirements.txt   # Project Dependencies
  .env               # Environment Configuration (Optional, Git-ignored)

/.streamlit
  secrets.toml       # Streamlit Secrets Configuration (Primary, Git-ignored)
  config.toml        # Optional Streamlit UI settings

README.md            # This file
.gitignore           # Git ignore patterns
```

## 🚀 Getting Started

### 1. Prerequisites
*   Python 3.8+
*   Gmail account with app password (for email OTP)
*   (Optional) Fingerprint Sensor for hardware verification.

### 2. Installation
```bash
pip install -r auth_app/requirements.txt
```

### 3. Configuration (Dual-Source Support)
The app reads configuration from **either** `.streamlit/secrets.toml` (Streamlit Secrets, primary) **or** `.env` file (fallback). Both config methods are supported.

#### Option A: Streamlit Secrets (Recommended for Production)
Create `.streamlit/secrets.toml` at the project root:
```toml
GMAIL_USER = "your.gmail@gmail.com"
GMAIL_APP_PASSWORD = "your_16_char_app_password"
JWT_SECRET = "your_random_secret_key_here"
FINGERPRINT_SERIAL_PORT = "/dev/ttyUSB0"
OTP_EXPIRY_MINUTES = "5"
TWILIO_ACCOUNT_SID = "your_sid_here"
TWILIO_AUTH_TOKEN = "your_token_here"
TWILIO_VERIFY_SERVICE_SID = "your_service_sid_here"
```

#### Option B: .env File (Development/Local Override)
Create `auth_app/.env` for local development (will override secrets if set):
```bash
GMAIL_USER=your.gmail@gmail.com
GMAIL_APP_PASSWORD=your_16_char_app_password
JWT_SECRET=your_random_secret_key_here
FINGERPRINT_SERIAL_PORT=/dev/ttyUSB0
OTP_EXPIRY_MINUTES=5
TWILIO_ACCOUNT_SID=your_sid_here
TWILIO_AUTH_TOKEN=your_token_here
TWILIO_VERIFY_SERVICE_SID=your_service_sid_here
```

#### Gmail Setup (Required for Email OTP)
1. **Enable 2-Factor Authentication** on your Gmail account
2. **Generate an App Password**:
   - Go to [Google Account Settings](https://myaccount.google.com/security)
   - Under "Signing in to Google", click "App passwords"
   - Select "Mail" and "Other (custom name)"
   - Enter "Guardian Auth" as the name
   - Copy the 16-character password

3. **Add to `.streamlit/secrets.toml` or `auth_app/.env`**

*Note: If Gmail credentials are missing, the app runs in **Mock Mode** (OTP logged to console and shown in the sidebar inbox).*

### 4. Run the App
```bash
streamlit run auth_app/app.py
```

## 🧪 Testing the Flow

### Default Account (Auto-Created on Boot)
The app automatically creates a default admin account on every boot:
- **Email**: `anupamkanoongo@gmail.com`
- **Passphrase**: `AdminPassword123`
- **Role**: Admin

If this account is deleted, it will be recreated on the next app restart.

### Testing Steps
1. Open the app at `http://localhost:8501`
2. Login with:
   - **Email**: `anupamkanoongo@gmail.com`
   - **Passphrase**: `AdminPassword123`
3. Enter the MFA code (If in Mock Mode, check the sidebar or console for the OTP).
4. Complete the Biometric scan:
   - If fingerprint sensor is available, place your finger on the sensor.
   - In simulation mode, click "Touch Sensor to Authorize" and the app will mock-enroll your fingerprint.

### Admin Features
Once logged in as admin, access the **⚙️ Admin** tab to:
- **View all users** in the System Directory
- **Create new users** with the Quick Enroll form
- **Manage users**: Lock, unlock, delete, promote, or demote users
- **View audit logs** for system activity
- **Factory Reset**: Clear all users and reinitialize the default account

## 🔐 Default Security Policies
- **Password minimum**: 12 characters
- **Failed login attempts**: 3 attempts before lockout
- **OTP expiry**: 5 minutes (configurable)
- **Session token expiry**: 1 hour
- **Rate limiting**: 2-second delay on failed login attempts
