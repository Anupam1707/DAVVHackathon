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
  .env.example       # Environment Configuration Template
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

### 3. Configuration
Rename `.env.example` to `.env` and add your credentials:

#### Gmail Setup (Required for Email OTP)
1. **Enable 2-Factor Authentication** on your Gmail account
2. **Generate an App Password**:
   - Go to [Google Account Settings](https://myaccount.google.com/security)
   - Under "Signing in to Google", click "App passwords"
   - Select "Mail" and "Other (custom name)"
   - Enter "Guardian Auth" as the name
   - Copy the 16-character password

3. **Configure `.env`**:
```bash
GMAIL_USER=your.gmail@gmail.com
GMAIL_APP_PASSWORD=abcd-efgh-ijkl-mnop  # Your 16-char app password
JWT_SECRET=your_random_secret
```

*Note: If Gmail credentials are missing, the app runs in **Mock Mode** (OTP logged to console and shown in the sidebar inbox).*

### 4. Run the App
```bash
streamlit run auth_app/app.py
```

## 🧪 Testing the Flow
1.  Open the app and use the **"Initialize Admin User"** button in the sidebar.
2.  Login with:
    *   **Email**: `admin@guardian.local`
    *   **Passphrase**: `AdminPassword123`
3.  Enter the MFA code (If in Mock Mode, check the sidebar inbox or console for the OTP).
4.  For the Biometric step, either click "Verify Fingerprint" or type **'s'** in the trigger box and press Enter.
