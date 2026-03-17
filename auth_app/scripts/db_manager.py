import sqlite3
import bcrypt
import os
from datetime import datetime
from typing import Optional, Tuple

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'auth.db')

def get_connection():
    # Ensure the directory exists
    db_dir = os.path.dirname(DB_PATH)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # User Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            is_locked BOOLEAN DEFAULT 0,
            is_admin BOOLEAN DEFAULT 0,
            fingerprint_index INTEGER DEFAULT -1,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Devices Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            uuid_hash TEXT NOT NULL,
            device_model TEXT,
            trusted_since DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    # Audit Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action_type TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def add_user(email: str, password: str, is_admin: bool = False, fingerprint_index: int = -1) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        pw_hash = hash_password(password)
        cursor.execute(
            'INSERT INTO users (email, password_hash, is_admin, fingerprint_index) VALUES (?, ?, ?, ?)',
            (email, pw_hash, 1 if is_admin else 0, fingerprint_index)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def update_fingerprint_index(user_id: int, index: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET fingerprint_index = ? WHERE id = ?', (index, user_id))
    conn.commit()
    conn.close()

def get_user_by_email(email: str):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def user_exists(email: str) -> bool:
    return get_user_by_email(email) is not None

def update_failed_attempts(user_id: int, reset: bool = False):
    conn = get_connection()
    cursor = conn.cursor()
    if reset:
        cursor.execute('UPDATE users SET failed_attempts = 0 WHERE id = ?', (user_id,))
    else:
        cursor.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', (user_id,))
        # Check lock condition
        cursor.execute('SELECT failed_attempts FROM users WHERE id = ?', (user_id,))
        attempts = cursor.fetchone()[0]
        if attempts >= 3:
            cursor.execute('UPDATE users SET is_locked = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

def log_audit(user_id: Optional[int], action_type: str, ip: str = None, user_agent: str = None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO audit_logs (user_id, action_type, ip_address, user_agent) VALUES (?, ?, ?, ?)',
        (user_id, action_type, ip, user_agent)
    )
    conn.commit()
    conn.close()

def set_last_login(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user_id))
    conn.commit()
    conn.close()

def get_all_users():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, is_locked, is_admin, fingerprint_index, last_login, created_at FROM users')
    users = cursor.fetchall()
    conn.close()
    return users

def toggle_user_lock(user_id: int, status: bool):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_locked = ? WHERE id = ?', (1 if status else 0, user_id))
    conn.commit()
    conn.close()

def toggle_user_admin(user_id: int, status: bool):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_admin = ? WHERE id = ?', (1 if status else 0, user_id))
    conn.commit()
    conn.close()

def update_user_details(user_id: int, new_email: str = None, new_password: str = None):
    conn = get_connection()
    cursor = conn.cursor()
    if new_email:
        cursor.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, user_id))
    if new_password:
        pw_hash = hash_password(new_password)
        cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (pw_hash, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    cursor.execute('DELETE FROM devices WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def get_all_audit_logs(limit: int = 50):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?', (limit,))
    logs = cursor.fetchall()
    conn.close()
    return logs

def get_user_audit_logs(user_id: int, limit: int = 50):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?', (user_id, limit))
    logs = cursor.fetchall()
    conn.close()
    return logs

def factory_reset():
    import sqlite3
    # Ensure any existing connections are handled (though SQLite handles file deletion ok usually)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()

if __name__ == "__main__":
    init_db()
    print("Database initialized.")
