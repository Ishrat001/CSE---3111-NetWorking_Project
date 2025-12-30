# server/db/user_db.py
import sqlite3
import hashlib
import secrets
from typing import Tuple, Optional, Dict
import os

class UserDatabase:
    """Handles user registration and authentication"""
    
    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Create users table if not exists"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            """)
            conn.commit()
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
    
    def register_user(self, full_name: str, username: str, password: str) -> Tuple[bool, str]:
        """Register new user - UI theke call hobe"""
        # Validation
        if not full_name or len(full_name.strip()) < 2:
            return False, "Full name is required"
        
        if not username or len(username.strip()) < 3:
            return False, "Username must be at least 3 characters"
        
        if not password or len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        # Check username exists
        if self.get_user(username):
            return False, "Username already exists"
        
        # Create user
        salt = secrets.token_hex(16)
        password_hash = self._hash_password(password, salt)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO users (full_name, username, password_hash, salt)
                    VALUES (?, ?, ?, ?)
                """, (full_name.strip(), username.strip(), password_hash, salt))
                conn.commit()
            return True, "Registration successful"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except Exception as e:
            return False, f"Registration failed: {str(e)}"
    
    def login_user(self, username: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
        """Authenticate user - UI theke call hobe"""
        user = self.get_user(username)
        if not user:
            return False, "Invalid username or password", None
        
        # Verify password
        test_hash = self._hash_password(password, user['salt'])
        if test_hash != user['password_hash']:
            return False, "Invalid username or password", None
        
        # Update last login
        self.update_last_login(user['id'])
        
        return True, "Login successful", user
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                row = cursor.fetchone()
                if row:
                    return dict(row)
        except Exception:
            pass
        return None
    
    def update_last_login(self, user_id: int):
        """Update last login timestamp"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
                """, (user_id,))
                conn.commit()
        except Exception:
            pass

# Global instance
user_db = UserDatabase()