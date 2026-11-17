# server/db_manager.py
import sqlite3
import os

class DBManager:
    def __init__(self, db_path="vpn_database.db"):
        self.db_path = db_path
        self.init_db()
        self.init_test_firewall_rules()
        
        # Create a default test user if it doesn't exist (2GB Quota)
        if not self.verify_user("test", "test"):
            self.add_user("test", "test", 2 * 1024 * 1024 * 1024)

        # Creating the admin user with a large quota (100GB) for testing purposes
        self.add_user("admin", "admin", 100 * 1024**3)

    def get_conn(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        with self.get_conn() as conn:
            cursor = conn.cursor()
            # UPDATED: Added 'status' column
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    total_quota INTEGER NOT NULL,
                    used_quota INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'ACTIVE' -- 'ACTIVE', 'BANNED', 'QUOTA_EXHAUSTED'
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    end_time DATETIME,
                    upload_bytes INTEGER DEFAULT 0,
                    download_bytes INTEGER DEFAULT 0,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    domain TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_ip TEXT,
                    target_port INTEGER,
                    target_domain TEXT,
                    action TEXT NOT NULL,
                    user_id INTEGER 
                )
            ''')
            # NEW: Firewall Logs Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS firewall_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    attempted_ip TEXT,
                    attempted_port INTEGER,
                    attempted_domain TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')
            conn.commit()

    def add_user(self, username, password, quota):
        try:
            with self.get_conn() as conn:
                conn.execute("INSERT INTO users (username, password, total_quota) VALUES (?, ?, ?)",
                             (username, password, quota))
        except sqlite3.IntegrityError:
            pass # User already exists

    # UPDATED: Check status as well as quota
    def verify_user(self, username, password):
        with self.get_conn() as conn:
            # Removed "AND status = 'ACTIVE'" so they can still log into the web portal
            cursor = conn.execute("SELECT id FROM users WHERE username = ? AND password = ?",
                                  (username, password))
            return cursor.fetchone() is not None

    def check_quota(self, username):
        with self.get_conn() as conn:
            cursor = conn.execute("SELECT total_quota, used_quota, status FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                # Return True ONLY if they have quota AND are not banned
                return row[0] > row[1] and row[2] != 'BANNED'
            return False

    def create_session(self, username):
        """Creates a new session record and returns the session ID."""
        with self.get_conn() as conn:
            cursor = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()
            if not user_row: 
                return None
            user_id = user_row[0]
            
            cursor = conn.execute("INSERT INTO sessions (user_id) VALUES (?)", (user_id,))
            return cursor.lastrowid

    # UPDATED: Explicitly set QUOTA_EXHAUSTED status
    def sync_usage(self, username, session_id, upload_diff, download_diff):
        with self.get_conn() as conn:
            conn.execute('''
                UPDATE sessions 
                SET upload_bytes = upload_bytes + ?, download_bytes = download_bytes + ?
                WHERE id = ?
            ''', (upload_diff, download_diff, session_id))
            
            conn.execute('''
                UPDATE users
                SET used_quota = used_quota + ? + ?
                WHERE username = ?
            ''', (upload_diff, download_diff, username))
            
            cursor = conn.execute("SELECT total_quota, used_quota FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                has_quota = row[0] > row[1]
                if not has_quota:
                    conn.execute("UPDATE users SET status = 'QUOTA_EXHAUSTED' WHERE username = ?", (username,))
                return has_quota
            return False

    def close_session(self, session_id):
        """Marks the session end time."""
        if session_id is None: 
            return
        with self.get_conn() as conn:
            conn.execute("UPDATE sessions SET end_time = CURRENT_TIMESTAMP WHERE id = ?", (session_id,))

    def add_firewall_rule(self, target_ip=None, target_port=None, target_domain=None, action='BLOCK', username=None):
        """Adds a firewall rule. If username is None, it applies globally."""
        with self.get_conn() as conn:
            user_id = None
            if username:
                cursor = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
                row = cursor.fetchone()
                if row:
                    user_id = row[0]
            
            # Check if rule already exists to prevent duplicates during restarts
            cursor = conn.execute('''
                SELECT id FROM firewall_rules 
                WHERE IFNULL(target_ip, '') = IFNULL(?, '') 
                AND IFNULL(target_port, '') = IFNULL(?, '') 
                AND IFNULL(target_domain, '') = IFNULL(?, '') 
                AND action = ? AND IFNULL(user_id, '') = IFNULL(?, '')
            ''', (target_ip, target_port, target_domain, action, user_id))
            
            if not cursor.fetchone():
                conn.execute('''
                    INSERT INTO firewall_rules (target_ip, target_port, target_domain, action, user_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (target_ip, target_port, target_domain, action, user_id))

    def init_test_firewall_rules(self):
        """Injects some default rules for testing Phase 2.4"""
        # Block example.com domain (Advanced DNS/App-Layer filtering)
        self.add_firewall_rule(target_domain="example.com", action="BLOCK", username="test")
        # Block outgoing Telnet (Basic Port filtering)
        self.add_firewall_rule(target_port=23, action="BLOCK", username="test")

    def log_traffic(self, username, src_ip, dst_ip, dst_port, domain):
        """Logs a new connection to the database."""
        with self.get_conn() as conn:
            cursor = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                user_id = row[0]
                conn.execute('''
                    INSERT INTO traffic_logs (user_id, src_ip, dst_ip, dst_port, domain)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, src_ip, dst_ip, dst_port, domain))

    # NEW: Log firewall blocks
    def log_firewall_block(self, username, ip, port, domain):
        with self.get_conn() as conn:
            cursor = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                conn.execute('''
                    INSERT INTO firewall_logs (user_id, attempted_ip, attempted_port, attempted_domain)
                    VALUES (?, ?, ?, ?)
                ''', (row[0], ip, port, domain))

    def get_all_users(self):
        with self.get_conn() as conn:
            return conn.execute("SELECT id, username, total_quota, used_quota, status FROM users").fetchall()
            
    def get_user(self, username):
        with self.get_conn() as conn:
            return conn.execute("SELECT id, username, total_quota, used_quota, status FROM users WHERE username=?", (username,)).fetchone()
            
    def get_traffic_logs(self, limit=50):
        with self.get_conn() as conn:
            return conn.execute('''
                SELECT users.username, src_ip, dst_ip, dst_port, domain, timestamp 
                FROM traffic_logs JOIN users ON traffic_logs.user_id = users.id 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,)).fetchall()
            
    def get_firewall_logs(self, limit=50):
        with self.get_conn() as conn:
            return conn.execute('''
                SELECT users.username, attempted_ip, attempted_port, attempted_domain, timestamp 
                FROM firewall_logs JOIN users ON firewall_logs.user_id = users.id 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,)).fetchall()
            
    def get_all_firewall_rules(self):
        with self.get_conn() as conn:
            return conn.execute('''
                SELECT firewall_rules.id, target_ip, target_port, target_domain, action, users.username 
                FROM firewall_rules LEFT JOIN users ON firewall_rules.user_id = users.id
            ''').fetchall()
            
    def delete_firewall_rule(self, rule_id):
        with self.get_conn() as conn:
            conn.execute("DELETE FROM firewall_rules WHERE id=?", (rule_id,))
            
    def add_quota(self, username, amount_bytes):
        """Simulates purchasing quota. Adds bytes and reactivates account."""
        with self.get_conn() as conn:
            conn.execute("UPDATE users SET total_quota = total_quota + ?, status = 'ACTIVE' WHERE username=?", (amount_bytes, username))