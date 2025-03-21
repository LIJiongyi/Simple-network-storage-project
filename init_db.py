import sqlite3
import hashlib
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'storage.db')

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users 
             (username TEXT PRIMARY KEY, password_hash TEXT, otp_secret TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS files 
             (file_id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, owner TEXT, encrypted_data BLOB)''')
c.execute('''CREATE TABLE IF NOT EXISTS shares 
             (file_id INTEGER, shared_with_username TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS logs 
             (log_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, action TEXT, timestamp TEXT)''')

admin_username = "admin"
admin_password = "admin123"
admin_password_hash = hashlib.sha256(admin_password.encode()).hexdigest()
admin_otp_secret = "JBSWY3DPEHPK3PXP"
c.execute("INSERT OR IGNORE INTO users (username, password_hash, otp_secret) VALUES (?, ?, ?)",
          (admin_username, admin_password_hash, admin_otp_secret))

conn.commit()
conn.close()
print("Database initialized with admin user at:", DB_PATH)