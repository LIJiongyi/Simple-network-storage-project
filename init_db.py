import sqlite3
import os
import hashlib
import secrets
import datetime


def initialize_database():

    # Create database directory if it doesn't exist
    # database file path
    print("start database initialization")
    if os.path.exists('storage.db'):
        print("Removing existing database...")
        os.remove('storage.db')

    # Connect to the database
    connect = sqlite3.connect('storage.db')
    cursor = connect.cursor()

    # Enable foreign key constraints
    cursor.execute('PRAGMA foreign_keys = ON')

    print("create tables")
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        creation_date TIMESTAMP NOT NULL,
        last_login TIMESTAMP,
        is_admin BOOLEAN DEFAULT 0,
        reset_token TEXT,
        reset_token_expiry TIMESTAMP
    )
    ''')

    # Create files table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        file_id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        owner_id INTEGER NOT NULL,
        upload_date TIMESTAMP NOT NULL,
        last_modified TIMESTAMP NOT NULL,
        file_size INTEGER NOT NULL,
        file_path TEXT NOT NULL,
        is_deleted BOOLEAN DEFAULT 0,
        FOREIGN KEY (owner_id) REFERENCES users(user_id)
    )
    ''')

    # Create file keys table (for encryption) - Separate from file metadata for security
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_keys (
        file_id INTEGER PRIMARY KEY,
        key_encrypted TEXT NOT NULL,
        iv TEXT NOT NULL,
        FOREIGN KEY (file_id) REFERENCES files(file_id)
    )
    ''')

    # Create file sharing permissions table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_permissions (
        permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        granted_by INTEGER NOT NULL,
        granted_date TIMESTAMP NOT NULL,
        FOREIGN KEY (file_id) REFERENCES files(file_id),
        FOREIGN KEY (user_id) REFERENCES users(user_id),
        FOREIGN KEY (granted_by) REFERENCES users(user_id),
        UNIQUE(file_id, user_id)
    )
    ''')

    # Create audit log table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action_type TEXT NOT NULL,
        action_details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP NOT NULL,
        signature TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )
    ''')

    # Create session table for managing user sessions
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )
    ''')

    # Create an admin account if it doesn't exist
    create_admin_account(cursor,connect)

    # Commit the changes and close the connection
    connect.commit()
    connect.close()

    print("Database initialized successfully.")


def create_admin_account(cursor,connection):
    """
    Create an admin account if it doesn't already exist.
    """
    # Check if admin exists
    cursor.execute("SELECT user_id FROM users WHERE username = 'admin'")
    if cursor.fetchone() is None:
        # Generate a random password for first-time setup
        admin_password = secrets.token_hex(8)

        # Generate a salt and hash the password
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((admin_password + salt).encode()).hexdigest()

        # Insert admin user
        cursor.execute('''
        INSERT INTO users (username, password_hash, salt, creation_date, is_admin)
        VALUES (?, ?, ?, ?, ?)
        ''', ('admin', password_hash, salt, datetime.datetime.now(), 1))

        print(f"Admin account created with username 'admin' and password '{admin_password}'")
        print("IMPORTANT: Change this password immediately after first login!")
    else:
        print("Admin account already exists.")

    connection.commit()


if __name__ == "__main__":
    initialize_database()
    print("Database setup complete")


































































