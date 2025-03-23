import os
import sqlite3
import hashlib
from datetime import datetime

def init_database():
    # database file path
    db_path = "storage.db"

    # connect to database
    connect = sqlite3.connect(db_path)

    # Enable foreign key constraints for referential integrity
    connect.execute("PRAGMA foreign_keys = ON")
    cursor=connect.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Users (
        UserID INTEGER PRIMARY KEY AUTOINCREMENT,
        Username TEXT UNIQUE NOT NULL,
        PasswordHash BLOB NOT NULL,
        Salt BLOB NOT NULL,
        RegistrationDate TIMESTAMP NOT NULL,
        LastLogin TIMESTAMP
        )
        ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Files (
        FileID INTEGER PRIMARY KEY AUTOINCREMENT,
        OwnerID INTEGER NOT NULL,
        EncryptedFileName TEXT NOT NULL,
        EncryptedFilePath TEXT NOT NULL,
        EncryptedFileKey BLOB NOT NULL,
        UploadDate TIMESTAMP NOT NULL,
        LastModified TIMESTAMP NOT NULL,
        FOREIGN KEY (OwnerID) REFERENCES Users(UserID) ON DELETE CASCADE
        )
        ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS FileSharing (
            SharingID INTEGER PRIMARY KEY AUTOINCREMENT,
            FileID INTEGER NOT NULL,
            SharedWithUserID INTEGER NOT NULL,
            PermissionType TEXT NOT NULL CHECK(PermissionType IN ('read', 'edit')),
            SharedDate TIMESTAMP NOT NULL,
            FOREIGN KEY (FileID) REFERENCES Files(FileID) ON DELETE CASCADE,
            FOREIGN KEY (SharedWithUserID) REFERENCES Users(UserID) ON DELETE CASCADE
        )
        ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ActivityLogs (
            LogID INTEGER PRIMARY KEY AUTOINCREMENT,
            UserID INTEGER NOT NULL,
            ActionType TEXT NOT NULL,
            Timestamp TIMESTAMP NOT NULL,
            IPAddress TEXT,
            ActionDetails TEXT,
            Signature BLOB NOT NULL,
            FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE CASCADE
        )
        ''')


    connect.commit()
    print("Data is initialize in db file")

    create_admin_account(connect)

    connect.close()

def create_admin_account(connect):
    cursor=connect.cursor()

    cursor.execute("SELECT UserID FROM Users WHERE Username='admin'")

    if cursor.fetchone() is None:
        # Generate salt and hash password
        salt = os.urandom(16)
        admin_password = "admin123"  # Should be changed immediately in production

        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            admin_password.encode('utf-8'),
            salt,
            100000  # Number of iterations (high for security)
        )

        # Insert admin user
        cursor.execute(
            "INSERT INTO Users (Username, PasswordHash, Salt, RegistrationDate) VALUES (?, ?, ?, ?)",
            ('admin', password_hash, salt, datetime.now())
        )
        connect.commit()
        print("Admin account created successfully")
    else:
        print("Admin account already exists")

    if __name__ == "__main__":
        # Run the initialization when script is executed
        init_database()
        print("Database setup complete")


