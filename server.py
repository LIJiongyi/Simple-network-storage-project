import socket
import json
import sqlite3
import time
import datetime
import threading
import os
import sys
import hashlib
import secrets
import base64
import re
import logging
from concurrent.futures import ThreadPoolExecutor
import pyotp  
# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SecureStorage")

# Server configuration
HOST = 'localhost'
PORT = 9999
MAX_BUFFER_SIZE = 8192  # 8KB buffer for basic messages
MAX_CONNECTIONS = 10
DB_PATH = 'storage.db'
TOKEN_EXPIRY = 7200  # Session token expiry in seconds (2 hours)
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes in seconds

# Rate limiting settings
RATE_LIMIT_WINDOW = 60  # 1 minute
RATE_LIMIT_MAX_REQUESTS = 30  # Max 30 requests per minute

# Dictionary to track rate limiting
rate_limit_tracker = {}

# Dictionary to track failed login attempts
failed_logins = {}

# Create a thread pool for handling client connections
thread_pool = ThreadPoolExecutor(max_workers=10)


def get_db_connection():
    """Create and return a database connection with proper settings"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allow column access by name
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def close_connection(conn):
    """Safely close a database connection"""
    if conn:
        conn.close()


def check_rate_limit(ip_address):
    """
    Implement rate limiting to prevent brute force attacks
    Returns True if request should be allowed, False otherwise
    """
    current_time = time.time()

    if ip_address not in rate_limit_tracker:
        rate_limit_tracker[ip_address] = {'count': 1, 'reset_time': current_time + RATE_LIMIT_WINDOW}
        return True

    tracker = rate_limit_tracker[ip_address]

    # If window has expired, reset the counter
    if current_time > tracker['reset_time']:
        tracker['count'] = 1
        tracker['reset_time'] = current_time + RATE_LIMIT_WINDOW
        return True

    # Check if we've hit the rate limit
    if tracker['count'] >= RATE_LIMIT_MAX_REQUESTS:
        return False

    # Increment the counter and allow the request
    tracker['count'] += 1
    return True


def generate_signature(user_id, action_type, timestamp, details=None):
    """
    Generate a digital signature for audit log non-repudiation
    This provides cryptographic proof of the action
    """
    # In a real system, this would use asymmetric cryptography
    # For simplicity, we'll use a keyed hash as signature
    server_secret = "SERVER_SECRET_KEY_CHANGE_IN_PRODUCTION"  # In production, use proper key management

    signature_data = f"{user_id}|{action_type}|{timestamp}"
    if details:
        signature_data += f"|{details}"

    signature = hashlib.sha256((signature_data + server_secret).encode()).hexdigest()
    return signature


def log_action(user_id, action_type, action_details=None, ip_address=None):
    """
    Record user actions with digital signature for non-repudiation
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        timestamp = datetime.datetime.now()

        # Generate cryptographic signature for non-repudiation
        signature = generate_signature(user_id, action_type, timestamp, action_details)

        # Insert into audit_logs table
        cursor.execute("""
            INSERT INTO audit_logs 
            (user_id, action_type, action_details, ip_address, timestamp, signature) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, action_type, action_details, ip_address, timestamp, signature))

        conn.commit()
        logger.info(f"Action logged: {action_type} by user {user_id}")
        return True
    except Exception as e:
        logger.error(f"Error logging action: {e}")
        return False
    finally:
        close_connection(conn)


def validate_input(data, regex_pattern=None):
    """
    Validate input data for common security issues
    Returns sanitized data or None if invalid
    """
    if data is None:
        return None

    # Convert to string if not already
    if not isinstance(data, str):
        data = str(data)

    # Check for SQL injection patterns
    sql_patterns = [
        "--", ";--", ";", "/*", "*/", "@@", "@",
        "EXEC", "EXECUTE", "INSERT", "DROP", "DELETE", "UPDATE", "SELECT",
        "UNION", "CREATE", "ALTER", "TRUNCATE", "DECLARE", "WAITFOR"
    ]

    # Convert to lowercase for case-insensitive comparison
    data_lower = data.lower()
    for sql_pattern in sql_patterns:  # Changed variable name here
        if sql_pattern.lower() in data_lower:
            logger.warning(f"Potential SQL injection detected: {data}")
            return None

    # Check for path traversal
    if ".." in data or "/" in data or "\\" in data:
        if not (regex_pattern and re.match(regex_pattern, data)):
            logger.warning(f"Potential path traversal detected: {data}")
            return None

    # If a specific pattern is provided, validate against it
    if regex_pattern and not re.match(regex_pattern, data):
        logger.warning(f"Input validation failed for pattern {regex_pattern}: {data}")
        return None

    return data

def create_session(user_id, ip_address=None, user_agent=None):
    """
    Create a new session for a user and return the session ID
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Generate a secure random session ID
        session_id = secrets.token_hex(32)

        # Set expiry time
        created_at = datetime.datetime.now()
        expires_at = created_at + datetime.timedelta(seconds=TOKEN_EXPIRY)

        # Remove any existing sessions for this user
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

        # Create new session
        cursor.execute("""
            INSERT INTO sessions 
            (session_id, user_id, created_at, expires_at, ip_address, user_agent) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session_id, user_id, created_at, expires_at, ip_address, user_agent))

        conn.commit()
        return session_id
    except Exception as e:
        logger.error(f"Error creating session: {e}")
        return None
    finally:
        close_connection(conn)


def validate_session(session_id, user_id=None):
    """
    Validate a session ID
    Returns user_id if valid, None otherwise
    """
    if not session_id:
        return None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get session information
        cursor.execute("""
            SELECT user_id, expires_at 
            FROM sessions 
            WHERE session_id = ?
        """, (session_id,))

        session = cursor.fetchone()

        # Check if session exists and hasn't expired
        if not session:
            return None

        expires_at = datetime.datetime.fromisoformat(session['expires_at'])
        if expires_at < datetime.datetime.now():
            # Session expired, delete it
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            conn.commit()
            return None

        # If user_id is provided, verify it matches the session
        if user_id and session['user_id'] != user_id:
            return None

        return session['user_id']
    except Exception as e:
        logger.error(f"Error validating session: {e}")
        return None
    finally:
        close_connection(conn)


def handle_register(request, ip_address=None):
    """
    Handle user registration request
    """
    # Validate inputs
    username = validate_input(request.get("username"), r'^[a-zA-Z0-9_]{3,32}$')
    password_hash = request.get("password_hash")

    if not username or not password_hash:
        return {"status": "error", "message": "Invalid username or password format"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return {"status": "error", "message": "Username already exists"}

        # Generate a salt and final password hash
        salt = secrets.token_hex(16)
        final_password_hash = hashlib.sha256((password_hash + salt).encode()).hexdigest()

        # Generate OTP secret for MFA
        otp_secret = pyotp.random_base32()

        # Insert new user
        cursor.execute("""
    INSERT INTO users 
    (username, password_hash, salt, creation_date, last_login, otp_secret) 
    VALUES (?, ?, ?, ?, ?, ?)
""", (username, final_password_hash, salt, datetime.datetime.now(), None, otp_secret))
        user_id = cursor.lastrowid
        conn.commit()

        # Log the registration
        log_action(user_id, "user_register", f"New user registered: {username}", ip_address)

        # Generate OTP provisioning URI for QR code
        otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
            name=username,
            issuer_name="SecureStorage"
        )

        return {
            "status": "success",
            "message": "User registered successfully",
            "user_id": user_id,
            "otp_secret": otp_secret,
            "otp_uri": otp_uri
        }
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return {"status": "error", "message": "Registration failed"}
    finally:
        close_connection(conn)


def handle_login(request, ip_address=None):
    """
    Handle user login request with MFA
    """
    username = validate_input(request.get("username"))
    password_hash = request.get("password_hash")
    otp_code = request.get("otp_code")

    if not username or not password_hash:
        return {"status": "error", "message": "Invalid credentials"}

    # Check for brute force attempts
    current_time = time.time()
    if username in failed_logins:
        attempts, lockout_time = failed_logins[username]
        if attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            if current_time < lockout_time:
                return {"status": "error", "message": "Account temporarily locked. Try again later."}
            else:
                # Reset failed attempts after lockout period
                failed_logins[username] = (0, 0)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user information
        cursor.execute("""
            SELECT user_id, password_hash, salt, is_admin, otp_secret 
            FROM users 
            WHERE username = ?
        """, (username,))

        user = cursor.fetchone()
        if not user:
            # Increment failed login attempts
            if username in failed_logins:
                attempts, _ = failed_logins[username]
                failed_logins[username] = (
                attempts + 1, current_time + LOCKOUT_TIME if attempts + 1 >= MAX_FAILED_LOGIN_ATTEMPTS else 0)
            else:
                failed_logins[username] = (1, 0)

            return {"status": "error", "message": "Invalid credentials"}

        # Verify password
        expected_hash = hashlib.sha256((password_hash + user['salt']).encode()).hexdigest()
        if expected_hash != user['password_hash']:
            # Increment failed login attempts
            if username in failed_logins:
                attempts, _ = failed_logins[username]
                failed_logins[username] = (
                attempts + 1, current_time + LOCKOUT_TIME if attempts + 1 >= MAX_FAILED_LOGIN_ATTEMPTS else 0)
            else:
                failed_logins[username] = (1, 0)

            return {"status": "error", "message": "Invalid credentials"}

        # Verify OTP if provided
        if otp_code:
            otp_secret = user['otp_secret']
            totp = pyotp.TOTP(otp_secret,interval=300)
            if not totp.verify(otp_code):
                # Increment failed login attempts
                if username in failed_logins:
                    attempts, _ = failed_logins[username]
                    failed_logins[username] = (
                    attempts + 1, current_time + LOCKOUT_TIME if attempts + 1 >= MAX_FAILED_LOGIN_ATTEMPTS else 0)
                else:
                    failed_logins[username] = (1, 0)

                return {"status": "error", "message": "Invalid OTP code"}

        # Create a new session
        session_id = create_session(user['user_id'], ip_address)

        # Update last login time
        cursor.execute("""
            UPDATE users 
            SET last_login = ? 
            WHERE user_id = ?
        """, (datetime.datetime.now(), user['user_id']))

        conn.commit()

        # Log the login
        log_action(user['user_id'], "user_login", f"User logged in: {username}", ip_address)

        # Reset failed login attempts
        if username in failed_logins:
            failed_logins.pop(username)

        return {
            "status": "success",
            "message": "Login successful",
            "session_id": session_id,
            "user_id": user['user_id'],
            "is_admin": user['is_admin']
        }
    except Exception as e:
        logger.error(f"Login error: {e}")
        return {"status": "error", "message": "Login failed"}
    finally:
        close_connection(conn)


def handle_reset_password(request, ip_address=None):
    """
    Handle password reset request
    """
    username= validate_input(request.get("username"))

    if not username:
        return {"status": "error", "message": "Invalid or expired session"}

    old_password_hash = request.get("old_password_hash")
    new_password_hash = request.get("new_password_hash")

    if not old_password_hash or not new_password_hash:
        return {"status": "error", "message": "Missing password data"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get current password information
        cursor.execute("""
            SELECT password_hash, salt 
            FROM users 
            WHERE username = ?
        """, (username,))

        user = cursor.fetchone()
        if not user:
            return {"status": "error", "message": "User not found"}

        # Verify old password
        expected_hash = hashlib.sha256((old_password_hash + user['salt']).encode()).hexdigest()
        if expected_hash != user['password_hash']:
            return {"status": "error", "message": "Current password is incorrect"}

        # Generate new salt and hash for the new password
        new_salt = secrets.token_hex(16)
        final_new_hash = hashlib.sha256((new_password_hash + new_salt).encode()).hexdigest()

        # Update password
        cursor.execute("""
            UPDATE users 
            SET password_hash = ?, salt = ? 
            WHERE username = ?
        """, (final_new_hash, new_salt, username))

        conn.commit()

        # Log the password reset
        log_action(username, "password_reset", "Password was reset", ip_address)

        return {"status": "success", "message": "Password reset successful"}
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        return {"status": "error", "message": "Password reset failed"}
    finally:
        close_connection(conn)


def handle_upload_file(request, ip_address=None):
    """
    Handle file upload request with simplified interface
    """
    username = validate_input(request.get("username"))
    
    if not username:
        return {"status": "error", "message": "Invalid username"}
        
    # Get user_id from username
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            return {"status": "error", "message": "User not found"}
        
        user_id = user['user_id']
        
        # Get filename and data from request
        filename = validate_input(request.get("filename"), r'^[a-zA-Z0-9_\-. ]{1,255}$')
        encrypted_data_str = request.get("data")  # This contains all the encrypted package
        
        if not filename or not encrypted_data_str:
            return {"status": "error", "message": "Missing filename or file data"}
            
        # Decode the encrypted package
        try:
            encrypted_package_json = base64.b64decode(encrypted_data_str).decode()
            encrypted_package = json.loads(encrypted_package_json)
            
            # Extract data from the package
            ciphertext = base64.b64decode(encrypted_package["ciphertext"])
            nonce = encrypted_package["nonce"]  # Keep as base64 for storage
            tag = encrypted_package["tag"]      # Keep as base64 for storage
            metadata = encrypted_package.get("metadata", {})
            
            original_filename = metadata.get("original_filename", filename)
            file_size = len(ciphertext)
            
            # Generate a unique filename to prevent overwriting
            safe_filename = f"{int(time.time())}_{filename}"
            file_path = os.path.join("files", safe_filename)
            
            # Ensure the files directory exists
            os.makedirs("files", exist_ok=True)
            
            # Save the encrypted file
            with open(file_path, 'wb') as f:
                f.write(ciphertext)
                
            # Create file record
            cursor.execute("""
                INSERT INTO files 
                (filename, original_filename, owner_id, upload_date, last_modified, file_size, file_path, is_deleted) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                safe_filename,
                original_filename,
                user_id,
                datetime.datetime.now(),
                datetime.datetime.now(),
                file_size,
                file_path,
                0
            ))
            
            file_id = cursor.lastrowid
            
            # Store encryption information
            cursor.execute("""
                INSERT INTO file_keys 
                (file_id, key_encrypted, iv) 
                VALUES (?, ?, ?)
            """, (file_id, tag, nonce))  # Using tag as key_encrypted and nonce as iv
            
            conn.commit()
            
            # Log the upload
            log_action(user_id, "file_upload", f"Uploaded file: {original_filename}", ip_address)
            
            return {
                "status": "success",
                "message": "File uploaded successfully",
                "file_id": file_id
            }
            
        except json.JSONDecodeError:
            return {"status": "error", "message": "Invalid encrypted package format"}
        except KeyError as e:
            return {"status": "error", "message": f"Missing required encryption data: {str(e)}"}
            
    except Exception as e:
        logger.error(f"File upload error: {e}")
        return {"status": "error", "message": "File upload failed"}
    finally:
        close_connection(conn)
    


def handle_download_file(request, ip_address=None):
    """
    Handle file download request
    """
    session_id = request.get("session_id")
    user_id = validate_session(session_id)
    username = validate_input(request.get("username"))

    if not username:
        return {"status": "error", "message": "Invalid or expired session"}

    file_id = request.get("file_id")

    if not file_id:
        return {"status": "error", "message": "Missing file ID"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user owns the file or has permission
        cursor.execute("""
            SELECT f.file_id, f.filename, f.original_filename, f.file_path, f.owner_id
            FROM files f
            WHERE f.file_id = ? AND f.is_deleted = 0 AND (f.owner_id = ? OR EXISTS (
                SELECT 1 FROM file_permissions p WHERE p.file_id = f.file_id AND p.user_id = ?
            ))
        """, (file_id, user_id, user_id))

        file = cursor.fetchone()
        if not file:
            return {"status": "error", "message": "File not found or permission denied"}

        # Get encryption key and IV
        cursor.execute("""
            SELECT key_encrypted, iv
            FROM file_keys
            WHERE file_id = ?
        """, (file_id,))

        key_data = cursor.fetchone()
        if not key_data:
            return {"status": "error", "message": "Encryption key not found"}

        # Read the encrypted file
        with open(file['file_path'], 'rb') as f:
            encrypted_data = f.read()

        # Log the download
        log_action(user_id, "file_download", f"Downloaded file: {file['original_filename']}", ip_address)

        # Return encrypted data and key information
        return {
            "status": "success",
            "message": "File download successful",
            "file_id": file['file_id'],
            "filename": file['original_filename'],
            "encrypted_key": key_data['key_encrypted'],
            "iv": key_data['iv'],
            "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8')
        }
    except Exception as e:
        logger.error(f"File download error: {e}")
        return {"status": "error", "message": "File download failed"}
    finally:
        close_connection(conn)


def handle_delete_file(request, ip_address=None):
    """
    Handle file deletion request
    """
    session_id = request.get("session_id")
    user_id = validate_session(session_id)

    if not user_id:
        return {"status": "error", "message": "Invalid or expired session"}

    file_id = request.get("file_id")

    if not file_id:
        return {"status": "error", "message": "Missing file ID"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user owns the file
        cursor.execute("""
            SELECT file_id, original_filename, file_path
            FROM files
            WHERE file_id = ? AND owner_id = ? AND is_deleted = 0
        """, (file_id, user_id))

        file = cursor.fetchone()
        if not file:
            return {"status": "error", "message": "File not found or you don't have permission to delete"}

        # Soft delete - mark as deleted
        cursor.execute("""
            UPDATE files
            SET is_deleted = 1
            WHERE file_id = ?
        """, (file_id,))

        conn.commit()

        # Log the deletion
        log_action(user_id, "file_delete", f"Deleted file: {file['original_filename']}", ip_address)

        return {"status": "success", "message": "File deleted successfully"}
    except Exception as e:
        logger.error(f"File deletion error: {e}")
        return {"status": "error", "message": "File deletion failed"}
    finally:
        close_connection(conn)


def handle_share_file(request, ip_address=None):
    """
    Handle file sharing request
    """
    session_id = request.get("session_id")
    user_id = validate_session(session_id)

    if not user_id:
        return {"status": "error", "message": "Invalid or expired session"}

    file_id = request.get("file_id")
    share_with_username = validate_input(request.get("share_with_username"))

    if not file_id or not share_with_username:
        return {"status": "error", "message": "Missing required information"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user owns the file
        cursor.execute("""
            SELECT file_id, original_filename
            FROM files
            WHERE file_id = ? AND owner_id = ? AND is_deleted = 0
        """, (file_id, user_id))

        file = cursor.fetchone()
        if not file:
            return {"status": "error", "message": "File not found or you don't have permission to share"}

        # Get the user ID of the user to share with
        cursor.execute("""
            SELECT user_id, username
            FROM users
            WHERE username = ?
        """, (share_with_username,))

        share_user = cursor.fetchone()
        if not share_user:
            return {"status": "error", "message": "User to share with not found"}

        # Check if already shared
        cursor.execute("""
            SELECT permission_id
            FROM file_permissions
            WHERE file_id = ? AND user_id = ?
        """, (file_id, share_user['user_id']))

        if cursor.fetchone():
            return {"status": "error", "message": "File already shared with this user"}

        # Create permission record
        cursor.execute("""
            INSERT INTO file_permissions
            (file_id, user_id, granted_by, granted_date)
            VALUES (?, ?, ?, ?)
        """, (file_id, share_user['user_id'], user_id, datetime.datetime.now()))

        conn.commit()

        # Log the sharing
        log_action(
            user_id,
            "file_share",
            f"Shared file: {file['original_filename']} with user: {share_user['username']}",
            ip_address
        )

        return {"status": "success", "message": "File shared successfully"}
    except Exception as e:
        logger.error(f"File sharing error: {e}")
        return {"status": "error", "message": "File sharing failed"}
    finally:
        close_connection(conn)


def handle_list_files(request, ip_address=None):
    """
    Handle request to list user's files
    """
    session_id = request.get("session_id")
    user_id = validate_session(session_id)

    if not user_id:
        return {"status": "error", "message": "Invalid or expired session"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get own files
        cursor.execute("""
            SELECT file_id, original_filename, upload_date, last_modified, file_size, 'owner' as type
            FROM files
            WHERE owner_id = ? AND is_deleted = 0
            ORDER BY last_modified DESC
        """, (user_id,))

        own_files = [dict(row) for row in cursor.fetchall()]

        # Get shared files
        cursor.execute("""
            SELECT f.file_id, f.original_filename, f.upload_date, f.last_modified, f.file_size, 
                   'shared' as type, u.username as owner
            FROM files f
            JOIN file_permissions p ON f.file_id = p.file_id
            JOIN users u ON f.owner_id = u.user_id
            WHERE p.user_id = ? AND f.is_deleted = 0
            ORDER BY p.granted_date DESC
        """, (user_id,))

        shared_files = [dict(row) for row in cursor.fetchall()]

        # Log the listing
        log_action(user_id, "list_files", "Listed files", ip_address)

        return {
            "status": "success",
            "message": "Files retrieved successfully",
            "own_files": own_files,
            "shared_files": shared_files
        }
    except Exception as e:
        logger.error(f"List files error: {e}")
        return {"status": "error", "message": "Failed to retrieve files"}
    finally:
        close_connection(conn)


def handle_partial_update(request, ip_address=None):
    """
    Handle partial file update (efficient update without reuploading entire file)
    This is one of the EXTENDED functionalities
    """
    session_id = request.get("session_id")
    user_id = validate_session(session_id)

    if not user_id:
        return {"status": "error", "message": "Invalid or expired session"}

    file_id = request.get("file_id")
    start_position = request.get("start_position")
    encrypted_chunk_base64 = request.get("encrypted_chunk")

    if not file_id or start_position is None or not encrypted_chunk_base64:
        return {"status": "error", "message": "Missing required information"}

    try:
        encrypted_chunk = base64.b64decode(encrypted_chunk_base64)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user owns the file
        cursor.execute("""
            SELECT file_id, file_path, original_filename, file_size
            FROM files
            WHERE file_id = ? AND owner_id = ? AND is_deleted = 0
        """, (file_id, user_id))

        file = cursor.fetchone()
        if not file:
            return {"status": "error", "message": "File not found or you don't have permission to update"}

        # Update the file with the new chunk
        with open(file['file_path'], 'r+b') as f:
            f.seek(start_position)
            f.write(encrypted_chunk)

        # Calculate new file size
        new_size = max(file['file_size'], start_position + len(encrypted_chunk))

        # Update file metadata
        cursor.execute("""
            UPDATE files
            SET last_modified = ?, file_size = ?
            WHERE file_id = ?
        """, (datetime.datetime.now(), new_size, file_id))

        conn.commit()

        # Log the partial update
        log_action(
            user_id,
            "file_partial_update",
            f"Partially updated file: {file['original_filename']}",
            ip_address
        )

        return {
            "status": "success",
            "message": "File partially updated successfully",
            "new_size": new_size
        }
    except Exception as e:
        logger.error(f"Partial update error: {e}")
        return {"status": "error", "message": "Partial update failed"}
    finally:
        close_connection(conn)


def handle_view_logs(request, ip_address=None):
    """
    Handle admin request to view audit logs
    """
    session_id = request.get("session_id")
    user_id = validate_session(session_id)

    if not user_id:
        return {"status": "error", "message": "Invalid or expired session"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user is admin
        cursor.execute("""
            SELECT is_admin
            FROM users
            WHERE user_id = ?
        """, (user_id,))

        user = cursor.fetchone()
        if not user or not user['is_admin']:
            return {"status": "error", "message": "Admin privileges required"}

        # Get logs with limit and pagination
        limit = request.get("limit", 100)
        offset = request.get("offset", 0)

        cursor.execute("""
            SELECT l.log_id, l.user_id, u.username, l.action_type, l.action_details, 
                   l.ip_address, l.timestamp, l.signature
            FROM audit_logs l
            LEFT JOIN users u ON l.user_id = u.user_id
            ORDER BY l.timestamp DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))

        logs = [dict(row) for row in cursor.fetchall()]

        # Log the viewing of logs
        log_action(user_id, "view_logs", f"Viewed audit logs (limit: {limit}, offset: {offset})", ip_address)

        return {
            "status": "success",
            "message": "Logs retrieved successfully",
            "logs": logs
        }
    except Exception as e:
        logger.error(f"View logs error: {e}")
        return {"status": "error", "message": "Failed to retrieve logs"}
    finally:
        close_connection(conn)


def handle_logout(request, ip_address=None):
    """
    Handle user logout request
    """
    session_id = request.get("session_id")
    user_id = validate_session(session_id)

    if not user_id:
        return {"status": "error", "message": "Invalid or expired session"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Delete the session
        cursor.execute("""
            DELETE FROM sessions
            WHERE session_id = ?
        """, (session_id,))

        conn.commit()

        # Log the logout
        log_action(user_id, "user_logout", "User logged out", ip_address)

        return {"status": "success", "message": "Logout successful"}
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return {"status": "error", "message": "Logout failed"}
    finally:
        close_connection(conn)


def handle_client(client_socket, addr):
    """
    Handle a client connection
    """
    ip_address = addr[0]

    # Check rate limit
    if not check_rate_limit(ip_address):
        response = {"status": "error", "message": "Rate limit exceeded. Try again later."}
        client_socket.send(json.dumps(response).encode())
        client_socket.close()
        return

    try:
        # Receive data
        data = b""
        while True:
            chunk = client_socket.recv(MAX_BUFFER_SIZE)
            if not chunk:
                break
            data += chunk
            if len(chunk) < MAX_BUFFER_SIZE:
                break

        if not data:
            return

        # Parse the request
        request = json.loads(data.decode())

        # Get the action
        action = request.get("action")
        if not action:
            response = {"status": "error", "message": "Missing action parameter"}
            client_socket.send(json.dumps(response).encode())
            return

        # Handle different actions
        if action == "register":
            response = handle_register(request, ip_address)
        elif action == "login":
            response = handle_login(request, ip_address)
        elif action == "reset_password":
            response = handle_reset_password(request, ip_address)
        elif action == "upload_file":
            response = handle_upload_file(request, ip_address)
        elif action == "download_file":
            response = handle_download_file(request, ip_address)
        elif action == "delete_file":
            response = handle_delete_file(request, ip_address)
        elif action == "share_file":
            response = handle_share_file(request, ip_address)
        elif action == "list_files":
            response = handle_list_files(request, ip_address)
        elif action == "partial_update":
            response = handle_partial_update(request, ip_address)
        elif action == "view_logs":
            response = handle_view_logs(request, ip_address)
        elif action == "logout":
            response = handle_logout(request, ip_address)
        else:
            response = {"status": "error", "message": "Unknown action"}

        # Send the response
        client_socket.send(json.dumps(response).encode())
    except json.JSONDecodeError:
        response = {"status": "error", "message": "Invalid JSON request"}
        client_socket.send(json.dumps(response).encode())
    except Exception as e:
        logger.error(f"Error handling client request: {e}")
        response = {"status": "error", "message": "Server error"}
        try:
            client_socket.send(json.dumps(response).encode())
        except:
            pass
    finally:
        client_socket.close()


def main():
    """
    Main server function
    """
    # Check if database exists, if not initialize it
    if not os.path.exists(DB_PATH):
        logger.info("Database not found, initializing...")
        try:
            from Database import initialize_database
            initialize_database()
        except ImportError:
            logger.error("Could not import database module")
            return

    # Create files directory if it doesn't exist
    os.makedirs("files", exist_ok=True)

    # Start the server
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(MAX_CONNECTIONS)

        logger.info(f"Server started on {HOST}:{PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            logger.info(f"New connection from {addr}")
            thread_pool.submit(handle_client, client_socket, addr)
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        if 'server_socket' in locals():
            server_socket.close()
        thread_pool.shutdown()


if __name__ == "__main__":
    main()
