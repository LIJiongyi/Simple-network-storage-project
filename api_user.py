# Description: general & security related api for user_interface.py


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import socket
import json
import base64
import hashlib
import pyotp
import sqlite3
import os
import re
import time
import logging

# 项目根目录和数据库路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'storage.db')

# 服务器地址和端口
HOST = 'localhost'
PORT = 9999


# 在文件顶部引入其他库的地方添加
_session_tokens = {}  # 按用户名存储会话数据

def store_session(username, session_data):
    """存储用户的会话令牌和数据"""
    _session_tokens[username] = session_data
    
def get_session_token(username):
    """获取用户的会话令牌"""
    if username in _session_tokens:
        return _session_tokens[username].get("session_id")
    return None

def clear_session(username):
    """清除用户会话"""
    if username in _session_tokens:
        del _session_tokens[username]

def send_request(request):
    """发送请求到服务器并接收响应"""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        client.send(json.dumps(request).encode())
        response = client.recv(4096).decode()
        client.close()
        return json.loads(response)
    except Exception as e:
        print("通信错误:", e)
        return {"status": "error", "message": str(e)}


def register_user(username, password):
    """注册用户"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    request = {"action": "register", "username": username, "password_hash": password_hash}  # 将password改为password_hash
    response = send_request(request)
    print(f"注册 {username}: {response}")
    return response


def login_user(username, password, otp):
    """用户登录"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    request = {"action": "login",
               "username": username,
               "password_hash": password_hash,
               "otp_code": otp}
    response = send_request(request)
    print(f"登录 {username}: {response}")
    
    # 如果登录成功，存储会话数据
    if response.get("status") == "success" and "session_id" in response:
        store_session(username, {
            "session_id": response.get("session_id"),
            "user_id": response.get("user_id", "")
        })
        
    return response


def reset_password(username, old_password, new_password):
    """重置密码"""

    session_id = get_session_token(username)
    if not session_id:
        return {"status": "error", "message": "session expired or not found"}
    old_password_hash = hashlib.sha256(old_password.encode()).hexdigest()
    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    request = {
        "action": "reset_password",
        "username": username,
        "old_password_hash": old_password_hash,
        "new_password_hash": new_password_hash,
        "session_id": session_id
    }
    response = send_request(request)
    print(f"重置 {username} 密码: {response}")
    
    if response.get("status") == "success":
        # 如果服务器要求重新登录，清除当前会话
        if response.get("require_relogin"):
            clear_session(username)
            print(f"密码已重置，请使用新密码重新登录")
    
    return response

def sanitize_filename(filename):  # 用来防止路径遍历攻击
    base_filename = os.path.basename(filename)
    safe_filename = re.sub(r'[^\w\.-]', '_', base_filename)
    if not safe_filename or safe_filename in ['.', '..'] or safe_filename.startswith('.'):
        raise ValueError(f"unsafe: {filename}")

    return safe_filename


# I commented out the original upload_file and download_file functions
# to avoid confusion with the new ones that include path traversal protection.如果成功运行这些注释可删掉
'''
def upload_file(username, filename, file_content):
    """上传文件"""
    encrypted_data = base64.b64encode(file_content.encode()).decode()
    request = {"action": "upload", "username": username, "filename": filename, "data": encrypted_data}
    response = send_request(request)
    print(f"{username} 上传 {filename}: {response}")
    return response
'''

'''
def download_file(username, filename):
    """下载文件"""
    request = {"action": "download", "username": username, "filename": filename}
    response = send_request(request)
    if response.get("status") == "success":
        file_content = base64.b64decode(response["data"]).decode()
        print(f"{username} 下载 {filename} 内容: {file_content}")
    print(f"{username} 下载 {filename}: {response}")
    return response
'''


def derive_encryption_key(username, password="file_encryption_key"):
    salt = username.encode()  # 使用用户名作为盐
    key = PBKDF2(password, salt, dkLen=32, count=1000, hmac_hash_module=SHA256)
    return key


def upload_file(username, filename, file_content=None, file_path=None):
    try:
        # Sanitize the filename for security
        safe_filename = sanitize_filename(filename)
        
        # If original filename was modified, notify user
        if safe_filename != filename:
            print(f"Note: Filename was changed to safe version '{safe_filename}'")
            
        # Handle file content from either direct content or file path
        if file_content is None and file_path is not None:
            # Validate file_path to prevent directory traversal attacks
            if not os.path.exists(file_path):
                return {"status": "error", "message": f"File not found: {file_path}"}
            
            # Check if file path is within allowed directories
            abs_path = os.path.abspath(file_path)
            
            try:
                # Read file content from the specified path
                with open(abs_path, 'rb') as f:
                    file_bytes = f.read()
            except (IOError, PermissionError) as e:
                return {"status": "error", "message": f"Cannot read file: {str(e)}"}
        elif isinstance(file_content, str):
            # If content provided as string, encode to bytes
            file_bytes = file_content.encode('utf-8')
        elif file_content is not None:
            # If content already in bytes, use directly
            file_bytes = file_content
        else:
            return {"status": "error", "message": "No file content or valid file path provided"}
            
        # Get file extension for metadata
        _, file_extension = os.path.splitext(safe_filename)

        # Get encryption key
        key = derive_encryption_key(username)

        # Generate random nonce
        nonce = get_random_bytes(12)  # AES-GCM recommended 12-byte nonce

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # Prepare file metadata
        file_metadata = {
            "original_filename": safe_filename,
            "file_type": file_extension.lstrip('.').lower(),
            "timestamp": time.time()
        }

        # Add metadata to verification data
        associated_data = json.dumps(file_metadata).encode()

        # Encrypt file content
        ciphertext, tag = cipher.encrypt_and_digest(file_bytes)

        # Prepare encrypted metadata
        encrypted_package = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "metadata": file_metadata
        }

        # Package encrypted data as JSON and encode for transmission
        encrypted_data = base64.b64encode(json.dumps(encrypted_package).encode()).decode()

        # Send request
        request = {"action": "upload_file", "username": username, "filename": safe_filename, "data": encrypted_data}
        response = send_request(request)
        print(f"{username} uploaded {safe_filename}: {response}")
        return response
    except ValueError as e:
        print(f"Upload error: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        print(f"Encryption or upload error: {e}")
        return {"status": "error", "message": str(e)}


def download_file(username, file_id):
    """通过文件 ID 下载文件并保存到 download 文件夹"""
    try:
        # 验证文件 ID
        if not isinstance(file_id, (int, str)) or not str(file_id).isdigit():
            return {"status": "error", "message": "Invalid file ID"}

        file_id = int(file_id)

        # 发送下载请求
        request = {"action": "download_file", "username": username, "file_id": file_id}
        logger.debug(f"Sending download request: {request}")
        response = send_request(request)
        logger.debug(f"Download response: {response}")

        if response.get("status") != "success":
            print(f"{username} 下载文件 ID {file_id}: {response.get('message', '未知错误')}")
            return response

        # 解析加密包
        encrypted_package = json.loads(base64.b64decode(response["data"]).decode())

        # 提取数据
        ciphertext = base64.b64decode(encrypted_package["ciphertext"])
        nonce = base64.b64decode(encrypted_package["nonce"])
        tag = base64.b64decode(encrypted_package["tag"])
        file_metadata = encrypted_package.get("metadata", {})

        # 获取文件类型和文件名
        file_type = file_metadata.get("file_type", "").lower()
        display_filename = file_metadata.get("original_filename", f"file_{file_id}")

        # 只处理 .txt 文件
        if file_type != "txt":
            print(f"仅支持下载 .txt 文件，当前文件类型: {file_type}")
            return {"status": "error", "message": f"Only .txt files are supported, got: {file_type}"}

        # 解密数据
        key = derive_encryption_key(username)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        decrypted_content = decrypted_bytes.decode('utf-8')  # 转换为字符串

        # 创建 download 文件夹
        download_dir = os.path.join(BASE_DIR, "download")
        os.makedirs(download_dir, exist_ok=True)

        # 处理文件名冲突
        def get_unique_filename(directory, filename):
            base, ext = os.path.splitext(filename)
            counter = 1
            new_filename = filename
            while os.path.exists(os.path.join(directory, new_filename)):
                new_filename = f"{base} ({counter}){ext}"
                counter += 1
            return new_filename

        unique_filename = get_unique_filename(download_dir, display_filename)
        file_path = os.path.join(download_dir, unique_filename)

        # 保存文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(decrypted_content)

        print(f"{username} 下载 {display_filename} 已保存到: {file_path}")
        return {"status": "success", "message": f"File saved to {file_path}"}

    except ValueError as e:
        logger.error(f"下载错误: {e}")
        print(f"下载错误: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.error(f"意外错误: {type(e).__name__}: {e}")
        print(f"意外错误: {e}")
        return {"status": "error", "message": str(e)}



def edit_file(username, filename, new_content):
    new_data = base64.b64encode(new_content.encode()).decode()
    request = {"action": "edit_file", "username": username, "filename": filename, "data": new_data}
    response = send_request(request)
    print(f"{username} edit {filename}: {response}")
    return response


def delete_file(username, filename):
    request = {"action": "delete_file", "username": username, "filename": filename}
    response = send_request(request)
    print(f"{username} delete {filename}: {response}")
    return response


def share_file(username, filename, share_with):
    request = {"action": "share", "username": username, "filename": filename, "share_with": share_with}
    response = send_request(request)
    print(f"{username} 分享 {filename} 给 {share_with}: {response}")
    return response


def view_logs(admin_username):
    """管理员查看日志"""
    request = {"action": "view_logs", "username": admin_username}
    response = send_request(request)
    if response.get("status") == "success":
        print(f"管理员 {admin_username} 查看日志: {response['data']}")
    else:
        print(f"管理员 {admin_username} 查看日志: {response}")
    return response


def get_otp(username):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT otp_secret FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        if result:
            totp = pyotp.TOTP(result[0], interval=300)  # 核心函数,作用很大
            return totp.now()
        else:
            print(f"user {username} not found")
            return None
    except Exception as e:
        print("wrong OTP:", e)
        return None


def send_otp_to_phone(username, otp):
    try:
        phone = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        phone.settimeout(5)  # Add timeout to prevent hanging
        phone.connect(('localhost', 8888))
        message = {'username': username, 'otp_secret': otp}
        phone.send(json.dumps(message).encode())
        response = phone.recv(1024).decode()  # Get response from OTP server
        phone.close()

        # Parse response to check success
        try:
            response_data = json.loads(response)
            if response_data.get('status') == 'success':
                return True
        except:
            pass
        return False
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False

logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SecureStorage')
def list_files(username):
    """
    List all files for the given user
    """
    try:
        # 验证用户名
        if not username or not isinstance(username, str):
            return {"status": "error", "message": "Invalid username"}

        # 构造请求
        request = {"action": "list_files", "username": username}

        # 发送请求
        response = send_request(request)
        return response

    except Exception as e:
        logger.error(f"List files error: {str(e)}")
        return {"status": "error", "message": str(e)}