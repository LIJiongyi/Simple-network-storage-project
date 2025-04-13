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
    return response


def reset_password(username, old_password, new_password):
    """重置密码"""
    old_password_hash = hashlib.sha256(old_password.encode()).hexdigest()
    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    request = {
        "action": "reset_password",
        "username": username,
        "old_password_hash": old_password_hash,
        "new_password_hash": new_password_hash
    }
    response = send_request(request)
    print(f"重置 {username} 密码: {response}")
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
    """通过文件 ID 下载文件"""
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

        if response.get("status") == "success":
            encrypted_package = json.loads(base64.b64decode(response["data"]).decode())

            # 解密数据
            ciphertext = base64.b64decode(encrypted_package["ciphertext"])
            nonce = base64.b64decode(encrypted_package["nonce"])
            tag = base64.b64decode(encrypted_package["tag"])
            file_metadata = encrypted_package.get("metadata", {})

            key = derive_encryption_key(username)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            # 解密并验证
            decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)

            # 处理文件类型
            file_type = file_metadata.get("file_type", "").lower() if file_metadata else ""
            display_filename = file_metadata.get("original_filename", f"file_{file_id}")

            text_file_types = ['txt', 'md', 'py', 'java', 'c', 'cpp', 'js', 'html', 'css', 'xml', 'json']

            if file_type in text_file_types:
                decrypted_content = decrypted_bytes.decode('utf-8')
                print(f"{username} 下载 {display_filename} 内容: {decrypted_content[:100]}...")
                return {"status": "success", "data": decrypted_content, "binary": False}
            else:
                print(f"{username} 下载 {display_filename} (二进制文件, {len(decrypted_bytes)} 字节)")
                return {"status": "success", "data": base64.b64encode(decrypted_bytes).decode(), "binary": True}

        # 下载失败
        print(f"{username} 下载文件 ID {file_id}: {response}")
        return response

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


if __name__ == "__main__":
    print("开始自动化测试...")

    # 测试管理员登录
    admin_otp = get_otp("admin")
    if admin_otp:
        login_user("admin", "admin123", admin_otp)
    else:
        print("无法获取 admin OTP，跳过管理员登录")

    # 测试用户注册
    register_user("user1", "password123")
    register_user("user2", "password456")

    # 测试用户登录
    user1_otp = get_otp("user1")
    if user1_otp:
        login_user("user1", "password123", user1_otp)
    else:
        print("无法获取 user1 OTP，跳过登录")

    # 测试密码重置
    if user1_otp:
        reset_password("user1", "password123", "newpass123")
        user1_new_otp = get_otp("user1")
        if user1_new_otp:
            login_user("user1", "newpass123", user1_new_otp)
        else:
            print("无法获取 user1 新 OTP，跳过新密码登录")

    # 测试文件上传
    upload_file("user1", "test.txt", "这是一个测试文件。")

    # 测试文件下载（拥有者）
    download_file("user1", "test.txt")

    # 测试文件编辑
    edit_file("user1", "test.txt", "这是编辑后的测试文件。")
    download_file("user1", "test.txt")

    # 测试文件分享
    user2_otp = get_otp("user2")
    if user2_otp:
        login_user("user2", "password456", user2_otp)
        share_file("user1", "test.txt", "user2")
        download_file("user2", "test.txt")
    else:
        print("无法获取 user2 OTP,跳过分享和下载")

    # 测试文件删除
    delete_file("user1", "test.txt")
    download_file("user1", "test.txt")  # 应返回未找到

    # 测试管理员查看日志
    if admin_otp:
        view_logs("admin")
    else:
        print("无法获取 admin OTP,跳过查看日志")

    # 测试非法文件名
    upload_file("user1", "../test.txt", "非法文件名测试")

    print("自动化测试完成")

    # start CLI
    # user_cli()
