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
    request = {"action": "register", "username": username, "password": password_hash}
    response = send_request(request)
    print(f"注册 {username}: {response}")
    return response

def login_user(username, password, otp):
    """用户登录"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    request = {"action": "login", "username": username, "password": password_hash, "otp": otp}
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
        "old_password": old_password_hash,
        "new_password": new_password_hash
    }
    response = send_request(request)
    print(f"重置 {username} 密码: {response}")
    return response


def sanitize_filename(filename): # 用来防止路径遍历攻击
    base_filename = os.path.basename(filename)
    safe_filename = re.sub(r'[^\w\.-]', '_', base_filename)
    if not safe_filename or safe_filename in ['.', '..'] or safe_filename.startswith('.'):
        raise ValueError(f"不安全的文件名: {filename}")
        
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
    """从用户名和密码派生加密密钥"""
    salt = username.encode()  # 使用用户名作为盐
    key = PBKDF2(password, salt, dkLen=32, count=1000, hmac_hash_module=SHA256)
    return key

def upload_file(username, filename, file_content):
    try:
        # 验证和清理文件名
        safe_filename = sanitize_filename(filename)
        
        # 如果原始文件名被修改，通知用户
        if safe_filename != filename:
            print(f"注意：文件名已更改为安全版本 '{safe_filename}'")
        
        # 获取加密密钥
        key = derive_encryption_key(username)
        
        # 生成随机nonce
        nonce = get_random_bytes(12)  # AES-GCM推荐12字节nonce
        
        # 创建AES-GCM加密器
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # 加密文件内容
        ciphertext, tag = cipher.encrypt_and_digest(file_content.encode())
        
        # 准备加密元数据
        encrypted_package = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode()
        }
        
        # 将加密数据打包为JSON字符串，并进行base64编码以便传输
        encrypted_data = base64.b64encode(json.dumps(encrypted_package).encode()).decode()
        
        # 发送请求
        request = {"action": "upload", "username": username, "filename": safe_filename, "data": encrypted_data}
        response = send_request(request)
        print(f"{username} 上传 {safe_filename}: {response}")
        return response
    except ValueError as e:
        print(f"上传错误: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        print(f"加密或上传错误: {e}")
        return {"status": "error", "message": str(e)}

def download_file(username, filename):
    try:
        # 验证和清理文件名
        safe_filename = sanitize_filename(filename)
        
        # 如果原始文件名被修改，通知用户
        if safe_filename != filename:
            print(f"注意：文件名已更改为安全版本 '{safe_filename}'")
        
        # 发送下载请求
        request = {"action": "download", "username": username, "filename": safe_filename}
        response = send_request(request)
        
        if response.get("status") == "success":
            # 解析加密数据包
            encrypted_package = json.loads(base64.b64decode(response["data"]).decode())
            
            # 提取加密组件
            ciphertext = base64.b64decode(encrypted_package["ciphertext"])
            nonce = base64.b64decode(encrypted_package["nonce"])
            tag = base64.b64decode(encrypted_package["tag"])
            
            # 获取解密密钥
            key = derive_encryption_key(username)
            
            # 创建解密器
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # 解密文件内容
            try:
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                decrypted_content = plaintext.decode()
                print(f"{username} 下载 {safe_filename} 内容: {decrypted_content}")
                return {"status": "success", "data": decrypted_content}
            except ValueError as e:
                print(f"文件验证失败: {e}")
                return {"status": "error", "message": "文件可能被篡改"}
        
        # 处理下载失败
        print(f"{username} 下载 {safe_filename}: {response}")
        return response
    except ValueError as e:
        print(f"下载错误: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        print(f"解密或下载错误: {e}")
        return {"status": "error", "message": str(e)}

def edit_file(username, filename, new_content):
    """编辑文件"""
    new_data = base64.b64encode(new_content.encode()).decode()
    request = {"action": "edit_file", "username": username, "filename": filename, "data": new_data}
    response = send_request(request)
    print(f"{username} 编辑 {filename}: {response}")
    return response

def delete_file(username, filename):
    """删除文件"""
    request = {"action": "delete_file", "username": username, "filename": filename}
    response = send_request(request)
    print(f"{username} 删除 {filename}: {response}")
    return response

def share_file(username, filename, share_with):
    """分享文件"""
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
    """get OTP"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT otp_secret FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        if result:
            totp = pyotp.TOTP(result[0], interval=300) # 核心函数,作用很大
            return totp.now()
        else:
            print(f"用户 {username} 未找到")
            return None
    except Exception as e:
        print("获取 OTP 错误:", e)
        return None
    
def send_otp_to_phone(username, otp):
    try:
        phone = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # ipv4
        phone.connect(('localhost', 8888))  # port 8888
        message = {'username': username, 'otp': otp}
        phone.send(json.dumps(message).encode())
        # ...处理响应...
    except Exception as e:
        print(f"发送OTP到手机错误: {e}")
        return False

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
    user_cli()