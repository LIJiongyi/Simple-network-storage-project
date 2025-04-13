import socket
import json
import base64
import os
import re
import time
import logging
import sqlite3
import hashlib
import pyotp
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# 项目根目录和数据库路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'storage.db')

# 服务器配置
HOST = 'localhost'
PORT = 9999
MAX_BUFFER_SIZE = 4096

# 设置日志
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SecureStorage')

def clear_screen():
    """清屏，兼容 Windows 和 Unix"""
    os.system("cls" if os.name == "nt" else "clear")

def input_with_validation(prompt: str, allow_empty: bool = False) -> str:
    """获取用户输入并验证"""
    while True:
        value = input(prompt).strip()
        if value or allow_empty:
            return value
        print("输入不能为空，请重试。")

def send_request(request):
    """发送请求到服务器并接收响应"""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        client.send(json.dumps(request).encode())
        response = b""
        while True:
            chunk = client.recv(MAX_BUFFER_SIZE)
            if not chunk:
                break
            response += chunk
            if len(chunk) < MAX_BUFFER_SIZE:
                break
        client.close()
        return json.loads(response.decode())
    except Exception as e:
        print(f"通信错误: {e}")
        return {"status": "error", "message": str(e)}

def derive_encryption_key(username, password="file_encryption_key"):
    """派生加密密钥"""
    salt = username.encode()
    key = PBKDF2(password, salt, dkLen=32, count=1000, hmac_hash_module=SHA256)
    return key

def register_user(username, password):
    """注册用户"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    request = {"action": "register", "username": username, "password_hash": password_hash}
    response = send_request(request)
    print(f"注册 {username}: {response.get('message', '无消息')}")
    return response

def get_otp(username):
    """获取 OTP"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT otp_secret FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        if result:
            totp = pyotp.TOTP(result[0], interval=300)
            return totp.now()
        else:
            print(f"用户 {username} 未找到")
            return None
    except Exception as e:
        print(f"获取 OTP 错误: {e}")
        return None

def send_otp_to_phone(username, otp):
    """模拟发送 OTP 到手机"""
    try:
        phone = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        phone.settimeout(5)
        phone.connect(('localhost', 8888))
        message = {'username': username, 'otp_secret': otp}
        phone.send(json.dumps(message).encode())
        response = phone.recv(1024).decode()
        phone.close()
        response_data = json.loads(response)
        return response_data.get('status') == 'success'
    except Exception as e:
        print(f"发送 OTP 错误: {e}")
        return False

def login_user(username, password, otp):
    """用户登录"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    request = {
        "action": "login",
        "username": username,
        "password_hash": password_hash,
        "otp_code": otp
    }
    response = send_request(request)
    print(f"登录 {username}: {response.get('message', '无消息')}")
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
    print(f"重置 {username} 密码: {response.get('message', '无消息')}")
    return response

def sanitize_filename(filename):
    """防止路径遍历攻击"""
    base_filename = os.path.basename(filename)
    safe_filename = re.sub(r'[^\w\.-]', '_', base_filename)
    if not safe_filename or safe_filename in ['.', '..'] or safe_filename.startswith('.'):
        raise ValueError(f"不安全的文件名: {filename}")
    return safe_filename

def upload_file(username, filename, file_content=None, file_path=None):
    """上传文件"""
    try:
        safe_filename = sanitize_filename(filename)
        if safe_filename != filename:
            print(f"注意: 文件名已改为安全的 '{safe_filename}'")

        if file_content is None and file_path is not None:
            abs_path = os.path.abspath(file_path)
            if not os.path.exists(abs_path):
                return {"status": "error", "message": f"文件未找到: {file_path}"}
            try:
                with open(abs_path, 'rb') as f:
                    file_bytes = f.read()
            except (IOError, PermissionError) as e:
                return {"status": "error", "message": f"无法读取文件: {str(e)}"}
        elif isinstance(file_content, str):
            file_bytes = file_content.encode('utf-8')
        elif file_content is not None:
            file_bytes = file_content
        else:
            return {"status": "error", "message": "未提供文件内容或有效文件路径"}

        _, file_extension = os.path.splitext(safe_filename)
        key = derive_encryption_key(username)
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        file_metadata = {
            "original_filename": safe_filename,
            "file_type": file_extension.lstrip('.').lower(),
            "timestamp": time.time()
        }
        associated_data = json.dumps(file_metadata).encode()
        ciphertext, tag = cipher.encrypt_and_digest(file_bytes)

        encrypted_package = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "metadata": file_metadata
        }
        encrypted_data = base64.b64encode(json.dumps(encrypted_package).encode()).decode()

        request = {
            "action": "upload_file",
            "username": username,
            "filename": safe_filename,
            "data": encrypted_data
        }
        response = send_request(request)
        print(f"{username} 上传 {safe_filename}: {response.get('message', '无消息')}")
        return response
    except ValueError as e:
        print(f"上传错误: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        print(f"加密或上传错误: {e}")
        return {"status": "error", "message": str(e)}

def download_file(username, file_id):
    """通过文件 ID 下载文件并保存到 download 文件夹"""
    try:
        if not isinstance(file_id, (int, str)) or not str(file_id).isdigit():
            return {"status": "error", "message": "无效的文件 ID"}

        file_id = int(file_id)
        request = {"action": "download_file", "username": username, "file_id": file_id}
        logger.debug(f"发送下载请求: {request}")
        response = send_request(request)
        logger.debug(f"下载响应: {response}")

        if response.get("status") != "success":
            print(f"{username} 下载文件 ID {file_id}: {response.get('message', '未知错误')}")
            return response

        encrypted_package = json.loads(base64.b64decode(response["data"]).decode())
        ciphertext = base64.b64decode(encrypted_package["ciphertext"])
        nonce = base64.b64decode(encrypted_package["nonce"])
        tag = base64.b64decode(encrypted_package["tag"])
        file_metadata = encrypted_package.get("metadata", {})

        file_type = file_metadata.get("file_type", "").lower()
        display_filename = file_metadata.get("original_filename", f"file_{file_id}")

        if file_type != "txt":
            print(f"仅支持下载 .txt 文件，当前文件类型: {file_type}")
            return {"status": "error", "message": f"仅支持 .txt 文件，当前类型: {file_type}"}

        key = derive_encryption_key(username)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        decrypted_content = decrypted_bytes.decode('utf-8')

        download_dir = os.path.join(BASE_DIR, "download")
        os.makedirs(download_dir, exist_ok=True)

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

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(decrypted_content)

        print(f"{username} 下载 {display_filename} 已保存到: {file_path}")
        return {"status": "success", "message": f"文件已保存到 {file_path}"}

    except ValueError as e:
        logger.error(f"下载错误: {e}")
        print(f"下载错误: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.error(f"意外错误: {type(e).__name__}: {e}")
        print(f"意外错误: {e}")
        return {"status": "error", "message": str(e)}

def list_files(username):
    """列出用户文件"""
    try:
        if not username or not isinstance(username, str):
            return {"status": "error", "message": "无效的用户名"}
        request = {"action": "list_files", "username": username}
        response = send_request(request)
        return response
    except Exception as e:
        logger.error(f"列出文件错误: {str(e)}")
        return {"status": "error", "message": str(e)}

def edit_file(username, filename, new_content):
    """编辑文件"""
    new_data = base64.b64encode(new_content.encode()).decode()
    request = {
        "action": "edit_file",
        "username": username,
        "filename": filename,
        "data": new_data
    }
    response = send_request(request)
    print(f"{username} 编辑 {filename}: {response.get('message', '无消息')}")
    return response

def delete_file(username, filename):
    """删除文件"""
    request = {
        "action": "delete_file",
        "username": username,
        "filename": filename
    }
    response = send_request(request)
    print(f"{username} 删除 {filename}: {response.get('message', '无消息')}")
    return response

def share_file(username, filename, share_with):
    """分享文件"""
    request = {
        "action": "share_file",
        "username": username,
        "filename": filename,
        "share_with_username": share_with
    }
    response = send_request(request)
    print(f"{username} 分享 {filename} 给 {share_with}: {response.get('message', '无消息')}")
    return response

def view_logs(admin_username):
    """管理员查看日志"""
    request = {"action": "view_logs", "username": admin_username}
    response = send_request(request)
    if response.get("status") == "success":
        print(f"管理员 {admin_username} 查看日志: {response.get('logs', [])}")
    else:
        print(f"管理员 {admin_username} 查看日志: {response.get('message', '无消息')}")
    return response

def handle_login():
    """处理登录逻辑"""
    username = input_with_validation("请输入用户名: ")
    password = input_with_validation("请输入密码: ")

    otp = get_otp(username)
    if not otp:
        print(f"无法为 {username} 生成 OTP")
        return False, ""

    print(f"正在向 {username} 发送 OTP...")
    send_result = send_otp_to_phone(username, otp)
    if not send_result:
        print("错误：OTP 服务不可用。请先运行 OTP 服务。")
        return False, ""

    print("OTP 发送成功！")
    print(f"测试用 OTP: {otp}")  # 生产环境移除

    user_input_otp = input_with_validation("请输入 OTP: ")
    if user_input_otp != otp:
        print("OTP 错误，请重试。")
        return False, ""

    result = login_user(username, password, user_input_otp)
    if result.get("status") == "success":
        print(f"用户 {username} 登录成功！")
        return True, username
    else:
        print(f"登录失败: {result.get('message', '未知错误')}")
        return False, ""

def logged_in_menu(username):
    """登录后菜单"""
    while True:
        clear_screen()
        print(f"\n==== 文件管理系统 - 已登录: {username} ====")
        print("1. 重置密码")
        print("2. 上传文件")
        print("3. 下载文件")
        print("4. 查看文件列表")
        print("5. 编辑文件")
        print("6. 删除文件")
        print("7. 分享文件")
        print("8. 查看日志")
        print("9. 退出登录")
        
        choice = input_with_validation("请选择 (1-9): ")
        
        if choice == "1":
            old_password = input_with_validation("请输入旧密码: ")
            new_password = input_with_validation("请输入新密码: ")
            result = reset_password(username, old_password, new_password)
            input("按回车返回...")
        
        elif choice == "2":
            file_path = input_with_validation("请输入文件路径: ")
            if not os.path.exists(file_path):
                print("文件不存在，请检查路径。")
            else:
                result = upload_file(username, os.path.basename(file_path), file_path=file_path)
            input("按回车返回...")
        
        elif choice == "3":
            result = list_files(username)
            if result.get("status") == "success":
                files = result.get("files", [])
                if not files:
                    print("没有找到文件。")
                else:
                    print("\n文件列表:")
                    print("-" * 50)
                    for file in files:
                        print(f"文件 ID: {file['file_id']}")
                        print(f"文件名: {file['filename']}")
                        print(f"大小: {file['file_size']} 字节")
                        print(f"上传时间: {file['upload_date']}")
                        print(f"最后修改: {file['last_modified']}")
                        print("-" * 50)
                    file_id = input_with_validation("请输入要下载的文件 ID: ")
                    if not file_id.isdigit():
                        print("无效的文件 ID，必须是数字。")
                    else:
                        result = download_file(username, file_id)
            else:
                print(f"错误: {result.get('message', '未知错误')}")
            input("按回车返回...")
        
        elif choice == "4":
            result = list_files(username)
            if result.get("status") == "success":
                files = result.get("files", [])
                if not files:
                    print("没有找到文件。")
                else:
                    print("\n文件列表:")
                    print("-" * 50)
                    for file in files:
                        print(f"文件 ID: {file['file_id']}")
                        print(f"文件名: {file['filename']}")
                        print(f"大小: {file['file_size']} 字节")
                        print(f"上传时间: {file['upload_date']}")
                        print(f"最后修改: {file['last_modified']}")
                        print("-" * 50)
            else:
                print(f"错误: {result.get('message', '未知错误')}")
            input("按回车返回...")
        
        elif choice == "5":
            file_name = input_with_validation("请输入文件名: ")
            new_content = input_with_validation("请输入新内容: ")
            result = edit_file(username, file_name, new_content)
            input("按回车返回...")
        
        elif choice == "6":
            file_name = input_with_validation("请输入文件名: ")
            result = delete_file(username, file_name)
            input("按回车返回...")
        
        elif choice == "7":
            file_name = input_with_validation("请输入文件名: ")
            share_with = input_with_validation("请输入分享对象用户名: ")
            result = share_file(username, file_name, share_with)
            input("按回车返回...")
        
        elif choice == "8":
            result = view_logs(username)
            input("按回车返回...")
        
        elif choice == "9":
            print("正在退出登录...")
            return
        
        else:
            print("无效选项，请选择 1-9。")
            input("按回车继续...")

def initial_menu():
    """初始菜单"""
    while True:
        clear_screen()
        print("\n==== 文件管理系统 ====")
        print("1. 注册")
        print("2. 登录")
        print("3. 退出")
        
        choice = input_with_validation("请选择 (1-3): ")
        
        if choice == "1":
            username = input_with_validation("请输入用户名: ")
            password = input_with_validation("请输入密码: ")
            result = register_user(username, password)
            input("按回车返回...")
        
        elif choice == "2":
            success, username = handle_login()
            if success:
                logged_in_menu(username)
        
        elif choice == "3":
            print("正在退出...")
            break
        
        else:
            print("无效选项，请选择 1-3。")
            input("按回车继续...")

def main():
    """主入口"""
    clear_screen()
    print("欢迎使用文件管理系统！")
    initial_menu()

if __name__ == "__main__":
    main()