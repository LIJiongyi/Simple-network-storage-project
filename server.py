import socket
import json
import sqlite3
import time
import pyotp
import base64
import re
import os

# 项目根目录和数据库路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'storage.db')

# 服务器配置
HOST = 'localhost'
PORT = 9999

def log_action(username, action):
    """记录用户操作日志到数据库"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO logs (username, action, timestamp) VALUES (?, ?, ?)",
                  (username, action, time.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    except Exception as e:
        print(f"Log error: {e}")
    finally:
        conn.close()

def handle_register(request):
    """处理用户注册请求"""
    username = request["username"]
    password_hash = request["password"]
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if c.fetchone():
            return {"status": "error", "message": "Username already exists"}
        otp_secret = pyotp.random_base32()
        c.execute("INSERT INTO users (username, password_hash, otp_secret) VALUES (?, ?, ?)",
                  (username, password_hash, otp_secret))
        conn.commit()
        log_action(username, "register")
        return {"status": "success", "message": "User registered"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

def handle_login(request):
    """处理用户登录请求，验证密码和 OTP"""
    username = request["username"]
    password_hash = request["password"]
    otp = request["otp"]
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT password_hash, otp_secret FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        if not user or user[0] != password_hash:
            return {"status": "error", "message": "Invalid credentials"}
        totp = pyotp.TOTP(user[1])
        if not totp.verify(otp):
            return {"status": "error", "message": "Invalid OTP"}
        log_action(username, "login")
        return {"status": "success", "message": "Login successful", "data": "token_abc123"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

def handle_reset_password(request):
    """处理密码重置请求"""
    username = request["username"]
    old_password_hash = request["old_password"]
    new_password_hash = request["new_password"]
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        if not user or user[0] != old_password_hash:
            return {"status": "error", "message": "Invalid old password"}
        c.execute("UPDATE users SET password_hash = ? WHERE username = ?", 
                  (new_password_hash, username))
        conn.commit()
        log_action(username, "reset_password")
        return {"status": "success", "message": "Password reset successful"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

def handle_upload(request):
    """处理文件上传请求，包含文件名验证"""
    username = request["username"]
    filename = request["filename"]
    encrypted_data = base64.b64decode(request["data"])
    if not re.match(r'^[a-zA-Z0-9_.-]+$', filename) or ".." in filename:
        return {"status": "error", "message": "Invalid filename"}
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO files (filename, owner, encrypted_data) VALUES (?, ?, ?)",
                  (filename, username, encrypted_data))
        conn.commit()
        log_action(username, "upload")
        return {"status": "success", "message": "File uploaded"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

def handle_download(request):
    """处理文件下载请求"""
    username = request["username"]
    filename = request["filename"]
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT encrypted_data FROM files WHERE filename = ? AND owner = ?",
                  (filename, username))
        file = c.fetchone()
        if not file:
            c.execute("SELECT f.encrypted_data FROM files f JOIN shares s ON f.file_id = s.file_id "
                      "WHERE f.filename = ? AND s.shared_with_username = ?",
                      (filename, username))
            file = c.fetchone()
            if not file:
                return {"status": "error", "message": "File not found or unauthorized"}
        encrypted_data = base64.b64encode(file[0]).decode()
        log_action(username, "download")
        return {"status": "success", "message": "Download successful", "data": encrypted_data}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

def handle_edit_file(request):
    """处理文件编辑请求"""
    username = request["username"]
    filename = request["filename"]
    new_data = base64.b64decode(request["data"])
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT file_id FROM files WHERE filename = ? AND owner = ?", 
                  (filename, username))
        file = c.fetchone()
        if not file:
            return {"status": "error", "message": "File not found or not owner"}
        c.execute("UPDATE files SET encrypted_data = ? WHERE file_id = ?", 
                  (new_data, file[0]))
        conn.commit()
        log_action(username, "edit_file")
        return {"status": "success", "message": "File edited"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

def handle_delete_file(request):
    """处理文件删除请求"""
    username = request["username"]
    filename = request["filename"]
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT file_id FROM files WHERE filename = ? AND owner = ?", 
                  (filename, username))
        file = c.fetchone()
        if not file:
            return {"status": "error", "message": "File not found or not owner"}
        file_id = file[0]
        c.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
        c.execute("DELETE FROM shares WHERE file_id = ?", (file_id,))
        conn.commit()
        log_action(username, "delete_file")
        return {"status": "success", "message": "File deleted"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

def handle_share(request):
    """处理文件分享请求"""
    username = request["username"]
    filename = request["filename"]
    share_with = request["share_with"]
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT file_id FROM files WHERE filename = ? AND owner = ?",
                  (filename, username))
        file = c.fetchone()
        if not file:
            return {"status": "error", "message": "File not found or not owner"}
        file_id = file[0]
        c.execute("INSERT INTO shares (file_id, shared_with_username) VALUES (?, ?)",
                  (file_id, share_with))
        conn.commit()
        log_action(username, f"share with {share_with}")
        return {"status": "success", "message": "File shared"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

def handle_view_logs(request):
    """处理管理员查看日志请求"""
    username = request["username"]
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        if username != "admin":
            return {"status": "error", "message": "Unauthorized access"}
        c.execute("SELECT username, action, timestamp FROM logs")
        logs = c.fetchall()
        log_list = [{"username": log[0], "action": log[1], "timestamp": log[2]} for log in logs]
        return {"status": "success", "message": "Logs retrieved", "data": log_list}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

def handle_request(request):
    """处理客户端请求的分发函数"""
    action = request.get("action")
    if action == "register":
        return handle_register(request)
    elif action == "login":
        return handle_login(request)
    elif action == "reset_password":
        return handle_reset_password(request)
    elif action == "upload":
        return handle_upload(request)
    elif action == "download":
        return handle_download(request)
    elif action == "edit_file":
        return handle_edit_file(request)
    elif action == "delete_file":
        return handle_delete_file(request)
    elif action == "share":
        return handle_share(request)
    elif action == "view_logs":
        return handle_view_logs(request)
    else:
        return {"status": "error", "message": "Unknown action"}

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)
print(f"Server running on {HOST}:{PORT}")

while True:
    client, addr = server.accept()
    print(f"Connection from {addr}")
    data = client.recv(4096).decode()
    request = json.loads(data)
    response = handle_request(request)
    client.send(json.dumps(response).encode())
    client.close()