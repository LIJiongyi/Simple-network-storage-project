# This is user interface

from api_user import (
    register_user, 
    login_user, 
    reset_password, 
    upload_file, 
    download_file, 
    edit_file, 
    delete_file, 
    share_file, 
    view_logs, 
    get_otp,
    send_otp_to_phone
)

def user_cli():
    while True:
        print("\n==== CLI ====")
        print("1. User Registration (register_user [username] [password])")
        print("2. User Login (login_user [username] [password])")
        print("3. Reset Password (reset_password [username] [password] [new_password])")
        print("4. Upload File (upload_file [username] [file name] [file content])")
        print("5. Download File (download_file [username] [file name])")
        print("6. Edit File (edit_file [username] [file name] [new content])")
        print("7. Delete file (delete_file [username] [file name])")
        print("8. Share File (share_file [username] [file name] [share with])")
        print("9. View Logs (view_logs [admin username])")
        print("10. Exit")
        
        command = input("Select a command: ").strip()
        parts = command.split(" ")
        
        try:
            if parts[0] == "register_user":
                register_user(parts[1], parts[2])
            # 在user_interface.py中修改登录部分
            elif parts[0] == "login_user":
                if len(parts) < 3:
                    print("格式错误: login_user [username] [password]")
                    continue
    
                username = parts[1]
                password = parts[2]
    
                # 生成OTP验证码
                otp = get_otp(username) # otp是已经生成的验证码
                if not otp:
                    print(f"Cannot generate OTP for {username}")
                    continue
    
                # 发送OTP到模拟手机
                print(f"sending OTP to {username}")
                send_result = send_otp_to_phone(username, otp) # 这里接收的是是否成功发送
    
                if not send_result:
                    print("make sure the phone is running")
                    continue
        
                print("Sent")
    
                # 提示用户输入验证码
                user_input_otp = input("Please input OTP: ").strip()
    
                # 验证用户输入的OTP
                if user_input_otp != otp:
                    print("Wrong OTP, please try again.")
                    continue
    
                # 验证通过，执行登录
                login_result = login_user(username, password, user_input_otp)
    
                if login_result.get("status") == "success":
                   print(f"用户 {username} 登录成功!")
                else:
                    print(f"登录失败: {login_result.get('message', '未知错误')}")
            elif parts[0] == "reset_password":
                reset_password(parts[1], parts[2], parts[3])
            elif parts[0] == "upload":
                upload_file(parts[1], parts[2], " ".join(parts[3:]))
            elif parts[0] == "download_file":
                download_file(parts[1], parts[2])
            elif parts[0] == "edit_file":
                edit_file(parts[1], parts[2], " ".join(parts[3:]))
            elif parts[0] == "delete_file":
                delete_file(parts[1], parts[2])
            elif parts[0] == "share_file":
                share_file(parts[1], parts[2], parts[3])
            elif parts[0] == "view_logs":
                view_logs(parts[1])
            elif parts[0] == "exit":
                print("Exit")
                break
            else:
                print("Unable, Try again")
        except IndexError:
            print("Wrong Grammar, Try again")


if __name__ == "__main__":
    user_cli()