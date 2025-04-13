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
    send_otp_to_phone,
    list_files,
)
import os

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

def handle_login() -> tuple[bool, str]:
    """处理登录逻辑，返回 (是否成功, 用户名)"""
    username = input_with_validation("请输入用户名: ")
    password = input_with_validation("请输入密码: ")

    otp = get_otp(username)
    if not otp:
        print(f"无法为 {username} 生成 OTP")
        return False, ""

    print(f"正在向 {username} 发送 OTP...")
    send_result = send_otp_to_phone(username, otp)
    if not send_result:
        print("错误：OTP 服务不可用。请先运行 'python get_otp.py'。")
        return False, ""

    print("OTP 发送成功！")
    print(f"测试用 OTP: {otp}")  # 测试用，生产环境移除

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

def logged_in_menu(username: str):
    """登录后菜单：提供所有功能"""
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
            print(f"{result.get('status', '未知')}: {result.get('message', '无消息')}")
            input("按回车返回...")
        
        elif choice == "2":
            file_path = input_with_validation("请输入文件路径: ")
            if not os.path.exists(file_path):
                print("文件不存在，请检查路径。")
            else:
                result = upload_file(username, os.path.basename(file_path), None, file_path)
                print(f"{result.get('status', '未知')}: {result.get('message', '无消息')}")
            input("按回车返回...")
        
        elif choice == "3":
            # 显示文件列表
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
                    # 提示输入文件 ID
                    file_id = input_with_validation("请输入要下载的文件 ID: ")
                    if not file_id.isdigit():
                        print("无效的文件 ID，必须是数字。")
                    else:
                        result = download_file(username, file_id)
                        if result.get("status") != "success":
                            print(f"错误: {result.get('message', '未知错误')}")
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
            print(f"{result.get('status', '未知')}: {result.get('message', '无消息')}")
            input("按回车返回...")
        
        elif choice == "6":
            file_name = input_with_validation("请输入文件名: ")
            result = delete_file(username, file_name)
            print(f"{result.get('status', '未知')}: {result.get('message', '无消息')}")
            input("按回车返回...")
        
        elif choice == "7":
            file_name = input_with_validation("请输入文件名: ")
            share_with = input_with_validation("请输入分享对象用户名: ")
            result = share_file(username, file_name, share_with)
            print(f"{result.get('status', '未知')}: {result.get('message', '无消息')}")
            input("按回车返回...")
        
        elif choice == "8":
            result = view_logs(username)
            print(f"{result.get('status', '未知')}: {result.get('message', '无消息')}")
            input("按回车返回...")
        
        elif choice == "9":
            print("正在退出登录...")
            return  # 改为 return，确保退出到 initial_menu
        
        else:
            print("无效选项，请选择 1-9。")
            input("按回车继续...")

def initial_menu():
    """初始菜单：注册、登录、退出"""
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
            print(f"{result.get('status', '未知')}: {result.get('message', '无消息')}")
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



def user_cli():
    """主入口"""
    clear_screen()
    print("欢迎使用文件管理系统！")
    initial_menu()

if __name__ == "__main__":
    user_cli()