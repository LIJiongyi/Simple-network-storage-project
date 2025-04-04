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
    get_otp
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
            elif parts[0] == "login_user":
                otp = get_otp(parts[1])
                if otp:
                    login_user(parts[1], parts[2], otp)
                else:
                    print("Cannot get OTP")
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