import os
import subprocess
import psutil


def is_zap_running(zap_executable):
    for process in psutil.process_iter(['name']):
        try:
            if process.info['name'].lower() == zap_executable.lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False


# Set the folder path and ZAP executable path
folder_path = "C:\\Program Files\\OWASP\\Zed Attack Proxy"
zap_executable = "ZAP.exe"  # ZAP executable file name

# Check if ZAP is already running
if not is_zap_running(zap_executable):
    # Change the current directory to the specified folder
    os.chdir(folder_path)

    # Run the ZAP executable
    subprocess.run([os.path.join(folder_path, zap_executable)])
else:
    print("ZAP is already running.")
