import sys
import subprocess
import platform

def open_new_console(command):
    if platform.system() == 'Windows':
        subprocess.Popen(f"start cmd.exe /k {command}", shell=True)
    else:
        subprocess.Popen(["gnome-terminal", "--", "/bin/bash", "-c", f"{command}; exec bash"])

def main():
    if platform.system() == 'Windows':
        command = 'dir'
    else:
        command = 'zap.sh -daemon'

    open_new_console(command)

if __name__ == "__main__":
    main()
