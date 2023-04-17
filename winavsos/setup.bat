@echo off

echo Installing Python...
powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.3/python-3.11.3-amd64.exe' -OutFile 'python-installer.exe'"
python-installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
del python-installer.exe

echo Installing OWASP ZAP...
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/zaproxy/zaproxy/releases/download/v2.12.0/ZAP_2_12_0_windows.exe' -OutFile 'zap-installer.exe'"
zap-installer.exe /S
del zap-installer.exe

echo Installing Amass...
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/OWASP/Amass/releases/download/v3.13.4/amass_windows_amd64.zip' -OutFile 'amass.zip'"
powershell -Command "Expand-Archive -Path 'amass.zip' -DestinationPath 'C:\Program Files\Amass'"
del amass.zip

echo Installing Nmap...
powershell -Command "Invoke-WebRequest -Uri 'https://nmap.org/dist/nmap-7.92-setup.exe' -OutFile 'nmap-installer.exe'"
nmap-installer.exe /S
del nmap-installer.exe

echo Installing required Python packages...
pip install python-owasp-zap-v2.4 google python-nmap matplotlib requests tldextract ipaddress configparser

echo Setup complete!
pause
