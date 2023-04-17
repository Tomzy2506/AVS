# AVSOS

AVSOS is a Python-based CLI tool that combines multiple security scanning tools to help identify vulnerabilities and risks in a given domain. AVSOS integrates with Amass for subdomain enumeration, Whois for domain hijacking risk analysis, Nmap for port scanning and CVE detection, and OWASP ZAP for vulnerability scanning. A comprehensive report is automatically generated after the scans are completed.

## Installation

1. Clone this repository or download the source code.

2. git clone https://github.com/Tomzy2506/avsos
3. cd avsos
4. pip install -r requirements.txt
	
5. Install [Amass](https://github.com/OWASP/Amass/releases/download/v3.13.4/amass_windows_amd64.zip) and [OWASP ZAP](https://github.com/zaproxy/zaproxy/releases/download/v2.12.0/ZAP_2_12_0_windows.exe) following their respective installation instructions.

OR

1. Open terminal
2. sudo apt-get update
3. pip install avsos

## Usage

To run all scans on a domain, use the following command:

avsos -d example.com -a


Replace `example.com` with the domain you want to scan.

## Command Line Options

- `-d DOMAIN` or `--domain DOMAIN`: Specify the target domain for scanning.
- `-a` or `--all`: Run all scans (Amass, Whois, Nmap, and ZAP) on the specified domain.
- `-se` or `--enum`: Perform subdomain enumeration using Amass.
- `-z` or `--zap`: Perform vulnerability scan using ZAP.
- `-n` or `--nmap`: Perform Nmap port scan.
- `-w` or `--whois`: Perform Whois lookup.
- `-f FORMAT` or `--format FORMAT`: Output file format (json/csv/txt), default is `output_format`.
- `-o OUTPUT` or `--output OUTPUT`: Output file name.
- `-en` or `--encrypt`: Encrypt the output report (default: False).
- `-dc` or `--decrypt`: Decrypt a previously encrypted output file.
- `-ns NUM_SCANS` or `--num_scans NUM_SCANS`: Number of scans to perform, default is 1.
- `-t TIME` or `--time TIME`: Schedule a scan (in minutes).
- `-deb` or `--debug`: Enable debugging messages.
- `-sf SUBDOMAINS_FILE` or `--subdomains_file SUBDOMAINS_FILE`: File containing subdomains to scan.
- `-k KEY` or `--key KEY`: The encryption key. Required for decryption.
- `-ef ENCRYPTED_FILE` or `--encrypted_file ENCRYPTED_FILE`: Path to the encrypted file (for decryption).
- `-df DECRYPTED_FILE` or `--decrypted_file DECRYPTED_FILE`: Path to save the decrypted file (for decryption).
- `-encf ENCRYPT_FILE` or `--encrypt_file ENCRYPT_FILE`: Encrypt an existing file in the folder.

## Features

- Subdomain enumeration using Amass.
- Domain hijacking risk analysis using Whois.
- Port scanning and CVE detection based on header information using Nmap.
- Vulnerability scanning using OWASP ZAP.
- Automatic report generation in different formats.
- Encryption and decryption of output reports.

## License

[MIT License](LICENSE)
