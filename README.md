# Voseto

Voseto is a Python-based CLI tool that combines multiple security scanning tools to help identify vulnerabilities and risks in a given domain. Dawn integrates with Amass for subdomain enumeration, Whois for domain hijacking risk analysis, Nmap for port scanning and CVE detection, and OWASP ZAP for vulnerability scanning. A comprehensive report is automatically generated after the scans are completed.

## Installation

1. Clone this repository or download the source code.

2. git clone https://github.com/Tomzy2506/dawn
3. cd dawn
4. pip install -r requirements.txt
	
5. Install [Amass](https://github.com/OWASP/Amass/releases/download/v3.13.4/amass_windows_amd64.zip) and [OWASP ZAP](https://github.com/zaproxy/zaproxy/releases/download/v2.12.0/ZAP_2_12_0_windows.exe) following their respective installation instructions.

## Usage

To run all scans on a domain, use the following command:

dawn -d example.com -a

Replace `example.com` with the domain you want to scan.

## Command Line Options

- `-d DOMAIN` or `--domain DOMAIN`: Specify the target domain for scanning.
- `-a` or `--all`: Run all scans (Amass, Whois, Nmap, and ZAP) on the specified domain.

## Features

- Subdomain enumeration using Amass.
- Domain hijacking risk analysis using Whois.
- Port scanning and CVE detection based on header information using Nmap.
- Vulnerability scanning using OWASP ZAP.
- Automatic report generation.

## License

[MIT License](LICENSE)

