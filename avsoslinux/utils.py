import requests
import tldextract
import ipaddress
import socket
import logging
import re
from urllib.parse import urlparse
import os
import xml.etree.ElementTree as ET

def enable_debugging():
    logging.basicConfig(level=logging.DEBUG)

def enable_logging():
    logging.basicConfig(filename="osint_utils.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def validate_input(url):
    if not is_valid_url(url) and not is_valid_domain(url) and not is_valid_ip(url):
        return False
    return True

def check_url_reachability(url):
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = f"http://{url}"

        response = requests.head(url, timeout=5)
        if response.status_code >= 400:
            print(f"Response status code: {response.status_code}")

        return response.status_code < 400

    except requests.exceptions.RequestException as e:
        print(f"RequestException: {e}")
        return False

def is_valid_url(url):
    # Validate the URL using a regular expression
    regex = re.compile(
        r'^(?:(?:http|ftp)s?://)?'  # http:// or https:// (optional)
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return re.match(regex, url) is not None

def extract_domain(url):
    # Extract the domain from the URL
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"


def is_valid_domain(domain):
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$'
    )
    return domain_regex.match(domain) is not None

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def domain_to_ip(domain):
    # Convert a domain to its corresponding IP address if the domain is valid
    if is_valid_domain(domain):
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except Exception as e:
            logging.error(f"Error converting domain {domain} to IP: {e}")
            return None
    else:
        logging.error(f"Invalid domain provided: {domain}")
        return None


def ip_to_domain(target):
    # Convert an IP address to its corresponding domain if the IP is valid
    if is_valid_ip(target):
        try:
            domain = socket.gethostbyaddr(target)
            return domain[0]
        except Exception as e:
            logging.error(f"Error converting IP {target} to domain: {e}")
            return None
    elif is_valid_domain(target):
        return target
    else:
        logging.error(f"Invalid IP address provided: {target}")
        return None

def resolve_domain_ips(domain):
    """
    Resolve all IP addresses associated with the domain.
    """
    try:
        ipv4_addresses = [str(x[4][0]) for x in socket.getaddrinfo(domain, None, socket.AF_INET)]
        ipv6_addresses = [str(x[4][0]) for x in socket.getaddrinfo(domain, None, socket.AF_INET6)]
    except socket.gaierror as e:
        print(f"Error resolving IP addresses for {domain}: {e}")
        return []

    return ipv4_addresses + ipv6_addresses

      
def count_severity(zap_scan_results):
    severity_counts = {
        "Informational": 0,
        "Low": 0,
        "Medium": 0,
        "High": 0
    }

    for issue in zap_scan_results:
        severity = issue.get('risk')
        if severity in severity_counts:
            severity_counts[severity] += 1

    return severity_counts

def get_zap_api_key():
    try:
        tree = ET.parse(os.path.expanduser('~/.ZAP/config.xml'))
        root = tree.getroot()
        for elem in root.findall(".//key"):
            return elem.text
    except FileNotFoundError:
        print("Error: ZAP config.xml not found. Please ensure ZAP is installed and configured.")
        return None
