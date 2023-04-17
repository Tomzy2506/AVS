import os
import re
import dateutil.parser
import subprocess
import whois
from datetime import datetime, timedelta, timezone
import utils
import logging
import pytz
import traceback

# Set up logging
logging.basicConfig(filename="osint.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Get the current working directory
current_dir = os.getcwd()


# AMASS
def amass(target):  # add possibility or reverse whois lookup and something to compare subdomains
    """
    Uses amass to enumerate subdomains for a given target.

    Args:
        target (str): The target to enumerate subdomains for.

    Returns:
        list: A list of subdomains for the given target.
    """
    domain = utils.extract_domain(target)
    ip = utils.ip_to_domain(target)

    if domain is None:
        return []

    subdomains_file = f"{target}_subdomains.txt"

    try:
        subprocess.run(["amass", "enum", "-d", domain, "-o", subdomains_file], check=True, text=True)
        with open(subdomains_file, "r") as f:
            subdomains = f.read().splitlines()
        os.remove(subdomains_file)
        return subdomains
    except Exception as e:
        print(f"Error running amass: {e}")
        return []


# WHOIS

def get_whois_info(target):
    """
    Uses whois to retrieve WHOIS information for a given target.

    Args:
        target (str): The target to retrieve WHOIS information for.

    Returns:
        tuple: A tuple containing the domain and a dictionary of WHOIS information for the given target.
    """
    domain = utils.extract_domain(target)
    print(target)
    ip = utils.domain_to_ip(target)


    try:
        whois_output = whois.whois(domain)

        # Extract the expiration date from the Whois output
        expiration_date = whois_output.expiration_date if whois_output.expiration_date else None

        # Extract the name servers from the Whois output
        name_servers = whois_output.name_servers

        # Extract DNSSEC status from the Whois output (not available in python-whois)
        dnssec = None

        # Extract domain status from the Whois output
        domain_status = whois_output.status

        # Extract the registrar information from the Whois output
        registrar = whois_output.registrar

        # Create the whois_data dictionary and include the extracted information
        whois_data = {
            'expiration_date': expiration_date,
            'name_servers': name_servers,
            'dnssec': dnssec,
            'domain_status': domain_status,
            'registrar': registrar
        }

        logging.info(f"\nWHOIS information for {target}:")
        return domain, whois_data
    except Exception as e:
        logging.error(f"\nError retrieving whois information for {target}: {e}")
        traceback.print_exc()
        return None, None


# Domains at risk
def domain_at_risk(urls, threshold_days=300):
    domains_at_risk = []
    current_datetime = datetime.now()    # Define the current_datetime variable

    for url in urls:
        domain, info = get_whois_info(url)
        if domain is None:
            continue

        if "expiration_date" in info:
            expiration_date = info["expiration_date"]
            expiration_date = expiration_date.astimezone(pytz.UTC).replace(tzinfo=None)

            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            if expiration_date is not None:
                if expiration_date - current_datetime <= timedelta(days=threshold_days):
                    domains_at_risk.append((domain, expiration_date))
            else:
                print(f"Warning: Expiration date not found for {domain}. Skipping...")

    return domains_at_risk

def extract_servers_from_whois(whois_info):
    # Extract server IPs from the WHOIS data
    servers = []
    if "name_servers" in whois_info:
        for server in whois_info["name_servers"]:
            servers.append(server)
    return servers


def check_domain_hijacking(whois_info):
    domains_at_risk = domain_at_risk([whois_info[0]])
    if domains_at_risk:
        domains_list = []
        print("\nDomains at risk of hijacking:")
        for domain, expiration_date in domains_at_risk:
            domain_info = f"{domain} (expires {expiration_date})"
            domains_list.append(domain_info)
            print(domain_info)
        return domains_list
    else:
        print("No domains found at risk of hijacking.")
        return None


def format_whois_output(whois_info):
    domain, whois_data = whois_info
    formatted_output = f"WHOIS information for {domain}:\n"

    if whois_data.get("expiration_date"):
        formatted_output += f"  Expiration Date: {whois_data['expiration_date']}\n"

    if whois_data.get("name_servers"):
        formatted_output += "  Name Servers:\n"
        for ns in whois_data["name_servers"]:
            formatted_output += f"    {ns}\n"

    if whois_data.get("dnssec"):
        formatted_output += f"  DNSSEC: {whois_data['dnssec']}\n"

    if whois_data.get("domain_status"):
        formatted_output += "  Domain Status:\n"
        for status in whois_data["domain_status"]:
            formatted_output += f"    {status}\n"

    if whois_data.get("registrar"):
        formatted_output += f"  Registrar: {whois_data['registrar']}\n"

    return formatted_output
