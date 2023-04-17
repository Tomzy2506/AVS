
import nmap
import csv
import utils
import os
import textwrap


# Function to run Nmap scan on a given URL
def run_nmap(urls, only_vulners=True):
    nm = nmap.PortScanner()
    all_open_ports = {}
    all_vulnerabilities = {}
    all_headers = {}

    if only_vulners:
        nmap_arguments = "-sV -T4 --script vulners"
    else:
        nmap_arguments = "-sV -T4 --script=http-title,http-headers,vulners"

    # Check if urls is a list, if not, make it a list
    if not isinstance(urls, list):
        urls = [urls]

    for url in urls:
        domain = utils.extract_domain(url)
        try:
            nm.scan(domain, arguments=nmap_arguments)
            for host in nm.all_hosts():
                open_ports = {}
                vulnerabilities = {}
                headers = {}
                for proto in nm[host].all_protocols():
                    if proto == "tcp":
                        if nm[host][proto] is not None:
                            for port in nm[host][proto].keys():
                                if nm[host][proto][port]["state"] == "open":
                                    open_ports[port] = nm[host][proto][port]["name"]
                                    # Extract vulnerabilities information
                                    if "script" in nm[host][proto][port] and "vulners" in nm[host][proto][port][
                                        "script"]:
                                        vulnerabilities[port] = nm[host][proto][port]["script"]["vulners"].split("\n")
                                    # Extract header information
                                    if "script" in nm[host][proto][port] and "http-headers" in nm[host][proto][port][
                                        "script"]:
                                        headers[port] = nm[host][proto][port]["script"]["http-headers"]
                all_open_ports[host] = [{"port": p, "service": s} for p, s in open_ports.items()]
                all_vulnerabilities[host] = vulnerabilities
                all_headers[host] = headers
        except nmap.PortScannerError as e:
            print(f"Error running Nmap scan on {domain}: {e}")
    nmap_data = {
        'open_ports': all_open_ports,
        'vulnerabilities': all_vulnerabilities,
        'headers': all_headers
    }
    return all_open_ports, all_vulnerabilities, all_headers


def print_report(nmap_data):
    all_open_ports = nmap_data['open_ports']
    all_vulnerabilities = nmap_data['vulnerabilities']
    all_headers = nmap_data['headers']

    report_str = ""
    for host, open_ports in all_open_ports.items():
        report_str += f"\nHost: {host}\n"
        report_str += f"\nOpen Ports:\n"
        for port_info in open_ports:
            port = port_info["port"]
            service = port_info["service"]
            report_str += f"\n- Port: {port}, Service: {service}\n"

            if host in all_vulnerabilities and port in all_vulnerabilities[host]:
                report_str += "Vulnerabilities:\n"
                for vuln in all_vulnerabilities[host][port]:
                    wrapped_vuln = textwrap.fill(vuln, width=76, initial_indent='    ', subsequent_indent='    ')
                    report_str += f"{wrapped_vuln}\n"

            if host in all_headers and port in all_headers[host]:
                report_str += "  HTTP Headers:\n"
                for header_line in all_headers[host][port].strip().split('\n'):
                    report_str += f"    {header_line}\n"

    return report_str


# Function to retrieve expected services from IANA service names and port numbers file
def get_expected_services():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, "service-names-port-numbers.csv")
    iana_services = {}

    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                port = row['Port Number']
                service = row['Service Name'].lower()
                if port.isdigit():
                    port = int(port)
                    if port not in iana_services:
                        iana_services[port] = service
    except IOError as e:
        print(f"Error opening file {file_path}: {e}")
        return {}

    return iana_services


# Function to compare services found in Nmap scan with expected services
def compare_services(url, all_open_ports):
    # Extract the domain from the URL
    url = utils.extract_domain(url)

    # Get the expected services
    expected_services = get_expected_services()

    # Check if the open ports are using the expected protocols/services
    unexpected_services = []
    for host, ports in all_open_ports.items():
        for port_info in ports:
            port = port_info["port"]
            service = port_info["service"]
            if port in expected_services and expected_services[port] != service.lower():
                unexpected_services.append({"port": port, "service": service})

    if not unexpected_services:
        for ports in all_open_ports.items():
            print(f"- Port: {port}, Service: {service}")
        print(f"\nAll open ports on {url} match expected services.")
    else:
        print(f"\nFound {len(unexpected_services)} unexpected service(s) on {url}:")
        for service_info in unexpected_services:
            port = service_info["port"]
            service = service_info["service"]
            print(f"- Port: {port}, Service: {service}")

    return unexpected_services
