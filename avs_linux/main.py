import osint
import zapscan
import portscan
import encryption
import utils
import argparse
import traceback
import subprocess
from config import ScannerConfig
import configparser
import json
from datetime import datetime
import os
import time
import schedule
import logging
import PyPDF2
import csv
import concurrent.futures
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet

config = ScannerConfig()
output_format = config.output_format
encrypt_output = None
amass_enabled = config.amass_enabled
whois_enabled = config.whois_enabled
nmap_enabled = config.nmap_enabled
zap_enabled = config.zap_enabled
zap_path = config.zap_path
api_key = config.zap_api_key
time_interval = config.time_interval


class CustomEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.strftime('%Y-%m-%dT%H:%M:%S.%fZ').replace(",", "")
        return super().default(o)


def format_output(report_data):
    formatted_output = ""

    def format_dict(dictionary, indent=0):
        nonlocal formatted_output
        for key, value in dictionary.items():
            formatted_output += " " * indent + str(key) + ":\n"
            if isinstance(value, dict):
                format_dict(value, indent + 2)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        format_dict(item, indent + 2)
                    else:
                        formatted_output += " " * (indent + 2) + str(item) + "\n"
            else:
                formatted_output += " " * indent + str(key) + ": " + str(value) + "\n"

    format_dict(report_data)
    formatted_output += "=" * 80 + "\n"
    return formatted_output


def save_report(report_data, file_formats, output_file, encrypt_output=False, graph_file=None):
    formatted_output = format_output(report_data)
    output_file_no_ext, file_ext = os.path.splitext(output_file)

    def save_as_pdf():
        doc = SimpleDocTemplate(output_file_no_ext + '.pdf', pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        if graph_file:
            report_data["Graph File"] = graph_file
            try:
                img = Image(graph_file, width=450, height=300)
                img.hAlign = 'CENTER'
                elements.append(img)
                elements.append(Spacer(1, 12))
            except Exception as e:
                print(f"Error adding graph to the PDF: {e}")

        for section, data in report_data.items():
            elements.append(Paragraph(section, styles['Heading1']))
            elements.append(Spacer(1, 12))

            if isinstance(data, dict):
                for key, value in data.items():
                    elements.append(Paragraph(f"<strong>{key}:</strong> {value}", styles['BodyText']))
            elif isinstance(data, list):
                for item in data:
                    elements.append(Paragraph(item, styles['Bullet']))
            elif isinstance(data, str):
                for line in data.split("\n"):
                    data = data.replace("\n", "<br/>")
                    elements.append(Paragraph(line, styles['BodyText']))

            elements.append(Spacer(1, 12))

        if encrypt_output:
            from io import BytesIO
            buffer = BytesIO()
            doc.build(elements, canvasmaker=buffer)
            encrypted_data = encryption.encrypt_data(buffer.getvalue())
            with open(output_file + '.pdf', 'wb') as f:
                f.write(encrypted_data)
        else:
            doc.build(elements)

    def save_as_json():
        with open(output_file_no_ext + '.json', 'w') as f:
            if graph_file:
                report_data["Graph File"] = graph_file
            if encrypt_output:
                encrypted_data = encryption.encrypt_data(json.dumps(report_data, cls=CustomEncoder))
                f.write(json.dumps(json.loads(encrypted_data.decode()), indent=2))
            else:
                json.dump(report_data, f, indent=2, cls=CustomEncoder)

    def save_as_csv():
        with open(output_file_no_ext + '.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            # Write the header row
            header = ["Section", "Key", "Value"]
            writer.writerow(header)
            # Write the data rows
            if graph_file:
                report_data["Graph File"] = graph_file
            for section, data in report_data.items():
                if isinstance(data, dict):
                    for key, value in data.items():
                        writer.writerow([section, key, value])
                elif isinstance(data, list):
                    for item in data:
                        writer.writerow([section, "", item])

    formats = file_formats.lower().split(',')

    if 'pdf' in formats:
        save_as_pdf()

    if 'json' in formats:
        save_as_json()

    if 'csv' in formats:
        save_as_csv()

    if 'txt' in formats:
        with open(output_file_no_ext + '.txt', 'w') as f:
            if graph_file:
                formatted_output += "Graph File: " + graph_file + "\n"
            if encrypt_output:
                encrypted_data = encryption.encrypt_data(formatted_output)
                f.write(encrypted_data.decode())
            else:
                f.write(formatted_output)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Welcome to AUTO-OSINT & VULNERABILITY REPORT TOOL!')

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument('-u', '--url', help='Target URL')
    target_group.add_argument('--ip', help='Target IP address')
    target_group.add_argument('-d', '--domain', help='Target domain')

    args = parser.parse_known_args()[0]
    target = args.url or args.ip or args.domain

    parser.add_argument('-a', '--all', help='Run all processes', action='store_true')
    parser.add_argument("-se", "--enum", action="store_true", help="Perform subdomain enumeration using Amass")
    parser.add_argument("-z", "--zap", action="store_true", help="Perform vulnerability scan using ZAP")
    parser.add_argument("-n", "--nmap", action="store_true", help="Perform Nmap port scan")
    parser.add_argument("-w", "--whois", action="store_true", help="Perform Whois lookup")
    parser.add_argument('-f', '--format', help='Output file format (json/csv/txt)', default=output_format)
    parser.add_argument('-o', '--output', help='Output file name')
    parser.add_argument('-en', '--encrypt', help='Encrypt the output report (default: False)', action='store_true')
    parser.add_argument('-dc', '--decrypt', action='store_true', help='Decrypt a previously encrypted output file')
    parser.add_argument('-ns', '--num_scans', help='Number of scans to perform', type=int, default=1)
    parser.add_argument('-t', '--time', help='Schedule a scan (in minutes)', type=int)
    parser.add_argument('-deb', "--debug", help="Enable debugging messages", action="store_true")
    parser.add_argument('-sf', "--subdomains_file", help="File containing subdomains to scan")
    parser.add_argument('-k', '--key', help='The encryption key. Required for decryption.')
    parser.add_argument('-ef', '--encrypted_file', help='Path to the encrypted file (for decryption)')
    parser.add_argument('-df', '--decrypted_file', help='Path to save the decrypted file (for decryption)')
    parser.add_argument('-encf', '--encrypt_file', help='Encrypt an existing file in the folder')

    args = parser.parse_args()

    if args.decrypt:
        if not args.key:
            parser.error("Please provide the key for decryption.")
        if not args.encrypted_file or not args.decrypted_file:
            parser.error("Please provide the encrypted file and decrypted file for decryption.")
    # If the '-encf' option is not provided, perform the target check
    elif not args.encrypt_file:
        if not target and not args.subdomains_file:  # If no target or subdomains_file is provided, show an error
            parser.error("No target specified. Please provide a URL, IP address, or domain.")
        elif target and not utils.validate_input(target):  # If the target is provided but is invalid, show an error
            parser.error("Invalid target input. Please provide a valid URL, IP address, or domain.")
    return args


def run_scans(args):
    target = args.url or args.ip or args.domain
    encrypt_output = args.encrypt

    report_data = {}

    # Initialize variables for scan results
    subdomains, domains_at_risk_list, whois_info, nslookup_info, zap, servers, graph_file = None, None, None, None, None, None, None
    server_open_ports_list = []
    all_open_ports, all_vulnerabilities, all_headers = None, None, None

    if args.subdomains_file:
        try:
            with open(args.subdomains_file, "r") as f:
                subdomains = f.read().splitlines()
                if not target:  # If the target is None, use the first subdomain from the file
                    target = subdomains[0]
                logging.debug("Running Amass on subdomains...") # run amass on domains in file
                print("\nRunning Amass on subdomains...")
                # Run Amass on subdomains file
                amass_output = subprocess.run(["amass", "enum", "-df", args.subdomains_file], check=True, text=True)
                amass_results = amass_output.stdout.splitlines()
                subdomains = amass_results
                report_data["File Subdomains"] = subdomains
        except FileNotFoundError:
            print(f"Error: File {args.subdomains_file} not found.")

    if args.enum or args.all:  # subdomain enumeration
        try:
		    if args.whois or args.all:
		        # Run Amass and Whois concurrently
		        with concurrent.futures.ThreadPoolExecutor() as executor:
		            amass_future = executor.submit(osint.amass, target)
		            whois_future = executor.submit(osint.get_whois_info, target)

		        subdomains = amass_future.result()
		        whois_info = whois_future.result()
		        report_data["Subdomains"] = subdomains
		        formatted_whois_info = osint.format_whois_output(whois_info)
		        print(formatted_whois_info)
		        domains_at_risk_list = osint.check_domain_hijacking(whois_info)
		        domains_at_risk_text = "\n".join(domains_at_risk_list) if domains_at_risk_list else "None"
		        report_data['WHOIS'] = formatted_whois_info  # Add Whois information to report_data
		        report_data["Domains at risk of hijacking"] = domains_at_risk_text
		    else:
		        logging.debug("Running Amass...")
		        print("\nRunning Amass...")
		        subdomains = osint.amass(target)
		        report_data["Subdomains"] = subdomains
		 except Exception as e:
		 	print(f"Error running the selected scans: {e}")
    elif args.whois or args.all:
        try:
		    logging.debug("Running WHOIS...")
		    print("\nRunning Whois...")
		    whois_info = osint.get_whois_info(target)
		    formatted_whois_info = osint.format_whois_output(whois_info)
		    print(formatted_whois_info)
		    domains_at_risk_list = osint.check_domain_hijacking(whois_info)
		    domains_at_risk_text = "\n".join(domains_at_risk_list) if domains_at_risk_list else "None"
		    report_data['WHOIS'] = formatted_whois_info  # Add Whois information to report_data
		    report_data["Domains at risk of hijacking"] = domains_at_risk_text
        except Exception as e:
		 	print(f"Error running the selected scans: {e}")

    if args.zap or args.all:
        try:
		    logging.debug("Running ZAP...")
		    print("\nRunning ZAP Scan...")
		    if api_key is None:
		        print("Error retrieving ZAP API key.")
		        return
		    zap_process = zapscan.start_zap(zap_path)
		    if zap_process is None:
		        print("Error starting ZAP.")
		        return
		    zap = zapscan.run_zap_scan(target, api_key,
		                               subdomains)  # add option of adding api key to config file and using that
		    print("\nZAP Complete")

		    zap_results_str, zap_alerts = zapscan.zap_report(zap)
		    report_data['ZAP Scan'] = zap_results_str  # Add ZAP scan results to report_data
		    # Generate the graph file name using the target and a timestamp
		    graph_file = f"{target}_graph_{datetime.now().strftime('%H%M%S')}.png"
		    # Plot the graph
		    severity_counts = utils.count_severity(zap_alerts)
		    zapscan.plot_graph(severity_counts, graph_file)
        except Exception as e:
		 	print(f"Error running the selected scans: {e}")
                

    if args.nmap or args.all:
        logging.debug("Running NMAP...")
        print("\nRunning Nmap on the main domain...")
        try:
            all_open_ports, all_vulnerabilities, all_headers = portscan.run_nmap(target, only_vulners=False)
            unexpected_services = portscan.compare_services(target, all_open_ports)
            nmap_data = {
                'open_ports': all_open_ports,
                'vulnerabilities': all_vulnerabilities,
                'headers': all_headers
            }
            nmap_report_str = portscan.print_report(nmap_data)
            print(nmap_report_str)
            report_data['Port Scan'] = {
                "Main Domain": nmap_report_str  # Add Nmap port scan results to report_data
            }
        except Exception as e:
            print(f"Error running Nmap on {target}: {e}")
            traceback.print_exc()

        # Run Nmap on subdomains if they exist
        if subdomains:
            logging.debug("\nRunning Nmap on subdomains...")
		        try:
		        print("\nRunning Nmap on subdomains...")
		        subdomain_all_open_ports, subdomain_all_vulnerabilities, subdomain_all_headers = portscan.run_nmap(subdomains,
		                                                                                                           only_vulners=True)
		        subdomain_nmap_data = {
		            'open_ports': subdomain_all_open_ports,
		            'vulnerabilities': subdomain_all_vulnerabilities,
		            'headers': subdomain_all_headers
		        }
		        # Add the subdomains Nmap scan results to the report_data
		        subdomain_nmap_report_str = portscan.print_report(subdomain_nmap_data)
		        print(subdomain_nmap_report_str)
		        report_data['Port Scan']['Subdomains'] = subdomain_nmap_report_str
            except Exception as e:
		 		print(f"Error running the selected scans: {e}")

    if args.debug:
        utils.enable_debugging()

    if args.encrypt_file:
        encryption.encrypt_existing_file(args.encrypt_file)
        return

    if args.decrypt:  # Check if the user wants to decrypt a file
        try:
        	encryption.decrypt_report(args.encrypted_file, args.decrypted_file, args.key)
        except Exception as e:
		 	print(f"Error: {e}")
        return  # Exit the program after decryption

    if args.output or args.all:
        if report_data:
            output_file = args.output
            encrypted_output_file = f"{args.output}_encrypted.txt"

            if encrypt_output:
                # Save encrypted report
                save_report(report_data, "txt", encrypted_output_file, encrypt_output=True)
                print(f"Encrypted report saved as {encrypted_output_file}")
                print(f"Encryption key: {encryption_key}")
            else:
                # Check if the user has provided an output format, if not, use the extension from the output_file
                if args.format:
                    file_format = args.format.lower()
                else:
                    file_format = args.output.split('.')[-1]

                # Save report in user-specified format
                save_report(report_data, file_format, output_file, graph_file=graph_file)
                print(f"\nReport saved as {output_file}")
        else:
            print("No previous scans were run. Please run OSINT or Vulnerabilty scans before generating reports!")
    return report_data

def main():
    global api_key
    args = parse_arguments()
    logging.debug("Parsed arguments: %s", args)

    config = configparser.ConfigParser()
    config.read("config.ini")

    num_scans = args.num_scans
    time_interval = args.time
    report_data = None

    if time_interval:
        for i in range(num_scans):
            report_data = run_scans(args)
            schedule.run_pending()
            time.sleep(1)

            if args.time:
                print(f"Scan {i + 1} completed.")
                if i < num_scans - 1:
                    print(f"Scheduling the next scan in {args.time} minutes.")
                    time.sleep(args.time * 60)  # Convert minutes to seconds
                else:
                    print("Ending the process.")
            if not report_data:
                print("No previous scans were run. Please run OSINT or Vulnerabilty scans before generating reports!")
    else:
        report_data = run_scans(args)


if __name__ == "__main__":
    main()
