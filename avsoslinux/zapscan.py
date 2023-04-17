import time
from zapv2 import ZAPv2
import subprocess
import utils
import matplotlib.pyplot as plt
import datetime
import logging
import sys

logging.basicConfig(filename="zapscan.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def start_zap(zap_path):
    python_executable = sys.executable
    zap_process = subprocess.Popen([python_executable, zap_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Sleep for a specified duration to give ZAP time to start
    time.sleep(150)
    return zap_process

def progress_bar(current, total, bar_size=40, bar_char_done="#", bar_char_todo="-", bar_percentage_scale=2):
    # Display a progress bar for a given process.
    percent = 100 * current / total
    done = int(bar_size * percent / 100)
    todo = int(bar_size - done)

    done_sub_bar = bar_char_done * done
    todo_sub_bar = bar_char_todo * todo

    msg = "Progress"
    print(f"\r{msg}: [{done_sub_bar}{todo_sub_bar}] {percent:.{bar_percentage_scale}f}%", end='')

    if total == current:
        print("\nDONE")

def run_zap_scan(url, api_key=None, subdomains=None): # Run a ZAP spider and active scan on a URL and its subdomains.
    # Add http:// or https:// to the URL if it doesn't have it
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    if not api_key:
        api_key = utils.get_zap_api_key()
        
    # Initialize ZAP API connection
    zap = ZAPv2(apikey=api_key, proxies={'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'})

    # Start ZAP
    print('Accessing target URL...')
    urls_to_scan = [url]  # Initialize the list of URLs to scan with the main URL
    
    if subdomains:  # Add subdomains to the list of URLs to scan
        for subdomain in subdomains:
            # Add http:// or https:// to the subdomain if it doesn't have it
            if not subdomain.startswith('http://') and not subdomain.startswith('https://'):
                subdomain = 'http://' + subdomain
            urls_to_scan.append(subdomain)
            
    for url_to_scan in urls_to_scan: # Access and scan each url to the list
        try:
            zap.urlopen(url_to_scan)
            time.sleep(2)
        except Exception as e:
            logging.exception(f"Error accessing {url_to_scan}: {e}")
	
    ascan_scan_ids = []
    spider_scan_ids = []

    for url_to_scan in urls_to_scan:
        print(f'Starting ZAP Spider for {url_to_scan}...')
        try:
            scan_id = zap.spider.scan(url_to_scan)
            print(f'Spider scan ID: {scan_id}')
            spider_scan_ids.append(scan_id)
        except Exception as e:
            logging.error(f"Error starting ZAP Spider for {url_to_scan}: {e}")

    all_spider_scans_completed = False
    while not all_spider_scans_completed:
        all_spider_scans_completed = True
        for scan_id in spider_scan_ids:
            try:
                progress = int(zap.spider.status(scan_id))
                progress_bar(progress, 100)
                if progress < 100:
                    all_spider_scans_completed = False
            except ValueError:
                logging.error(f"Error: Spider scan status could not be determined for scan ID {scan_id}.")
                all_spider_scans_completed = False
        time.sleep(5)

    for url_to_scan in urls_to_scan:
        print(f'Starting ZAP Active Scan for {url_to_scan}...')
        try:
            if scan_policy:
                scan_id = zap.ascan.scan(url_to_scan, scanpolicyname=scan_policy)
            else:
                scan_id = zap.ascan.scan(url_to_scan)
            ascan_scan_ids.append(scan_id)
        except Exception as e:
            logging.error(f"Error starting ZAP Active Scan for {url_to_scan}: {e}")

    all_ascan_scans_completed = False
    while not all_ascan_scans_completed:
        all_ascan_scans_completed = True
        for scan_id in ascan_scan_ids:
            progress = int(zap.ascan.status(scan_id))
            progress_bar(progress, 100)
            if progress < 100:
                all_ascan_scans_completed = False
        time.sleep(5)

    return zap

def plot_graph(severity_counts, graph_file):
    # Plot a bar graph of the severity frequencies.
    fig, ax = plt.subplots()
    ax.bar(severity_counts.keys(), severity_counts.values())
    ax.set_xlabel('Severity')
    ax.set_ylabel('Frequency')
    ax.set_title('Severity by Frequency')

    plt.savefig(graph_file)

def zap_report(zap):
    # Report findings
    alerts = zap.core.alerts()
    results = []
    seen_alerts = set()
    
    for alert in alerts:
        alert_name = alert.get('alert')
        alert_url = alert.get('url')
        
        if (alert_name, alert_url) not in seen_alerts:
            seen_alerts.add((alert_name, alert_url))
            result = {'Alert': alert_name, 'Risk': alert.get('risk'), 'URL': alert_url,
                      'Description': alert.get('description'), 'Solution': alert.get('solution')}
            results.append(result)

    # Format the results as a string
    output_str = ""
    for result in results:
        output_str += f"Alert: {result['Alert']}\n"
        output_str += f"Risk: {result['Risk']}\n"
        output_str += f"URL: {result['URL']}\n"
        output_str += f"Description: {result['Description']}\n"
        output_str += f"Solution: {result['Solution']}\n"
        output_str += "\n" + "=" * 80 + "\n\n"

    return output_str, alerts
