#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from ipwhois import IPWhois
from pprint import pprint
import argparse
import csv
import dns.resolver
import ipaddress
import json
import os
import pyasn
import requests
import shodan
import socket
import subprocess
import sys
import threading
import time
import warnings
import ipaddress
import shutil 


warnings.filterwarnings("ignore")

cache = {}
shodan_cache = {}
cymru_asn_cache = {}
rdns_cache = {}
last_ipwhois_timestamp = 0  # Initialize the timestamp
lock = threading.Lock()

parser = argparse.ArgumentParser()
parser.add_argument("dnslist", help="A text file containing a list of domain names")
parser.add_argument("-s", "--shodan", default=True, action="store_false", help="Disable Shodan search against discovered IP addresses")
parser.add_argument("-w", "--whois", default=False, action="store_true", help="Enable WHOIS functionality for IP ownership, this will slow things down dramatically")
parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default 20)")
parser.add_argument("-o", "--output", default="-", help="Output file")
parser.add_argument("-v", "--verbose", default=0, action="count", help="Increase verbosity level (use -v for normal verbosity, -vv for more verbosity)")
args = parser.parse_args()
shodan_enable = args.shodan
whois_enable = args.whois
num_threads = args.threads
verbose = args.verbose
output = args.output

max_domains_per_thread = 1000

@contextmanager
def open_or_stdout(filename):
    if filename != '-':
        with open(filename, 'w') as f:
            yield f
    else:
        yield sys.stdout

def print_debug(output, level):
    if verbose >= level:
        sys.stderr.write(f"{output}\n")
        sys.stderr.flush()

def check_required_files():
    required_files = ['pyasn_util_download.py', 'pyasn_util_convert.py']
    local_bin_path = os.path.expanduser("~/.local/bin/")
    file_paths = {}
    for file in required_files:
        file_path = shutil.which(file) or os.path.join(local_bin_path, file)
        if not os.path.isfile(file_path):
            sys.stderr.write(f"")
            print_debug(f"[!] Error: Required file '{file}' not found in the path.\n", 0)
            print_debug(f'[!] pyasn (https://github.com/hadiasghari/pyasn/) is missing or incorrectly installed.\n', 0)
            sys.stderr.write(f"")
            sys.exit(1)
        else:
            print_debug(f"Found '{file}' at '{file_path}'.\n",2)
            file_paths[file] = file_path
    return file_paths

# Function to download and convert BGP data using pyasn utilities
def download_and_convert_bgp_data(cache_dir, pyasn_util_download, pyasn_util_convert):
    db_path = os.path.join(cache_dir, "ipasn.json")
    dump_path = os.path.join(cache_dir, "latest.bz2")
    file_age = time.time() - os.path.getmtime(db_path) if os.path.exists(db_path) else None

    if not file_age or file_age >= 6 * 3600:
        # Download the BGP data dump if it doesn't exist or is older than 6 hours
        print(f"[*] Downloading BGP data dump as cached copy is not present or is older than 6 hours")
        download_command = f"{pyasn_util_download} --latestv46 --filename {dump_path}"
        print_debug(f'[*] Running {download_command}', 2)
        if verbose == False:
            subprocess.run(download_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(download_command, shell=True)
        print(f"[*] Download of BGP data dump complete")

        # Convert the BGP data to the pyasn format
        print(f"[*] Converting BGP data dump to pyasn format")
        convert_command = f"{pyasn_util_convert} --single {dump_path} {db_path}"
        print_debug(f'[*] Running {convert_command}', 2)
        if verbose == False:
            subprocess.run(convert_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(convert_command, shell=True)
        print(f"[*] Conversion of BGP data dump complete")

    return pyasn.pyasn(db_path)

def get_asn_bgpdb(ip, asndb):
    asn, _ = asndb.lookup(ip)
    return asn

def get_cidr_bgpdb(ip, asndb):
    _, cidr = asndb.lookup(ip)
    return cidr


def search_cymru_cache(asn_number):

    if asn_number in cymru_asn_cache.keys():
        print_debug(f"[*] Cache hit for ASN: {asn_number}", 2)
        return cymru_asn_cache[asn_number]
    else:
        print_debug(f"[*] Cache miss for ASN: {asn_number}", 2)
        return False

def get_asn_name_cymru(ip, asndb):


    asn_number = get_asn_bgpdb(ip, asndb)
    result = search_cymru_cache(asn_number)

    if result:
        return result

    try:
        asn_query = f"AS{asn_number}.asn.cymru.com"
        answers = dns.resolver.resolve(asn_query, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                txt_string = txt_string.decode("utf-8")  # Decode bytes to string
                if txt_string.startswith(f"{asn_number} |"):
                    asn_name = txt_string.split("|")[-1].strip()
                    cymru_asn_cache[asn_number] = asn_name
                    return asn_name
    
    except Exception as e:
        return "No Data/Failed"

    return None


def search_cache(ip):
    ip_network = ipaddress.ip_network(ip)

    for item in cache.keys():
        item_network = ipaddress.ip_network(item)
        if ip_network.overlaps(item_network):
            print_debug(f"[*] Cache hit for IP: {ip}", 2)
            return cache[item]

    print_debug(f"[*] Cache miss for IP: {ip}", 2)
    return False


def search_ip(ip):
    global last_ipwhois_timestamp  # Use the global timestamp variable
    result = search_cache(ip)
    
    if result == False:
        with lock:
            try:
                current_timestamp = time.time()
                if (current_timestamp - last_ipwhois_timestamp) < 5:
                    sleeptime = 5 - (current_timestamp - last_ipwhois_timestamp)
                    print_debug(f"[*] Sleeping for {sleeptime} to avoid whois rate limits", 1)
                    time.sleep(sleeptime)
                obj = IPWhois(ip)
                result = obj.lookup_rdap(depth=1)
                cache[result.get("asn_cidr", result["network"]["cidr"])] = result
                last_ipwhois_timestamp = time.time()  # Update the timestamp
            except:
                return "Failed"
    return result

def get_ip(d):

    ipv4_addresses = []
    ipv6_addresses = []

    # Resolve IPv4 addresses
    try:
        answers_ipv4 = dns.resolver.resolve(d, 'A')
        ipv4_addresses = [rdata.address for rdata in answers_ipv4]
    except:
        pass  # No IPv4 addresses found

    # Resolve IPv6 addresses
    try:
        answers_ipv6 = dns.resolver.resolve(d, 'AAAA')
        ipv6_addresses = [rdata.address for rdata in answers_ipv6]
    except:
        pass  # No IPv6 addresses found

    ip_addresses = ipv4_addresses + ipv6_addresses

    if len(ip_addresses) == 0:
        print_debug(f'[-] Could not resolve domain {d}', 1)
    else:
        print_debug(f'[+] Domain {d}, IP: {ip_addresses}', 1)

    return ip_addresses




def search_rnds_cache(ip):

    if ip in rdns_cache.keys():
        print_debug(f"[*] Cache hit for RDNS: {ip}", 2)
        return rdns_cache[ip]
    else:
        print_debug(f"[*] Cache miss for RDNS: {ip}", 2)
        return False


def get_rdns(ip):
    result = search_rnds_cache(ip)

    if result:
        return result

    try:
        addr_type = socket.AF_INET if '.' in ip else socket.AF_INET6
        data = socket.gethostbyaddr(ip, addr_type)
        host = data[0]
        print_debug(f'[+] IP: {ip}, RDNS {host}', 1)
        rdns_cache[ip] = host
        return host
    except Exception:
        print_debug(f'[-] No RDNS found for {ip}', 1)
        rdns_cache[ip] = "None"
        return "None"


def get_cname(d):
    try:
        data = socket.gethostbyname_ex(d)
        alias = repr(data[1])
        print_debug(f'[+] Domain: {d}, CNAME {alias}', 1)
        return alias
    except Exception:
        print_debug(f'[-] No CNAME found for {d}', 1)
        return False

def get_ip_owner(ip):
    try:
        results = search_ip(ip)
        return results.get("network", {}).get("name", "No Data/Failed")
    except:
        return "No Data/Failed"

def get_ip_hoster(ip):
    try:
        results = search_ip(ip)
        return results.get("asn_description", "No Data/Failed")
    except:
        return "No Data/Failed"

def get_whois_cidr(ip):
    try:
        results = search_ip(ip)
        return results.get("asn_cidr", "No Data/Failed")
    except:
        return "No Data/Failed"

def get_bgp_cidr(ip):
    try:
        results = search_ip(ip)
        return results["network"]["cidr"]
    except:
        return "No Data/Failed"

def get_asn(ip):
    try:
        results = search_ip(ip)
        return results.get("asn", "No Data/Failed")
    except:
        return "No Data/Failed"

def shodan_search(ip):
    if ip in shodan_cache.keys():
        print_debug(f"[*] Cache hit for Shodan: {ip}", 2)
        return shodan_cache[ip]
    else:
        print_debug(f"[*] Cache miss for Shodan: {ip}", 2)
        try:
            # Use Shodan internetdb to get information for the given IP
            response = requests.get(f'https://internetdb.shodan.io/{ip}')
            if response.status_code == 200:
                data = response.json()
                shodan_cache[ip] = data
                return data
            else:
                print_debug(f"[-] Shodan API request failed for IP: {ip}", 1)
        except Exception as e:
            print_debug(f"[-] Error occurred while querying Shodan API: {e}", 1)
    return None


def get_shodan_ports(host):
    try:
        ports = host['ports']
        ports = ", ".join(map(str, ports))
        return ports
    except:
        return "No Data/Failed"


def check_if_ipv4(domain):
    try:
        ipaddress.IPv4Network(domain)
        return True
    except ValueError:
        return False


def check_if_ipv6(domain):
    try:
        ipaddress.IPv6Network(domain)
        return True
    except ValueError:
        return False


def process_domains(domains, asndb, whois_enabled):
    thread_id = threading.get_ident()
    print_debug(f'[*] Thread {thread_id} processing {len(domains)} domains', 2)
    
    results = []
    domains_chunk = domains[:max_domains_per_thread]  # Limit the number of domains processed by each thread
    for domain in domains_chunk:
        domain = domain.strip()

        data = []

        if (check_if_ipv4(domain)):
            data.append(domain)
        elif (check_if_ipv6(domain)):
            data.append(domain)
        else:
            data = get_ip(domain)

        if data:
            for ip in data:
                result = {
                    "IP": ip,
                    "DNS": domain,
                    "RDNS": get_rdns(ip),
                    "ASN": get_asn_bgpdb(ip, asndb),
                    "IP Hoster": get_asn_name_cymru(ip, asndb),
                    "BGP CIDR": get_cidr_bgpdb(ip, asndb)
                }
                if whois_enabled:
                    result["IP Owner"] = get_ip_owner(ip)
                    result["Whois CIDR"] = get_whois_cidr(ip)
                if shodan_enable:
                    host = shodan_search(ip)
                    result["Shodan Ports"] = get_shodan_ports(host)
                results.append(result)

    return results, thread_id  # Return the thread ID along with results

# Modify the main function to use ThreadPoolExecutor dynamically
def main():

    file_paths = check_required_files()

    cache_dir = os.path.expanduser("~/.cache/scopebuddy/ipasn")
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)

    # Download and convert BGP data
    asndb = download_and_convert_bgp_data(cache_dir, file_paths['pyasn_util_download.py'], file_paths['pyasn_util_convert.py'])

    domains = [line.rstrip('\n') for line in open(args.dnslist)]

    with open_or_stdout(output) as f:
        writer = csv.writer(f)

        header = ["IP", "DNS", "RDNS", "ASN", "IP Hoster", "BGP CIDR"]
        if whois_enable:
            header.append("IP Owner")
            header.append("Whois CIDR")
        if shodan_enable:
            header.append("Shodan Ports")
        writer.writerow(header)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            thread_results = []  # List to collect thread results and IDs
            for i in range(0, len(domains), max_domains_per_thread):
                domains_chunk = domains[i:i + max_domains_per_thread]
                result = executor.submit(process_domains, domains_chunk, asndb, whois_enable)
                thread_results.append(result)  # Collect thread results

            for result in thread_results:
                results, thread_id = result.result()
                for result in results:
                    row = [result["IP"], result["DNS"], result["RDNS"], result["ASN"], result["IP Hoster"], result["BGP CIDR"]]
                    if whois_enable:
                        row.append(result["IP Owner"])
                        row.append(result["Whois CIDR"])
                    if shodan_enable:
                        row.append(result["Shodan Ports"])
                    writer.writerow(row)

if __name__ == "__main__":
    main()