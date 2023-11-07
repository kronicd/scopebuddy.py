from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import argparse
import time
import socket
from ipwhois import IPWhois
import ipaddress
from pprint import pprint
import warnings
import shodan
import sys
import json
import os
import csv

warnings.filterwarnings("ignore")

cache = {}
shodan_cache = {}
last_ipwhois_timestamp = 0  # Initialize the timestamp

parser = argparse.ArgumentParser()
parser.add_argument("dnslist", help="A text file containing a list of domain names")
parser.add_argument("-s", "--shodan", default=True, action="store_false", help="Disable Shodan search against discovered IP addresses")
parser.add_argument("-c", "--config", default="config.json", help="Provide a config file containing API keys for additional services (e.g. Shodan)")
parser.add_argument("-o", "--output", default="-", help="Output file")
parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose output")
args = parser.parse_args()
shodan_enable = args.shodan
verbose = args.verbose
output = args.output

if shodan_enable:
    try:
        with open(args.config, "r") as f:
            config = json.load(f)
            SHODAN_APIKEY = config.get("shodan")
        api = shodan.Shodan(SHODAN_APIKEY)
    except FileNotFoundError as e:
        print(f"Config file doesn't exist. A sample file is included in the repository for this project. {e}")
        shodan_enable = False
        sys.exit(1)
    except KeyError:
        print("Malformed config file - missing Shodan API key")
        shodan_enable = False
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        shodan_enable = False
        sys.exit(1)

@contextmanager
def open_or_stdout(filename):
    if filename != '-':
        with open(filename, 'w') as f:
            yield f
    else:
        yield sys.stdout

def search_cache(ip):
    for item in cache.keys():
        needle = ipaddress.ip_network(f'{ip}/32')
        haystack = ipaddress.ip_network(item)
        if needle.subnet_of(haystack):
            return cache[item]
    return False

def search_ip(ip):
    global last_ipwhois_timestamp  # Use the global timestamp variable
    result = search_cache(ip)
    current_timestamp = time.time()
    
    if result == False:
        try:
            if current_timestamp - last_ipwhois_timestamp < 2:
                time.sleep(2 - (current_timestamp - last_ipwhois_timestamp))
            obj = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)
            cache[result.get("asn_cidr", result["network"]["cidr"])] = result
            last_ipwhois_timestamp = time.time()  # Update the timestamp
        except:
            return "Failed"
    return result

def get_ip(d):
    try:
        data = socket.gethostbyname_ex(d)
        ipx = data[2]
        if verbose:
            print(f'[+] Domain {d}, IP: {ipx}')
        return ipx
    except Exception:
        if verbose:
            print(f'[-] Could not resolve domain {d}')
        return False

def get_rdns(ip):
    try:
        data = socket.gethostbyaddr(ip)
        host = data[0]
        if verbose:
            print(f'[+] IP: {ip}, RDNS {host}')
        return host
    except Exception:
        if verbose:
            print(f'[-] No RDNS found for {ip}')
        return "None"

def get_cname(d):
    try:
        data = socket.gethostbyname_ex(d)
        alias = repr(data[1])
        if verbose:
            print(f'[+] Domain: {d}, CNAME {alias}')
        return alias
    except Exception:
        if verbose:
            print(f'[-] No CNAME found for {d}')
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
        return shodan_cache[ip]
    else:
        try:
            host = api.host(ip)
            shodan_cache[ip] = host
        except shodan.APIError:
            return None
        return host

def get_shodan_ports(host):
    try:
        ports = (f'{item["port"]}({item["_shodan"]["module"]})' for item in host["data"])
        return ",".join(ports)
    except:
        return "No Data/Failed"

def process_domain(domain):
    data = get_ip(domain)
    if data:
        results = []
        for ip in data:
            result = {
                "IP": ip,
                "DNS": domain,
                "RDNS": get_rdns(ip),
                "ASN": get_asn(ip),
                "IP Hoster": get_ip_hoster(ip),
                "IP Owner": get_ip_owner(ip),
                "BGP CIDR": get_bgp_cidr(ip),
                "Whois CIDR": get_whois_cidr(ip)
            }
            if shodan_enable:
                host = shodan_search(ip)
                result["Shodan Ports"] = get_shodan_ports(host)
            results.append(result)
        return results
    else:
        return []  # Return an empty list when no IP address is associated with the domain


def main():
    domains = [line.rstrip('\n') for line in open(args.dnslist)]
    
    with open_or_stdout(output) as f:
        writer = csv.writer(f)
        
        if shodan_enable:
            writer.writerow(["IP", "DNS", "RDNS", "ASN", "IP Hoster", "IP Owner", "BGP CIDR", "Whois CIDR", "Shodan Ports"])
        else:
            writer.writerow(["IP", "DNS", "RDNS", "ASN", "IP Hoster", "IP Owner", "BGP CIDR", "Whois CIDR"])
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            for domain in domains:
                domain = domain.strip()
                results = executor.submit(process_domain, domain)
                for result in results.result():
                    row = [result["IP"], result["DNS"], result["RDNS"], result["ASN"], result["IP Hoster"], result["IP Owner"], result["BGP CIDR"], result["Whois CIDR"]]
                    if shodan_enable:
                        row.append(result.get("Shodan Ports", "No Data/Failed"))
                    writer.writerow(row)

if __name__ == "__main__":
    main()