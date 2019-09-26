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

warnings.filterwarnings("ignore")

cache = {}
shodanCache = {}

parser = argparse.ArgumentParser()
parser.add_argument(
    "dnslist", help="A text file containing a list of domain names")
parser.add_argument("-s",
                    "--shodan", default=True, action="store_false", help="Disable Shodan search against discovered IP addresses")
parser.add_argument("-c",
                    "--config", default=f"{os.path.dirname(sys.argv[0])}/config.json", help="Provide a config file containing API keys for additional services (e.g. Shodan)")
args = parser.parse_args()
shodan_enable = args.shodan

if shodan_enable:
    try:
        with open(args.config, "r") as f:
            config = json.load(f)
            SHODAN_APIKEY = config["shodan"]
            shodan_enable = True
        api = shodan.Shodan(SHODAN_APIKEY)
    except FileNotFoundError as e:
        print(f"Config file doesn't exist. A sample file is included in the repository for this project. {e}")
        shodan_enable = False
        sys.exit(1)
    except KeyError:
        print(f"malformed config file - missing shodan api key")
        shodan_enable = False
        sys.exit(1)
    except Exception as e:
        print(f"Um this is well fucked eh: {e}")
        shodan_enable = False
        sys.exit(1)

def searchCache(ip):
    result = False

    for item in cache.keys():
        needle = ipaddress.ip_network(f'{ip}/32')
        haystack = ipaddress.ip_network(item)
        if (needle.subnet_of(haystack)):
            result = cache[item]

    return result

def searchIP(ip):
    # first we will need to search cache
    result = searchCache(ip)
    if (result == False):
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        if result["asn_cidr"] != "NA":
            cache[result["asn_cidr"]] = result
        else:  
            cache[result["network"]["cidr"]] = result

    return result

def getIP(d):
    """
    returns thinger of
    one or more IP address strings that respond
    as the given domain name
    """
    try:
        data = socket.gethostbyname_ex(d)
        ipx = data[2]
        return ipx
    except Exception:
        # fail gracefully!
        return False
#
def getRDNS(ip):
    """
        gets rdns, idk what you expect
    """
    try:
        data = socket.gethostbyaddr(ip)
        host = data[0]
        return host
    except Exception:
        # fail gracefully
        return "None"
#
def getCNAME(d):
    """
    This method returns an array containing
    a list of cnames for the domain
    """
    try:
        data = socket.gethostbyname_ex(d)
        alias = repr(data[1])
        return alias
    except Exception:
        # fail gracefully
        return False

def getIPOwner(ip):
    results = searchIP(ip)
    return results["network"]["name"]

def getIPHoster(ip):
    results = searchIP(ip)
    return results["asn_description"]

def getWhoisCIDR(ip):
    results = searchIP(ip)
    return results["asn_cidr"]

def getBGPCIDR(ip):
    results = searchIP(ip)
    return results["network"]["cidr"]

def getASN(ip):
    results = searchIP(ip)
    return results["asn"]

def shodan_search(ip):
    if ip in shodanCache.keys():
        return shodanCache[ip]
    else:
        try:
            host = api.host(ip)
            shodanCache[ip] = host
        except shodan.APIError:
            return None
        return host

def getShodanPorts(host):
    ports = (f'{item["port"]}({item["_shodan"]["module"]})' for item in host["data"])
    return ",".join(ports)

        
domains = [line.rstrip('\n') for line in open(args.dnslist)]
if shodan_enable:
    print(f'IP,DNS,RDNS,ASN,IP Hoster,IP Owner,BGP CIDR,Whois CIDR,Shodan Ports')
else:
    print(f'IP,DNS,RDNS,ASN,IP Hoster,IP Owner,BGP CIDR,Whois CIDR')

for domain in domains:
    time.sleep(0.01)
    data = getIP(domain)
    if data != False:
        for ip in data:
            try:
                if shodan_enable:
                    host = shodan_search(ip)
                    print(f'"{ip}","{domain}","{getRDNS(ip)}","{getASN(ip)}","{getIPHoster(ip)}","{getIPOwner(ip)}","{getBGPCIDR(ip)}","{getWhoisCIDR(ip)}","{getShodanPorts(host)}"')
                else:
                    print(f'"{ip}","{domain}","{getRDNS(ip)}","{getASN(ip)}","{getIPHoster(ip)}","{getIPOwner(ip)}","{getBGPCIDR(ip)}","{getWhoisCIDR(ip)}"')
            except:
                sys.stderr.write(f'Error:{ip} failed for some reason')
                pass


