# scopebuddy.py
A utility that accepts a file containing target hosts (IP or DNS, one per line) and provides details on the ownership of those hosts.

The ownership information is gathered from BGP and whois data.

## Intended use case
scopebuddy.py was written to quickly allow penetration testers to identify the ownership of a list of hosts to identify targets that are in/out of scope.