# scopebuddy.py
A utility that accepts a file containing target hosts (IP or DNS, one per line) and provides details on the ownership of those hosts.

The ownership information is gathered from BGP and whois data.

## Intended use case
scopebuddy.py was written to quickly allow penetration testers to identify the ownership of a list of hosts to identify targets that are in/out of scope.

## Prep

* `pip install -r requirements.txt`
* `mv config.json.sample config.json`
* Edit config.json to add your Shodan API details

## Usage
`python3 scopebuddy.py hosts.txt [-c config.json] -o somefile`

## License Amendment
The software is distributed under GPL-2.0 with the amendment that ss23 is not permitted to use it.
