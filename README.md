# Subdomain Reconnaisance Scanner
A security tool to scan a domain to gather information. Useful for information gathering when potentially many subdomains are in use.

This tool will do the following:
 1. Check nameservers for the entire domain chain, searching for unregistered servers, which could lead to domain takeover
 2. Search for subdomains using [DNSDumpster](https://dnsdumpster.com/)
 3. Screenshot each subdomain
 4. Search for any information shodan has on the subdomain's IP (requires a free shodan API key)

## Installation
The project requires python3 with pipenv (pip install pipenv if you don't have it)

Clone the repository to your computer. You will need a chrome webdriver to enable screenshots - download the latest to the subdomain_recon/chrome directory from the [chrome webdriver](https://chromedriver.chromium.org/downloads) downloads page.

You can now install the dependencies with pipenv
```bash
pipenv install
```

## Running the program
If you want to use shodan, set the SHODAN_API in your environment variables, though this is not required.

```bash
export SHODAN_API=<your api>
pipenv run python subdomain_recon.py example.com
```

The program will generate an html report for viewing.