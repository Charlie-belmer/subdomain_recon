import sys
import dns
import dns.name
import dns.query
import dns.resolver
from dns import reversename
import os
import shutil
from urllib.parse import urlparse
import requests
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
import shodan
import socket
import whois
from whois.parser import PywhoisError

if len(sys.argv) != 2:
    print("Usage: subdomain_recon.py <domain>")
    sys.exit(0)

domain_to_check = sys.argv[1]
name_server = os.environ.get('DNS_NAME_SERVER', '8.8.8.8')
shodan_api_key = os.environ.get('SHODAN_API', False)
api = None
if not shodan_api_key:
    print("Not integrating with Shodan. To search shodan, set your SHODAN_API environment variable with your API key (Free tier should be enough).")
else:
    api = shodan.Shodan(shodan_api_key)


def domain_details(domain):
    ''' Return dictionary of domain name, IP, and reverse DNS'''
    details = {}
    details['domain'] = domain
    details['ip'] = str(socket.gethostbyname(domain))
    details['reverse_dns'] = str(reversename.from_address(details['ip']))
    return details


def can_register(domain):
    ''' True if the domain is currently unregistered'''
    try:
        whois.whois(str(domain))
        return False
    except PywhoisError:
        return True


def list_ns(domain):
    ''' Return a list of name servers for the given domain'''
    q = dns.message.make_query(domain, dns.rdatatype.NS)
    r = dns.query.udp(q, name_server)
    if r.rcode() == dns.rcode.NOERROR and len(r.answer) > 0:
        return r.answer[0].items
    return []


def get_ns_registration_status(domain, depth=2):
    ''' Check registration status of all name servers.
    Depth of 2 will check TLD's such as .com or .info,
    3 or higher skips TLD
    '''
    domain = dns.name.from_text(domain)
    done = False
    nameservers = {}
    while not done:
        s = domain.split(depth)

        done = s[0].to_unicode() == u'@'
        subdomain = s[1]

        nss = list_ns(subdomain)
        for ns in nss:
            print(f"Checking name server {ns} for {subdomain}...")
            nameservers[ns.to_text()] = "registered"
            if can_register(ns):
                nameservers[ns.to_text()] = "UNREGISTERED"
        depth += 1
    return nameservers


def screenshot_url(url, savepath):
    cdriver = "chrome/chromedriver"
    filename = f"{savepath}/{urlparse(url).hostname}.png"

    driver = webdriver.Chrome(cdriver)
    driver.set_page_load_timeout(15)
    timeout = False
    try:
        driver.get(url)
        screenshot = driver.save_screenshot(filename)
    except TimeoutException:
        timeout = True
    finally:
        driver.quit()
    return (filename, timeout)


def shodan_data(ip):
    if api is None:
        return ("", False)
    try:
        host = api.host(ip)
        return (host, True)
    except shodan.APIError as e:
        return (str(e), False)


def find_subdomains(domain):
    results = DNSDumpsterAPI({'verbose': True}).search(domain)
    subdomains = [domain_details(domain)]
    if len(results) > 0:
        subdomains.extend(results['dns_records']['host'])
    return subdomains


def html_report(domain, nameservers, subdomain_data):
    html = f"""
    <html>
    <body>
    <h1> Report for {domain}</h1>
    <h2> Nameservers </h2>"""
    for ns, status in nameservers.items():
        html += f"<b>{ns}</b>: {status} <br />"
    html += "<h2> Subdomain Search Results</h2>"
    for subdomain in subdomain_data:
        html += f"""
            <h3>{subdomain['domain']}</h3>
            <p>{subdomain['ip']} / {subdomain['reverse_dns']} </p>
        """
        keys = ['ports', 'product', 'cpe', 'opts', 'error', 'os', 'isp']
        html += "<div>"
        host, success = subdomain['shodan']
        if success:
            for key in keys:
                if key in host.keys():
                    html += f"<b>{key}</b>: {host[key]} <br />"
        else:
            html += f"<p>{host}</p>"
        html += "</div>"
        img, to = subdomain['img']
        if to:
            html += f"""<p> Page load timed out</p>"""
        else:
            html += f"""<img src="{img}" height="500" width="500"/>"""
    html += "</body></html>"
    return html


if __name__ == "__main__":
    # Create a folder to store results
    try:
        shutil.rmtree(domain_to_check)
    except FileNotFoundError:
        pass    # folder doesn't exist, no problem
    os.mkdir(domain_to_check)
    print(f"Checking {domain_to_check} for subdomains and takeover opportunities...")
    print(f"Searching for unregistered name servers...")
    nss = get_ns_registration_status(domain_to_check)
    for ns, r in nss.items():
        if not r:
            print(f"\t Nameserver {ns} not registered!")
    print(f"Searching for subdomains...")
    subdomains = find_subdomains(domain_to_check)
    print(f"\tFound {len(subdomains) - 1} subdomains")
    for subd in subdomains:
        subd['shodan'] = shodan_data(subd['ip'])
        subd['img'] = screenshot_url("http://" + subd['domain'], domain_to_check)

    html = html_report(domain_to_check, nss, subdomains)
    fh = open(domain_to_check + ".html", 'w')
    fh.write(html)
    fh.close()
    print(f"Wrote report to {domain_to_check}.html")