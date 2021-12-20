from collections import defaultdict
import socket
import ssl
import tldextract
import urllib3
urllib3.disable_warnings()
import requests
import time

print("")
print("[*] - Importing domains from input.txt...\n")

hostname = [line.rstrip('\n') for line in open('input.txt')]
subjectAltName = defaultdict(set)
alreadychecked = []
primarydomains = []

def getrealurl(url):
    try:
        geturl = requests.get("https://"+url, verify=False, allow_redirects=False, timeout=2)
        domainextract = tldextract.extract(geturl.url)
        if domainextract.subdomain:
            domain = domainextract.subdomain + "." + domainextract.domain + "." + domainextract.suffix
        elif sum(c.isdigit() for c in url) > 4:
            domain = domainextract.domain
        else:
            domain = domainextract.domain + "." + domainextract.suffix
        getsslcertsan(domain)
    except:
        ""


def getsslcertsan(url_input):
    if url_input not in alreadychecked:
        alreadychecked.append(url_input)
    else:
        return


    print("[*] - Running SSL_Links against %s" % url_input)
    #try:
    context = ssl.create_default_context()
    context.check_hostname = False
    with socket.create_connection((url_input, 443)) as sock:
        sock.settimeout(3)
        with context.wrap_socket(sock, server_hostname=url_input) as ssock:
            # https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.getpeercert
            cert = ssock.getpeercert()

    #subject = dict(item[0] for item in cert['subject'])

    for type_, san in cert['subjectAltName']:
        subjectAltName[type_].add("[%s] - %s" % (url_input, san))
        tld = tldextract.extract(san).domain + "." + tldextract.extract(san).suffix
        primarydomains.append(tld)
    #except:
        #pass


for url in hostname:
    getrealurl(url)


if len(subjectAltName) > 0:
    print("\n[*] Result set")
    print("---------------")

    for i in sorted(set(subjectAltName['DNS'])):
        print(i)

if len(primarydomains) > 0:
    print("\n[*] - Top level primary domains discovered [%s]" % len(sorted(set(primarydomains))))
    print("-----------------------------------------------")
    for x in sorted(set(primarydomains)):
        print(x)

print("")
