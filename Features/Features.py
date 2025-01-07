from urllib.parse import urlparse, urlencode
import ipaddress
import re
import requests
from bs4 import BeautifulSoup
import whois
import math
from collections import Counter
from datetime import datetime
import ssl
import socket
import pandas as pd
import urllib
import urllib.request
import requests
import whois
from datetime import datetime
import tldextract

# 1.
def check_favicon(url):
    """
    Checks if a website has a favicon.
    Returns 0 if favicon is found (legit) and 1 if not found (phishing).
    """
    try:
        # Fetch the website's HTML
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an error for bad HTTP responses (4xx, 5xx)
        soup = BeautifulSoup(response.text, 'html.parser')
        favicon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if favicon and favicon.get("href"):
            return 0
        return 1
    except:
        return None

# 2.
def get_fullDomain(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Default to HTTP
    domain = urlparse(url).netloc
    return domain




# 3.Checks for IP address in URL (Have_IP)
def havingIP(url):
    try:
        ip_pattern = r"(?:(?:\d{1,3}\.){3}\d{1,3})|(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}"
        matches = re.findall(ip_pattern, url)

        for match in matches:
            try:
                ipaddress.ip_address(match)
                return 1
            except ValueError:
                continue
        return 0
    except:
        return None  # Return 0 on error

# 4.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
  if "@" in url:
    at = 1
  else:
    at = 0
  return at


# 5.
def check_robots_txt(url):
    """
    Checks if a website has a robots.txt file.
    Returns 0 if robots.txt exists (legit) and 1 if not found (phishing).
    """
    if not url.endswith('/'):
        url += '/'
    robots_url = url + "robots.txt"

    try:
        response = requests.get(robots_url, timeout=10)
        if response.status_code == 200:
            return 0  # Legit (robots.txt found)
        return 1  # Phishing (robots.txt not found)
    except:
        return None

# 6.Checking for redirection '//' in the url (Redirection)
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0



#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"


def tinyURL(url):
    match = re.search(r"https?://(www\\.)?([^/]+)", url)
    if match:
        domain = match.group(2)  # Extract domain name
        print("Domain:", domain)
        if re.search(shortening_services, domain):
            return 1  # URL is from a shortening service
    return 0  # URL is not from a shortening service

# # 11.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    match = re.search(r"https?://(www\\.)?([^/]+)", url)
    if match:
        domain = match.group(2)  # Extract domain name
        if '-' in domain:
            return 1            # phishing
        else:
            return 0            # legitimate
    else:
        return None
#
def domainAge(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date

        # Handle lists (multiple records for the same field)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        # Validate the presence of dates
        if creation_date is None or expiration_date is None:
            return 1

        # Ensure dates are datetime objects
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')

        # Calculate domain age
        domain_age_days = (expiration_date - creation_date).days

        if (domain_age_days/30) < 24:  # Approximation for months
            return 1
        else:
            return 0

    except whois.parser.PywhoisError:
        return 1  # No WHOIS record found
    except Exception as e:
        print(f"An error occurred for domain {domain}: {e}")
        return 1


# # 17.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
    try:
        response = requests.get(url, timeout=10)  # Set a timeout for safety
        if response == "":
            return 1
        else:
            if len(response.history) <= 2:
                return 0
            else:
                return 1
    except:
        return None

# 19.
def get_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        return [
            headers.get('X-Frame-Options', 'None'),
            headers.get('Strict-Transport-Security', 'None'),
            headers.get('Content-Security-Policy', 'None'),
            headers.get('X-XSS-Protection', 'None'),
            headers.get('X-Content-Type-Options', 'None'),
            headers.get('X-DNS-Prefetch-Control', 'None'),
            headers.get('Cross-Origin-Embedder-Policy', 'None'),
            headers.get('Cross-Origin-Opener-PolicyNone', 'None')
        ]
    except requests.exceptions.RequestException:
        return None

# 20.
def check_honeypot(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        hidden_fields = soup.find_all('input', {'type': 'hidden'})
        return len(hidden_fields) > 0
    except:
        return None

# 21.
def check_cookies(url):
    try:
        response = requests.get(url)
        return len(response.cookies) > 0
    except:
        return None

# 22.
def check_entropy_domain(url, threshold = 3.8):
    domain_e = get_fullDomain(url)
    try:
        if not domain_e:
            return None
        frequency = Counter(domain_e)
        total_characters = len(domain_e)
        entropy = -sum((freq / total_characters) * math.log2(freq / total_characters) for freq in frequency.values())
        return entropy > threshold
    except:
        return None

# 23.
import re


def evaluate_url_safety(url):
    try:
        unsafe_symbols = set("~ΑΒΓΔΕΖΗΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηικλμνξοπρσςτυφχψω")
        unsafe_symbols_count = sum(1 for char in url if char in unsafe_symbols)
        # If unsafe symbols are detected, the URL is flagged as phishing
        if unsafe_symbols_count < 1:
            return True
        else:
            return False
        # Character sets that are considered safe
        # always_safe = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~()'!*:@,;")
        # sometimes_safe_paths = set("+&=")
        # sometimes_safe_queries_fragments = set("?#+&=")
        # unsafe_characters = set("%<>[]{}|\^")

        # Count safe, sometimes safe, and unsafe characters
        # always_safe_count = sum(1 for char in url if char in always_safe)
        # sometimes_safe_count = sum(
        #     1 for char in url if char in sometimes_safe_paths or char in sometimes_safe_queries_fragments)
        # unsafe_count = sum(1 for char in url if char in unsafe_characters)

        # Check for unsafe Greek and Latin symbols

        # # Weights for the URL safety calculation
        # safe_weight = 5
        # sometimes_weight = 1
        # unsafe_weight = -8
        #
        # # Calculate the safety score (normalized)
        # score = ((always_safe_count * safe_weight) + (sometimes_safe_count * sometimes_weight) + (
        #             unsafe_count * unsafe_weight)) / (total_chars * safe_weight)
        # safety_percentage = max(0, min(1, score)) * 100
        # return round(safety_percentage, 2)
    except:
        return None

# 24.
def check_for_ads(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        iframes = soup.find_all('iframe')
        suspicious_ads = [iframe for iframe in iframes if 'ads' in iframe.get('src', '')]
        return len(suspicious_ads) > 0
    except:
        return None


def get_ssl_certificate(url):
    hostname = url.split("//")[-1].split("/")[0]
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            certificate = ssock.getpeercert()
    return certificate

def get_organization_name(certificate):
    issuer_info = certificate['issuer']

    for item in issuer_info:
        for sub_item in item:
            if sub_item[0] == 'organizationName':
                return sub_item[1]
    return None

# 26.
def is_free_certificate(url):
    try:
        free_cas = [
            "Let's Encrypt",
            "ZeroSSL",
            "Buypass",
            "SSL.com",
            "Actalis",
            "Cloudflare",
            "BuyPass",
            "StartCom",
            "WoSign",
            "Google Trust Services",
            "Amazon",
            "CAcert",
            "FreeSSL",
            "DigiCert (Free Trials)",
            "Certum",
            "SubCA",
            "Trustico",
            "ACME Certificate Authorities",
            "FreeSSL/TLS Certificates by Cloudflare",
            "Mozilla CA Certificate Program",
            "Comodo (Free Trials)",
            "SSL Mate",
            "R3",
            "Let’s Encrypt Staging",
            "Sectigo (Free Trials)",
            "Node.js Foundation",
            "GoDaddy (Free Trials)",
            "PositiveSSL (Free Trials)",
            "ComodoCA (Free Trials)"
        ]
        certificate = get_ssl_certificate(url=url)
        issuer = get_organization_name(certificate=certificate)
        for ca in free_cas:
            if ca in issuer:
                return True
        return False
    except:
        return None

# 29.
def check_caching_and_compression(url):
  caching_headers = [
    'Cache-Control',
    'Expires',
    'Last-Modified',
    'ETag',
    'Content-Encoding',
    'Pragma',
    'Vary',
    'Age',
    'Surrogate-Control',
    'Content-Disposition',
    'If-Modified-Since',
    'If-None-Match',
    'Accept-Encoding',
    'X-Cache',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
  ]

  try:
    response = requests.get(url)
    headers = response.headers

    caching_info_present = any(header in headers for header in caching_headers)
    is_compressed = 'Content-Encoding' in headers
    return caching_info_present, is_compressed
  except Exception as e:
    return False, False

