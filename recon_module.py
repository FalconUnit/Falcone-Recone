import whois
import dns.resolver
import requests
import socket
import nmap
import subprocess
import os

# 1. WHOIS Lookup
def get_whois(domain):
    try:
        w = whois.whois(domain)
        return w.text
    except:
        return "WHOIS data not found."

# 2. DNS Records
def get_dns(domain):
    records = {}
    for record_type in ['A', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [r.to_text() for r in answers]
        except:
            records[record_type] = ['No data found']
    return records

# 3. HTTP Headers
def get_headers(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)
        return dict(response.headers)
    except:
        return {"Error": "Could not retrieve headers."}

# 4. Port Scanner
def scan_ports(domain):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(domain, arguments='-T4 -F')
        result = {}
        for host in scanner.all_hosts():
            result[host] = []
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    state = scanner[host][proto][port]['state']
                    name = scanner[host][proto][port]['name']
                    result[host].append(f"Port {port} ({name}): {state}")
        return result
    except Exception as e:
        return {"error": str(e)}

# 5. Subdomain Enumeration (using Sublist3r)
def find_subdomains_sublist3r(domain):
    try:
        if not os.path.exists("output"):
            os.makedirs("output")
        subprocess.run([
            "python", "Sublist3r/sublist3r.py", "-d", domain, "-o", "output/subdomains.txt"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open("output/subdomains.txt", "r", encoding="utf-8") as f:
            subdomains = f.read().splitlines()
        return subdomains if subdomains else ["No subdomains found."]
    except Exception as e:
        return [f"Error: {str(e)}"]

# 6. Technology Fingerprinting
def detect_technologies(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=10)
        headers = response.headers
        body = response.text.lower()
        findings = []
        fingerprints = {
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
            "joomla": ["joomla", "index.php?option=com"],
            "drupal": ["sites/all", "drupal"],
            "magento": ["mage", "magento"],
            "shopify": ["cdn.shopify.com", "x-shopify-stage"],
            "laravel": ["laravel_session", "laravel"],
            "cloudflare": ["cloudflare"],
            "nginx": ["nginx"],
            "apache": ["apache"],
            "iis": ["microsoft-iis"],
            "react": ["react", "main.jsx", "app.jsx"],
            "vue": ["vue", "main.js", "app.vue"],
            "django": ["csrftoken", "django"],
            "symfony": ["symfony"]
        }
        for tech, keywords in fingerprints.items():
            for keyword in keywords:
                if keyword in body or keyword in headers.get("Server", "").lower() or keyword in headers.get("X-Powered-By", "").lower():
                    findings.append(f"Detected: {tech.title()} (via keyword '{keyword}')")
                    break
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        if not findings:
            if server:
                findings.append(f"Server Header: {server}")
            if powered:
                findings.append(f"Powered By: {powered}")
        return findings if findings else ["No technology detected."]
    except Exception as e:
        return [f"Error: {str(e)}"]

# 7. OWASP Security Check
def owasp_security_check(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=10)
        headers = response.headers
        findings = []
        security_headers = {
            "Content-Security-Policy": "CSP",
            "Strict-Transport-Security": "HSTS",
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "Referrer-Policy": "Referrer Policy",
            "Permissions-Policy": "Permissions Policy"
        }
        for header, desc in security_headers.items():
            if header in headers:
                findings.append(f"[✓] {header} present – {desc}")
            else:
                findings.append(f"[X] {header} missing – {desc}")
        robots = requests.get(f"http://{domain}/robots.txt")
        if robots.status_code == 200:
            findings.append("[!] Found: robots.txt is accessible")
        for path in ["/admin", "/login", "/cpanel"]:
            try:
                check = requests.get(f"http://{domain}{path}", timeout=5)
                if check.status_code == 200:
                    findings.append(f"[!] Accessible admin path found: {path}")
            except:
                continue
        return findings
    except Exception as e:
        return [f"Error: {str(e)}"]
