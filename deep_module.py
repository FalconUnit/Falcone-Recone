import os
import requests
import time
from rich import print

def load_wordlist(file_name):
    path = os.path.join("wordlists", file_name)
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def print_status(url, status_code):
    if status_code == 200:
        print(f"[green][200] {url}[/green]")
    elif status_code in [401, 403]:
        print(f"[yellow][{status_code}] {url}[/yellow]")
    else:
        print(f"[red][{status_code}] {url}[/red]")

def path_discovery(domain):
    paths = load_wordlist("common_paths.txt")
    found = []
    for path in paths:
        url = f"http://{domain}/{path}"
        try:
            r = requests.get(url, timeout=5)
            print_status(url, r.status_code)
            if r.status_code == 200:
                found.append(f"[\u2713] Found: {url}")
        except Exception as e:
            print(f"[red]Error: {url} – {str(e)}[/red]")
        time.sleep(1)
    return found if found else ["No paths found."]

def admin_panel_finder(domain):
    panels = load_wordlist("admin_panels.txt")
    found = []
    for panel in panels:
        url = f"http://{domain}/{panel}"
        try:
            r = requests.get(url, timeout=5)
            print_status(url, r.status_code)
            if r.status_code == 200:
                found.append(f"[\u2713] Admin Panel: {url}")
        except Exception as e:
            print(f"[red]Error: {url} – {str(e)}[/red]")
        time.sleep(1)
    return found if found else ["No admin panels found."]

def sensitive_file_scanner(domain):
    files = load_wordlist("sensitive_files.txt")
    found = []
    for file in files:
        url = f"http://{domain}/{file}"
        try:
            r = requests.get(url, timeout=5)
            print_status(url, r.status_code)
            if r.status_code == 200:
                found.append(f"[\u2713] Sensitive File: {url}")
        except Exception as e:
            print(f"[red]Error: {url} – {str(e)}[/red]")
        time.sleep(1)
    return found if found else ["No sensitive files found."]

def cms_vuln_checker(domain):
    sigs = load_wordlist("cms_signatures.txt")
    try:
        r = requests.get(f"http://{domain}", timeout=10)
        body = r.text.lower()
        matches = []
        for sig in sigs:
            if sig.lower() in body:
                matches.append(f"[!] Detected CMS signature: {sig}")
        return matches if matches else ["No CMS fingerprints matched."]
    except Exception as e:
        return [f"Error: {str(e)}"]

def shell_file_scanner(domain):
    shells = load_wordlist("shell_files.txt")
    found = []
    for shell in shells:
        url = f"http://{domain}/{shell}"
        try:
            r = requests.get(url, timeout=5)
            print_status(url, r.status_code)
            if r.status_code == 200:
                found.append(f"[\u2713] Shell File Detected: {url}")
        except Exception as e:
            print(f"[red]Error: {url} – {str(e)}[/red]")
        time.sleep(1)
    return found if found else ["No shell files found."]

def waf_detection(domain):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        r = requests.get(f"http://{domain}", headers=headers, timeout=5)
        waf_headers = ["Server", "X-Security", "X-Powered-By", "X-CDN"]
        detected = []
        for header in waf_headers:
            if header in r.headers:
                detected.append(f"[!] Potential WAF header detected: {header}: {r.headers[header]}")
        return detected if detected else ["No WAF signatures detected."]
    except Exception as e:
        return [f"Error: {str(e)}"]
