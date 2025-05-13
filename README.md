

# 🛡️ Falcon Recon Tool

**Falcon Recon** is a powerful terminal-based cybersecurity reconnaissance and web analysis tool developed by **Falcon Unit**.  
It allows users to perform deep scans, discover vulnerabilities, generate professional PDF/HTML reports, and even **send results to their own Telegram bot**.

---

## 🚀 Features

### 🔍 Phase 1: Reconnaissance
- WHOIS Lookup
- DNS Records Collection
- HTTP Header Inspection
- Port Scanning (Nmap)
- Subdomain Enumeration (Sublist3r)
- Technology Fingerprinting (CMS, Servers, Frameworks)
- OWASP-Based Security Header Check

### 🔎 Phase 2: Deep Web Application Analysis
- Common Path Discovery
- Admin Panel Finder
- Sensitive File Scanner
- CMS Signature Detection
- Shell File Detection
- WAF (Web Application Firewall) Detection

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/falcon-recon.git
cd falcon-recon
pip install -r requirements.txt
```

Make sure you have:
- Python 3.8+
- `nmap` installed
- `wkhtmltopdf` installed and path configured in `report_generator.py`

---

## 🧪 Usage

```bash
python main.py
```

- Follow the prompt to choose a **scan section**.
- Run specific modules or full scan modes.
- View results directly in the terminal.
- Choose to **generate a report**, and **send it to your Telegram bot**.

---

## 📬 Telegram Bot Integration

At the end of any scan, Falcon Recon asks if you'd like to send the report to your Telegram bot.  
To use this feature:

1. Create a bot via [BotFather](https://t.me/botfather)
2. Get your bot token and chat ID
3. Enter them when prompted

> ✔ This makes Falcon Recon great for remote reporting and monitoring.

---

## 📂 Folder Structure

```
falcon-recon/
│
├── main.py                 → Main launcher
├── recon_module.py         → Recon functions
├── deep_module.py          → Web analysis modules
├── report_generator.py     → Generates HTML/PDF reports
├── telegram_sender.py      → Sends reports to Telegram
├── wordlists/              → Wordlist dictionary files
├── output/                 → Stores generated reports
├── Sublist3r/              → Subdomain enumeration engine
├── template.html           → Report structure
└── requirements.txt
```

---

## 🔗 Community

Join our channel for updates, improvements, and discussions:  
👉 [https://t.me/falcounit](https://t.me/falcounit)

---

## 🧠 License & Legal

This tool is for educational and authorized penetration testing only.  
You are fully responsible for using it on legal targets.

---

## 🛡 Developed by
**Falcon Unit – Cybersecurity Intelligence**
