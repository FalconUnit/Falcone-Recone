from rich import print
from rich.prompt import Prompt
from rich.console import Console
from rich.panel import Panel
from recon_module import *
from deep_module import *
from report_generator import generate_report
from telegram_sender import send_to_telegram
from datetime import datetime
import os

console = Console()

def show_banner():
    banner = r"""
 _   _____/____  |  |   ____  ____   ____   \______   \ ____  ____  ____  ____  
 |    __) \__  \ |  | _/ ___\/  _ \ /    \   |       _// __ \/ ___\/  _ \ /    \ 
 |     \   / __ \|  |_\  \__(  <_> )   |  \  |    |   \  ___|  \__(  <_> )   |  \
 \___  /  (____  /____/\___  >____/|___|  /  |____|_  /\___  >___  >____/|___|  /
     \/        \/          \/           \/          \/     \/    \/           \/
                          Falcon Recon Tool – v1.1
"""
    console.print(f"[bold cyan]{banner}[/bold cyan]", justify="center")

def welcome_message():
    console.print(Panel.fit(
        "[bold yellow]Welcome to Falcon Recon Tool![/bold yellow]\n"
        "Your personal reconnaissance assistant.",
        title="👋 Welcome"
    ))

def ask_to_generate_report(title, content, domain):
    confirm = Prompt.ask("\nDo you want to generate a report for this scan? (Y/N)", default="N")
    if confirm.lower() == 'y':
        generate_report(title, content, domain)
        console.print("[green]\n✔ Report generated in output folder[/green]")
        send = Prompt.ask("Do you want to send the report to Telegram? (Y/N)", default="N")
        if send.lower() == 'y':
            token = Prompt.ask("Enter your Bot Token")
            chat_id = Prompt.ask("Enter your Chat ID")
            send_to_telegram("output/report.pdf", token, chat_id)

def handle_result(title, result, domain):
    console.print(result)
    ask_to_generate_report(title, result, domain)
    restart = Prompt.ask("\nDo you want to go back to the main menu? (Y/N)", default="N")
    if restart.lower() == 'y':
        main()
    else:
        console.print("\n[bold green]Thanks for using Falcon Recon Tool! Goodbye 👋[/bold green]")
        exit()

def main():
    show_banner()
    welcome_message()

    domain = Prompt.ask("[bold green]Enter the target domain[/bold green]").replace("http://", "").replace("https://", "")

    console.print("\n[bold magenta]Choose a section:[/bold magenta]")
    console.print("[cyan]1.[/cyan] Reconnaissance")
    console.print("[cyan]2.[/cyan] Web Application Deep Analysis\n")
    section = Prompt.ask("[bold yellow]Enter your choice (1/2)[/bold yellow]")

    if section == '1':
        console.print("\n[bold magenta]Choose an option:[/bold magenta]")
        console.print("[cyan]1.[/cyan] WHOIS Lookup")
        console.print("[cyan]2.[/cyan] DNS Records")
        console.print("[cyan]3.[/cyan] HTTP Headers")
        console.print("[cyan]4.[/cyan] Port Scanner")
        console.print("[cyan]5.[/cyan] Subdomain Scanner")
        console.print("[cyan]6.[/cyan] Technology Fingerprint")
        console.print("[cyan]7.[/cyan] OWASP Security Check")
        console.print("[cyan]8.[/cyan] Run ALL Recon Checks\n")
        choice = Prompt.ask("[bold yellow]Enter your choice (1–8)[/bold yellow]")

        recon_choices = {
            '1': ("WHOIS Information", get_whois),
            '2': ("DNS Records", get_dns),
            '3': ("HTTP Headers", get_headers),
            '4': ("Port Scan", scan_ports),
            '5': ("Subdomain Enumeration", find_subdomains_sublist3r),
            '6': ("Technology Fingerprinting", detect_technologies),
            '7': ("OWASP Security Check", owasp_security_check)
        }

        if choice in recon_choices:
            title, func = recon_choices[choice]
            console.print(f"\n[bold green]Running {title}...[/bold green]")
            result = func(domain)
            handle_result(title, result, domain)

        elif choice == '8':
            console.print("\n[bold green]Running all Reconnaissance checks...[/bold green]")
            all_data = {
                "WHOIS Information": get_whois(domain),
                "DNS Records": get_dns(domain),
                "HTTP Headers": get_headers(domain),
                "Port Scan": scan_ports(domain),
                "Subdomain Enumeration": find_subdomains_sublist3r(domain),
                "Technology Fingerprinting": detect_technologies(domain),
                "OWASP Security Check": owasp_security_check(domain)
            }
            for title, content in all_data.items():
                console.print(f"\n[bold blue]{title}[/bold blue]\n{content}")
            ask_to_generate_report("Full Recon Report", all_data, domain)
            restart = Prompt.ask("\nDo you want to go back to the main menu? (Y/N)", default="N")
            if restart.lower() == 'y':
                main()
            else:
                console.print("\n[bold green]Thanks for using Falcon Recon Tool! Goodbye 👋[/bold green]")
                exit()

    elif section == '2':
        console.print("\n[bold magenta]Choose an option:[/bold magenta]")
        console.print("[cyan]9.[/cyan] Path Discovery")
        console.print("[cyan]10.[/cyan] Admin Panel Finder")
        console.print("[cyan]11.[/cyan] Sensitive File Scanner")
        console.print("[cyan]12.[/cyan] CMS Vulnerability Overview")
        console.print("[cyan]13.[/cyan] Shell File Detection")
        console.print("[cyan]14.[/cyan] WAF Detection")
        console.print("[cyan]15.[/cyan] Run ALL Deep Analysis Checks\n")
        choice = Prompt.ask("[bold yellow]Enter your choice (9–15)[/bold yellow]")

        deep_choices = {
            '9': ("Path Discovery", path_discovery),
            '10': ("Admin Panel Finder", admin_panel_finder),
            '11': ("Sensitive File Scanner", sensitive_file_scanner),
            '12': ("CMS Vulnerability Overview", cms_vuln_checker),
            '13': ("Shell File Detection", shell_file_scanner),
            '14': ("WAF Detection", waf_detection)
        }

        if choice in deep_choices:
            title, func = deep_choices[choice]
            console.print(f"\n[bold green]Running {title}...[/bold green]")
            result = func(domain)
            handle_result(title, result, domain)

        elif choice == '15':
            console.print("\n[bold green]Running all Deep Analysis checks...[/bold green]")
            all_data = {
                "Path Discovery": path_discovery(domain),
                "Admin Panel Finder": admin_panel_finder(domain),
                "Sensitive File Scanner": sensitive_file_scanner(domain),
                "CMS Vulnerability Overview": cms_vuln_checker(domain),
                "Shell File Detection": shell_file_scanner(domain),
                "WAF Detection": waf_detection(domain)
            }
            for title, content in all_data.items():
                console.print(f"\n[bold blue]{title}[/bold blue]\n{content}")
            ask_to_generate_report("Full Deep Analysis Report", all_data, domain)
            restart = Prompt.ask("\nDo you want to go back to the main menu? (Y/N)", default="N")
            if restart.lower() == 'y':
                main()
            else:
                console.print("\n[bold green]Thanks for using Falcon Recon Tool! Goodbye 👋[/bold green]")
                exit()

if __name__ == "__main__":
    try:
        while True:
            main()
            restart = Prompt.ask("\nDo you want to perform another scan? (Y/N)", default="N")
            if restart.lower() != 'y':
                console.print("\n[bold green]Thanks for using Falcon Recon Tool! Goodbye 👋[/bold green]")
                break
    except KeyboardInterrupt:
        console.print("\n\n[bold red]⛔ Scan interrupted by user (CTRL+C).[/bold red]")
        console.print("[yellow]You can restart the tool anytime to run a new scan.[/yellow]")
        console.print("[cyan]Exiting...[/cyan]")
