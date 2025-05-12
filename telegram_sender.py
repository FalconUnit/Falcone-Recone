import requests
from rich import print

def send_to_telegram(file_path, token, chat_id):
    try:
        with open(file_path, "rb") as f:
            files = {"document": f}
            url = f"https://api.telegram.org/bot{token}/sendDocument"
            data = {"chat_id": chat_id}
            response = requests.post(url, data=data, files=files)

        if response.status_code == 200:
            print("[bold green]✔ Report sent successfully to Telegram![/bold green]")
        else:
            print(f"[bold red]✖ Failed to send report. Status code: {response.status_code}[/bold red]")
    except Exception as e:
        print(f"[bold red]✖ Error sending report: {str(e)}[/bold red]")
