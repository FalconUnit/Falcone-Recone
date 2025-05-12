from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import pdfkit
import os

def generate_report(title, content, domain):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    env = Environment(loader=FileSystemLoader(os.path.dirname(__file__)))

    template = env.get_template("template.html")

    html_content = template.render(
        domain=domain,
        data_type=title,
        data_content=content,
        timestamp=timestamp,
        team_name="Falcon Recon Team",
        analyst="Automated Analysis"
    )

    with open("output/report.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    path_to_wkhtmltopdf = r'C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe'
    config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)
    pdfkit.from_file("output/report.html", "output/report.pdf", configuration=config)
