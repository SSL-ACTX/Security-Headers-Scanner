import argparse
import re
from curl_cffi import requests
from urllib.parse import quote_plus
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

#█████████████████████████████████████████████████████
#█                                                   █
#█ ███████╗███████╗██╗   ██╗██████╗ ██╗██╗███╗   ██╗ █
#█ ██╔════╝██╔════╝██║   ██║██╔══██╗██║██║████╗  ██║ █
#█ ███████╗█████╗  ██║   ██║██████╔╝██║██║██╔██╗ ██║ █
#█ ╚════██║██╔══╝  ██║   ██║██╔══██╗██║██║██║╚██╗██║ █
#█ ███████║███████╗╚██████╔╝██║  ██║██║██║██║ ╚████║ █
#█ ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝╚═╝  ╚═══╝ █
#█          Created by SSL-ACTX (Seuriin)            █
#█████████████████████████████████████████████████████

console = Console()

# Precompiled regex patterns (faster) - for summary cleaningg
RMV_ADVTXT = re.compile(
    r"(Perform a deeper security analysis of (your|the) (website|site) and APIs:?|let’s perform a deeper security analysis of (your|the) site and APIs:?)[\s]*",
    re.IGNORECASE
)
RNM_ADV = re.compile(r"^Advanced[:]*", re.IGNORECASE)

def getSecHeadReport(targetURL):
    """Fetch security headers report"""
    baseURL = 'https://securityheaders.com/'
    scanURL = f'{baseURL}?q={quote_plus(targetURL)}&followRedirects=on'
    headers = {'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'}

    try:
        session = requests.Session()
        response = session.get(scanURL, headers=headers, impersonate="chrome110") # must have, this script won't work if no impersonation :/

        if response.status_code != 200:
            console.print(f"[bold red]❌ ERROR:[/bold red] URL scan failed. Status: {response.status_code}")
            return None

        soup = BeautifulSoup(response.text, 'html.parser')
        report_data = {
            'grade': xtGrade(soup),
            'security_headers': xtGradeStatus(soup),
            'summary': cleanSumm(xtTabData(soup, 'Security Report Summary')),
            'raw_headers': xtTabData(soup, 'Raw Headers')
        }

        return report_data
    except Exception as e:
        console.print(f"[bold red]❌ ERROR:[/bold red] Failed to fetch data: {str(e)}")
        return None

def xtGrade(soup):
    """Extracts the security grade from the report"""
    score_div = soup.find('div', class_='score')
    return score_div.find('span').text.strip() if score_div else "N/A"

def xtGradeStatus(soup):
    """Extracts the security headers and their status"""
    hdrStatus = {}
    for item in soup.find_all('li', class_='headerItem'):
        name = item.text.strip()
        is_present = "pill-green" in item.get("class", [])
        hdrStatus[name] = "[green]✅ Present[/green]" if is_present else "[red]❌ Missing[/red]"
    return hdrStatus

def xtTabData(soup, section_title):
    """Extracts table data from a given report section"""
    for section in soup.find_all('div', class_='reportSection'):
        title = section.find('div', class_='reportTitle', string=section_title)
        if title:
            body = section.find('div', class_='reportBody')
            if body:
                table = body.find('table', class_='reportTable')
                if table:
                    return {
                        row.find('th', class_='tableLabel').text.strip().replace(':', ''):
                        " ".join(row.find('td', class_='tableCell').stripped_strings)
                        for row in table.find('tbody').find_all('tr', class_='tableRow')
                    }
    return {}

def cleanSumm(summary):
    """Summary Cleaner"""
    cleanedSumm = {}
    for key, value in summary.items():
        new_key = RNM_ADV.sub("Comment", key)
        new_value = RMV_ADVTXT.sub("", value).strip()
        new_value = new_value.rstrip(":,. ")

        # skip if header
        if not new_key.lower().startswith("headers"):
            cleanedSumm[new_key] = new_value

    return cleanedSumm

def genGradeArt(grade):
    """Cool ASCII art for the grade scores :)"""
    asciiGrades = {
        "A+": ["\t █████     ", "\t██   ██  █ ", "\t███████ ███", "\t██   ██  █ ", "\t██   ██    "],
        "A":  ["\t █████  ", "\t██   ██ ", "\t███████ ", "\t██   ██ ", "\t██   ██ "],
        "B":  ["\t█████  ", "\t██  ██ ", "\t█████  ", "\t██  ██ ", "\t█████  "],
        "C":  ["\t ██████ ", "\t██      ", "\t██      ", "\t██      ", "\t ██████ "],
        "D":  ["\t██████  ", "\t██   ██ ", "\t██   ██ ", "\t██   ██ ", "\t██████  "],
        "E":  ["\t███████ ", "\t██      ", "\t██████  ", "\t██      ", "\t███████ "],
        "F":  ["\t███████ ", "\t██      ", "\t█████   ", "\t██      ", "\t██      "],
        "R":  ["\t██████  ", "\t██   ██ ", "\t█████   ", "\t██  ██  ", "\t██   ██ "]
    }
    return "\n".join(asciiGrades.get(grade.strip().upper(), [f" {grade} "]))

def displayReport(report):
    """Formats and displays the security headers report"""
    console.print(Panel(Text("🔍 SECURITY HEADERS REPORT", justify="center", style="bold cyan"), expand=False))

    # Display Grade w/ ASCII Art
    grade = report.get('grade', 'N/A')
    gradeColor = "green" if grade in ["A", "A+"] else "yellow" if grade in ["B", "C"] else "red"
    console.print(f"\n[bold {gradeColor}]\n{genGradeArt(grade)}[/bold {gradeColor}]\n")

    # Security Headers Table
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Header", style="cyan", justify="left")
    table.add_column("Status", style="bold", justify="center")

    for header, status in report.get('security_headers', {}).items():
        table.add_row(header, status)

    console.print(table)

    # Summary -->
    console.print("\n📊 [bold]Summary:[/bold]", style="yellow")
    summary = report.get('summary', {})
    if summary:
        for label, value in summary.items():
            console.print(f"  [cyan]{label}:[/cyan] {value}")
    else:
        console.print("  ⚠️ No summary data found.")

    # Raw Headers -->
    console.print("\n📜 [bold]Raw Headers:[/bold]", style="magenta")
    raw_headers = report.get('raw_headers', {})
    if raw_headers:
        for label, value in raw_headers.items():
            console.print(f"  [cyan]{label}:[/cyan] {value}")
    else:
        console.print("  ⚠️ No raw headers data found.")

    console.print("\n" + "="*50)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a website for security headers.")
    parser.add_argument("url", help="Target website URL")
    args = parser.parse_args()

    report = getSecHeadReport(args.url)
    if report:
        displayReport(report)
    else:
        console.print("\n[bold red]❌ Failed to retrieve security headers report.[/bold red]")
