import sys
import argparse
import time
import uuid
import re
import os
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

try:
    from protos import audit_schema_pb2
except ImportError:
    print("Error: Protobuf definitions not found. Run compilation step.")
    sys.exit(1)

from pypi_client import PyPIClient
from detector import TyposquatDetector
from secure_logger import SecureLogger

console = Console()

BANNER = r"""
   _____ __            _____ __    _      __    __
  / ___// /___  ____  / ___// /_  (_)__  / /___/ /
  \__ \/ / __ \/ __ \ \__ \/ __ \/ / _ \/ / __  / 
 ___/ / / /_/ / /_/ /___/ / / / / /  __/ / /_/ /  
/____/_/\____/ .___//____/_/ /_/_/\___/_/\__,_/   
            /_/                                   
"""

def print_banner():
    text = Text(BANNER, style="bold cyan")
    panel = Panel(text, subtitle="Supply Chain Security Audit Tool", expand=False, border_style="blue")
    console.print(panel)

def parse_requirements_file(filepath):
    packages = []
    if not os.path.exists(filepath):
        console.print(f"[bold red]Error:[/bold red] File '{filepath}' not found.")
        return []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                match = re.match(r'^([a-zA-Z0-9_\-\.]+)', line)
                if match:
                    packages.append(match.group(1).lower())
    except Exception as e:
        console.print(f"[bold red]Error reading file:[/bold red] {e}")
        sys.exit(1)
        
    return packages

def run_audit(packages, save_path, password):
    print_banner()
    
    unique_packages = sorted(list(set(packages)))
    
    if not unique_packages:
        console.print("[yellow]No packages provided for audit. Use -f <file> or list packages manually.[/yellow]")
        return

    client = PyPIClient()
    detector = TyposquatDetector()
    
    report = audit_schema_pb2.AuditReport()
    report.id = str(uuid.uuid4())
    report.timestamp = int(time.time())
    report.tool_version = "1.2.0 (File Support)"
    current_time = datetime.now(timezone.utc)

    table = Table(title=f"Audit Results ({len(unique_packages)} packages)", show_header=True, header_style="bold magenta")
    table.add_column("Package", style="dim", width=20)
    table.add_column("Status", justify="center")
    table.add_column("Risk Level", justify="center")
    table.add_column("Details")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        
        task = progress.add_task("[green]Initializing scan...", total=len(unique_packages))

        for pkg_name in unique_packages:
            progress.update(task, description=f"Auditing [bold]{pkg_name}[/bold]...")
            
            pkg_info_proto = report.packages.add()
            pkg_info_proto.name = pkg_name
            
            status_text = ""
            risk_style = ""
            risk_text = ""
            details = ""

            # 1. Typosquatting Check
            typo_target = detector.check_typo(pkg_name)
            is_typo = False
            
            if typo_target:
                is_typo = True
                alert = report.alerts.add()
                alert.package_name = pkg_name
                alert.risk_type = "Typosquatting"
                alert.severity = "HIGH"
                alert.description = f"Impersonates {typo_target}"
                
                status_text = "Typosquat"
                risk_style = "bold red"
                risk_text = "HIGH"
                details = f"Similar to [bold underline]{typo_target}[/]"

            try:
                metadata = client.get_metadata(pkg_name)
            except Exception:
                table.add_row(pkg_name, "Error", "UNKNOWN", "Network connectivity issue", style="yellow")
                progress.advance(task)
                continue

            if metadata is None:
                pkg_info_proto.exists_in_registry = False
                alert = report.alerts.add()
                alert.package_name = pkg_name
                alert.risk_type = "Slopsquatting"
                alert.severity = "CRITICAL"
                alert.description = "Does not exist in PyPI"

                status_text = "Not Found"
                risk_style = "bold red reverse"
                risk_text = "CRITICAL"
                details = "Possible AI Hallucination"
                table.add_row(pkg_name, status_text, Text(risk_text, style=risk_style), details)
            
            else:
                pkg_info_proto.exists_in_registry = True
                info = metadata.get('info', {})
                pkg_info_proto.version = info.get('version', 'unknown')
                
                upload_dt = client.get_upload_time(metadata)
                
                if upload_dt:
                    pkg_info_proto.upload_time = upload_dt.isoformat()
                    age_days = (current_time - upload_dt).days
                    
                    if age_days < 7:
                        alert = report.alerts.add()
                        alert.package_name = pkg_name
                        alert.risk_type = "Fresh Package"
                        alert.severity = "WARNING"
                        alert.description = f"Age: {age_days} days"

                        if not is_typo:
                            status_text = "Fresh"
                            risk_style = "bold yellow"
                            risk_text = "WARNING"
                            details = f"Uploaded {age_days} days ago"
                        else:
                            details += f", Fresh ({age_days}d)"
                    else:
                        if not is_typo:
                            status_text = "Existing"
                            risk_style = "bold green"
                            risk_text = "SAFE"
                            details = f"Age: {age_days} days"
                else:
                    if not is_typo:
                        status_text = "Existing"
                        risk_style = "green"
                        risk_text = "SAFE"
                        details = "Date unknown"

                table.add_row(pkg_name, status_text, Text(risk_text, style=risk_style), details)
            
            time.sleep(0.05) 
            progress.advance(task)

    console.print(table)
    console.print()

    if save_path:
        if not password:
            console.print("[bold red]ERROR:[/bold red] --password is required to save the report.")
            sys.exit(1)
        
        with console.status("[bold cyan]Encrypting report...[/]"):
            try:
                logger = SecureLogger(password)
                serialized_data = report.SerializeToString()
                logger.save(serialized_data, save_path)
                
                console.print(Panel(
                    f"Report encrypted and saved to: [bold underline]{save_path}[/]\n"
                    f"Session ID: {report.id}",
                    title="Success",
                    border_style="green"
                ))
            except Exception as e:
                console.print(f"[bold red]Failed to save report:[/bold red] {e}")

def main():
    parser = argparse.ArgumentParser(description="SlopShield - Supply Chain Attack Detector")
    
    parser.add_argument("packages", nargs="*", help="List of packages to check")
    parser.add_argument("-f", "--file", help="Path to requirements.txt file")
    parser.add_argument("--save", help="Path to save encrypted Protobuf report")
    parser.add_argument("--password", help="Password for report encryption")
    
    args = parser.parse_args()
    
    all_packages = []
    
    if args.file:
        file_pkgs = parse_requirements_file(args.file)
        if file_pkgs:
            console.print(f"[blue]Loaded {len(file_pkgs)} packages from {args.file}[/blue]")
            all_packages.extend(file_pkgs)
    
    if args.packages:
        all_packages.extend(args.packages)
    
    run_audit(all_packages, args.save, args.password)

if __name__ == "__main__":
    main()