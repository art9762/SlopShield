import sys
import argparse
import time
import uuid
import os

from datetime import datetime, timezone

import requests

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
from input_requirements import package_name, parse_requirements_file

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

def run_audit(packages, save_path, password):
    if save_path and not password:
        console.print("[bold red]ERROR:[/bold red] --password or SLOPSHIELD_PASSWORD is required to save the report.")
        return 2
    try:
        unique_packages = sorted({package_name(pkg) for pkg in packages})
    except ValueError as exc:
        console.print(str(exc), style="red", markup=False)
        return 2

    print_banner()
    
    if not unique_packages:
        console.print("[yellow]No packages provided for audit. Use -f <file> or list packages manually.[/yellow]")
        return 2

    client = PyPIClient()
    detector = TyposquatDetector()
    
    report = audit_schema_pb2.AuditReport()
    report.id = str(uuid.uuid4())
    report.timestamp = int(time.time())
    report.tool_version = "1.3.0 (CI Gate)"
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
            except (requests.RequestException, ValueError) as exc:
                alert = report.alerts.add()
                alert.package_name = pkg_name
                alert.risk_type = "Registry Error"
                alert.severity = "ERROR"
                alert.description = f"Registry lookup incomplete: {exc}"
                table.add_row(pkg_name, "Error", "UNKNOWN", "Registry lookup incomplete", style="yellow")
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
                info = metadata['info']
                pkg_info_proto.version = info['version']
                
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
                            details = f"Latest release uploaded {age_days} days ago"
                        else:
                            details += f", Fresh ({age_days}d)"
                    else:
                        if not is_typo:
                            status_text = "Existing"
                            risk_style = "bold green"
                            risk_text = "LOW"
                            details = f"Latest release age: {age_days} days"
                else:
                    alert = report.alerts.add()
                    alert.package_name = pkg_name
                    alert.risk_type = "Unknown Release Age"
                    alert.severity = "WARNING"
                    alert.description = "Latest release upload date is unavailable"
                    if not is_typo:
                        status_text = "Unknown Age"
                        risk_style = "yellow"
                        risk_text = "WARNING"
                        details = "Latest release date unavailable"

                table.add_row(pkg_name, status_text, Text(risk_text, style=risk_style), details)
            
            progress.advance(task)

    console.print(table)
    console.print()

    if save_path:
        with console.status("[bold cyan]Encrypting report...[/]"):
            try:
                logger = SecureLogger(password)
                serialized_data = report.SerializeToString()
                logger.save(serialized_data, save_path)
                
                console.print(Panel(
                    Text(f"Report encrypted and saved to: {save_path}\nSession ID: {report.id}"),
                    title="Success",
                    border_style="green"
                ))
            except (OSError, ValueError) as exc:
                console.print(f"Failed to save report: {exc}", style="red", markup=False)
                return 2

    if any(alert.severity == "ERROR" for alert in report.alerts):
        return 2
    return 1 if report.alerts else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="SlopShield - Supply Chain Attack Detector")
    
    parser.add_argument("packages", nargs="*", help="List of packages to check")
    parser.add_argument("-f", "--file", help="Path to requirements.txt file")
    parser.add_argument("--save", help="Path to save encrypted Protobuf report")
    parser.add_argument("--password", help="Report password (prefer SLOPSHIELD_PASSWORD environment variable)")
    
    args = parser.parse_args(argv)
    
    all_packages = []
    
    if args.file:
        try:
            file_pkgs = parse_requirements_file(args.file)
        except ValueError as exc:
            parser.error(str(exc))
        if file_pkgs:
            console.print(f"Loaded {len(file_pkgs)} packages from {args.file}", style="blue", markup=False)
            all_packages.extend(file_pkgs)
    
    if args.packages:
        all_packages.extend(args.packages)
    
    return run_audit(all_packages, args.save, args.password or os.environ.get("SLOPSHIELD_PASSWORD"))

if __name__ == "__main__":
    sys.exit(main())
