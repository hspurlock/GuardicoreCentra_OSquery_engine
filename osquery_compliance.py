#!/usr/bin/env python3
"""
OSQuery-Compliance: A Python CLI application that uses osquery to assess 
DOD STIG (Security Technical Implementation Guide) compliance for a running system.
"""

import os
import sys
import json
import yaml
import platform
import subprocess
import click
from datetime import datetime
from tabulate import tabulate
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from colorama import Fore, Style

console = Console()

def run_osquery(query, silent=False):
    """Run an osquery query and return the results as JSON."""
    try:
        result = subprocess.run(
            ["osqueryi", "--json", query],
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit code
        )
        
        if result.returncode != 0:
            if not silent:
                console.print(f"[bold yellow]Warning: osquery returned non-zero exit code for query: {query}[/bold yellow]")
                console.print(f"[dim]{result.stderr.strip()}[/dim]")
            return []
        
        if not result.stdout.strip():
            return []
            
        return json.loads(result.stdout)
    except subprocess.SubprocessError as e:
        if not silent:
            console.print(f"[bold red]Error running osquery: {e}[/bold red]")
        return []
    except json.JSONDecodeError as e:
        if not silent:
            console.print(f"[bold red]Error decoding JSON from osquery output: {e}[/bold red]")
            console.print(f"[dim]Output: {result.stdout}[/dim]")
        return []

def get_os_type():
    """Detect the operating system type."""
    system = platform.system().lower()
    if system == 'linux':
        return 'linux'
    elif system == 'windows':
        return 'windows'
    elif system == 'darwin':
        return 'macos'
    else:
        return 'unknown'

def load_stig_checks(check_dir=None, os_type=None):
    """Load STIG checks from YAML files in the stig_checks directory for the specified OS."""
    checks = []
    
    # Determine the OS type if not specified
    if os_type is None:
        os_type = get_os_type()
    
    # Set the base checks directory
    if check_dir is None:
        base_check_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stig_checks')
    else:
        base_check_dir = check_dir
    
    # Set the OS-specific checks directory
    os_check_dir = os.path.join(base_check_dir, os_type)
    
    # If OS-specific directory doesn't exist, fall back to base directory
    if not os.path.exists(os_check_dir):
        console.print(f"[bold yellow]OS-specific STIG checks directory not found: {os_check_dir}[/bold yellow]")
        console.print(f"[bold yellow]Falling back to base directory: {base_check_dir}[/bold yellow]")
        check_dir = base_check_dir
    else:
        check_dir = os_check_dir
    
    if not os.path.exists(check_dir):
        console.print(f"[bold yellow]STIG checks directory not found: {check_dir}[/bold yellow]")
        return checks
    
    # Load checks from the directory
    for filename in os.listdir(check_dir):
        if filename.endswith('.yaml') or filename.endswith('.yml'):
            with open(os.path.join(check_dir, filename), 'r') as f:
                try:
                    check_data = yaml.safe_load(f)
                    checks.extend(check_data.get('checks', []))
                except yaml.YAMLError as e:
                    console.print(f"[bold red]Error parsing YAML file {filename}: {e}[/bold red]")
    
    return checks

def run_compliance_check(check, verbose=False):
    """Run a single compliance check and return the results."""
    check_id = check.get('id', 'unknown')
    query = check.get('query')
    if not query:
        return {
            'id': check_id,
            'title': check.get('title', 'Unknown check'),
            'status': 'error',
            'message': 'No query defined for this check',
            'results': []
        }
    
    if verbose:
        console.print(f"Running query for check {check_id}: [italic]{query}[/italic]")
    
    # Use silent mode for osquery to avoid cluttering output
    results = run_osquery(query, silent=not verbose)
    
    # Apply the compliance check logic
    compliant = True
    message = "System is compliant with this check"
    
    # Check if we have a condition to evaluate
    condition = check.get('condition', {})
    if condition:
        condition_type = condition.get('type')
        field = condition.get('field')
        value = condition.get('value')
        
        if condition_type and field:
            # Special handling for 'count' field which might be a meta-check
            if field == 'count' and not any(field in result for result in results if results):
                # If checking for count and no results have a count field,
                # we're probably checking for the number of results
                count = len(results)
                if condition_type == 'equals' and str(count) != str(value):
                    compliant = False
                    message = f"Expected {count} results, got {value}"
                elif condition_type == 'not_equals' and str(count) == str(value):
                    compliant = False
                    message = f"Expected not {value} results, but got exactly that"
            elif not results:
                compliant = False
                message = "No results returned from query"
            else:
                # For normal field checks in results
                for result in results:
                    if field not in result:
                        if verbose:
                            console.print(f"[yellow]Warning: Field '{field}' not found in result: {result}[/yellow]")
                        continue
                    
                    if condition_type == 'equals':
                        if str(result[field]) != str(value):
                            compliant = False
                            message = f"Expected {field} to be '{value}', got '{result[field]}'"
                            break
                    elif condition_type == 'not_equals':
                        if str(result[field]) == str(value):
                            compliant = False
                            message = f"{field} should not be '{value}'"
                            break
                    elif condition_type == 'contains':
                        if str(value) not in str(result[field]):
                            compliant = False
                            message = f"{field} should contain '{value}'"
                            break
                    elif condition_type == 'not_contains':
                        if str(value) in str(result[field]):
                            compliant = False
                            message = f"{field} should not contain '{value}'"
                            break
                    elif condition_type == 'greater_than':
                        try:
                            if float(result[field]) <= float(value):
                                compliant = False
                                message = f"{field} should be greater than {value}"
                                break
                        except ValueError:
                            compliant = False
                            message = f"Could not compare {field} as a number"
                            break
                    elif condition_type == 'less_than':
                        try:
                            if float(result[field]) >= float(value):
                                compliant = False
                                message = f"{field} should be less than {value}"
                                break
                        except ValueError:
                            compliant = False
                            message = f"Could not compare {field} as a number"
                            break
    
    return {
        'id': check_id,
        'title': check.get('title', 'Unknown check'),
        'description': check.get('description', ''),
        'severity': check.get('severity', 'medium'),
        'status': 'compliant' if compliant else 'non-compliant',
        'message': message,
        'results': results
    }

def print_check_result(result, verbose=False):
    """Print the result of a compliance check."""
    status_color = "[green]" if result['status'] == 'compliant' else "[red]"
    status_icon = "✓" if result['status'] == 'compliant' else "✗"
    
    console.print(f"{status_color}{status_icon}[/] [bold]{result['id']}[/bold]: {result['title']}")
    console.print(f"  Severity: {result['severity'].upper()}")
    console.print(f"  Status: {status_color}{result['status'].upper()}[/]")
    console.print(f"  Message: {result['message']}")
    
    if verbose and result['results']:
        console.print("  Results:")
        table = Table(show_header=True)
        
        # Add columns dynamically based on the first result
        if result['results']:
            for key in result['results'][0].keys():
                table.add_column(key)
            
            # Add rows
            for row in result['results']:
                table.add_row(*[str(row.get(key, '')) for key in result['results'][0].keys()])
            
            console.print(table)
    
    console.print("")

def generate_report(results, output_file=None):
    """Generate a compliance report."""
    # Create a report
    report_lines = []
    report_lines.append("DOD STIG Compliance Report")
    report_lines.append("========================")
    report_lines.append("")
    
    # Add system information
    os_info = run_osquery("SELECT * FROM os_version")
    system_info = run_osquery("SELECT hostname, uuid FROM system_info")
    
    if system_info:
        report_lines.append(f"Hostname: {system_info[0].get('hostname', 'Unknown')}")
    if os_info:
        report_lines.append(f"OS: {os_info[0].get('name', 'Unknown')} {os_info[0].get('version', 'Unknown')}")
    
    report_lines.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("")
    
    # Add compliance summary
    compliant_count = sum(1 for r in results if r['status'] == 'compliant')
    total_count = len(results)
    compliance_percentage = (compliant_count / total_count) * 100 if total_count > 0 else 0
    
    report_lines.append(f"Compliance Summary: {compliant_count}/{total_count} checks passed ({compliance_percentage:.1f}%)")
    report_lines.append("")
    
    # Add detailed results
    report_lines.append("Detailed Results:")
    report_lines.append("================")
    report_lines.append("")
    
    table_data = []
    for result in results:
        status_symbol = "✓" if result['status'] == 'compliant' else "✗"
        table_data.append([
            result['id'],
            result['title'],
            result['severity'].upper(),
            status_symbol,
            result['message']
        ])
    
    headers = ["ID", "Title", "Severity", "Status", "Message"]
    report_lines.append(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    report_text = '\n'.join(report_lines)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(report_text)
        console.print(f"[bold green]Report saved to {output_file}[/bold green]")
    
    return report_text

@click.group()
def cli():
    """OSQuery-Compliance: A tool for assessing DOD STIG compliance using osquery."""
    pass

@cli.command('list')
@click.option('--checks-dir', '-d', help='Directory containing STIG check definitions')
@click.option('--os-type', '-o', help='Operating system type (linux, windows, macos)')
def list_checks(checks_dir, os_type):
    """List all available STIG compliance checks."""
    if os_type:
        console.print(f"[bold]Loading STIG checks for OS: {os_type}[/bold]")
    else:
        detected_os = get_os_type()
        console.print(f"[bold]Detected OS: {detected_os}[/bold]")
        os_type = detected_os
    
    checks = load_stig_checks(checks_dir, os_type)
    
    if not checks:
        console.print("[bold yellow]No STIG checks found.[/bold yellow]")
        return
    
    table = Table(title=f"Available STIG Checks for {os_type.upper()}")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Severity", style="magenta")
    
    for check in checks:
        table.add_row(
            check.get('id', 'unknown'),
            check.get('title', 'Unknown check'),
            check.get('severity', 'medium').upper()
        )
    
    console.print(table)

@cli.command('run')
@click.option('--check-id', '-c', help='Run a specific check by ID')
@click.option('--checks-dir', '-d', help='Directory containing STIG check definitions')
@click.option('--os-type', '-o', help='Operating system type (linux, windows, macos)')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed output')
def run_check(check_id, checks_dir, os_type, verbose):
    """Run one or all STIG compliance checks."""
    if os_type:
        console.print(f"[bold]Running STIG checks for OS: {os_type}[/bold]")
    else:
        detected_os = get_os_type()
        console.print(f"[bold]Detected OS: {detected_os}[/bold]")
        os_type = detected_os
    
    checks = load_stig_checks(checks_dir, os_type)
    
    if not checks:
        console.print("[bold yellow]No STIG checks found.[/bold yellow]")
        return
    
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        if check_id:
            # Run a specific check
            for check in checks:
                if check.get('id') == check_id:
                    task = progress.add_task(f"Running check {check_id}...", total=1)
                    result = run_compliance_check(check, verbose)
                    results.append(result)
                    progress.update(task, advance=1)
                    break
            else:
                console.print(f"[bold red]Check with ID {check_id} not found[/bold red]")
                return
        else:
            # Run all checks
            task = progress.add_task("Running all compliance checks...", total=len(checks))
            for check in checks:
                result = run_compliance_check(check, verbose)
                results.append(result)
                progress.update(task, advance=1)
    
    # Print results
    compliant_count = sum(1 for r in results if r['status'] == 'compliant')
    total_count = len(results)
    compliance_percentage = (compliant_count / total_count) * 100 if total_count > 0 else 0
    
    console.print(Panel(f"[bold]Compliance Summary: {compliant_count}/{total_count} checks passed ({compliance_percentage:.1f}%)[/bold]"))
    
    for result in results:
        print_check_result(result, verbose)

@cli.command('report')
@click.option('--checks-dir', '-d', help='Directory containing STIG check definitions')
@click.option('--os-type', '-o', help='Operating system type (linux, windows, macos)')
@click.option('--output', '-o', help='Output file for the report')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed output')
def generate_compliance_report(checks_dir, os_type, output, verbose):
    """Generate a compliance report."""
    if os_type:
        console.print(f"[bold]Generating report for OS: {os_type}[/bold]")
    else:
        detected_os = get_os_type()
        console.print(f"[bold]Detected OS: {detected_os}[/bold]")
        os_type = detected_os
    
    checks = load_stig_checks(checks_dir, os_type)
    
    if not checks:
        console.print("[bold yellow]No STIG checks found.[/bold yellow]")
        return
    
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Running compliance checks for report...", total=len(checks))
        for check in checks:
            result = run_compliance_check(check, verbose)
            results.append(result)
            progress.update(task, advance=1)
    
    report_text = generate_report(results, output)
    
    if not output:
        console.print(report_text)

@cli.command('query')
@click.argument('query')
@click.option('--format', '-f', type=click.Choice(['table', 'json']), default='table', help='Output format')
def run_query(query, format):
    """Run a custom osquery query."""
    results = run_osquery(query)
    
    if not results:
        console.print("[bold yellow]No results returned from query.[/bold yellow]")
        return
    
    if format == 'json':
        console.print(json.dumps(results, indent=2))
    else:
        table = Table(title=f"Query Results: {query}")
        
        # Add columns dynamically based on the first result
        for key in results[0].keys():
            table.add_column(key)
        
        # Add rows
        for row in results:
            table.add_row(*[str(row.get(key, '')) for key in results[0].keys()])
        
        console.print(table)

if __name__ == '__main__':
    # Create necessary directories if they don't exist
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Create STIG check directories
    os.makedirs(os.path.join(base_dir, 'stig_checks'), exist_ok=True)
    os.makedirs(os.path.join(base_dir, 'stig_checks', 'linux'), exist_ok=True)
    os.makedirs(os.path.join(base_dir, 'stig_checks', 'windows'), exist_ok=True)
    os.makedirs(os.path.join(base_dir, 'stig_checks', 'macos'), exist_ok=True)
    
    # Create threat hunt directories
    os.makedirs(os.path.join(base_dir, 'threat_hunts'), exist_ok=True)
    os.makedirs(os.path.join(base_dir, 'threat_hunts', 'linux'), exist_ok=True)
    os.makedirs(os.path.join(base_dir, 'threat_hunts', 'windows'), exist_ok=True)
    os.makedirs(os.path.join(base_dir, 'threat_hunts', 'macos'), exist_ok=True)
    
    try:
        cli()
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        sys.exit(1)
