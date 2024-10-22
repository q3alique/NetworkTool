#!/usr/bin/env python

import ipaddress
import netifaces
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from tabulate import tabulate

from colorama import init, Fore, Style

import db
import cli
import json

# Dictionary that stores the scan IDs corresponding to the running NmapProcs
nmapproc_scanid = {}

SCAN_TYPE_RECON = "Recon"
SCAN_TYPE_SEGMENTATION = "Segmentation"
SCAN_TYPE_GENERIC = "Generic"
SCAN_TYPE_CUSTOM_NMAP = "CustomNmap"

# Nmap scan options for Recon scan
nmap_recon_options = {
    1: {"name": "Ping Scan", "option": "-sn", "description": "Discover online hosts without scanning ports."},
    2: {"name": "SYN Scan", "option": "-sS", "description": "Perform SYN scan on hosts discovered by Ping Scan."},
    3: {"name": "SYN Scan + Version Detection", "option": "-sS -sV", "description": "Perform SYN scan and detect service versions."},
    4: {"name": "SYN Scan + Aggressive Scan", "option": "-sS -A", "description": "Perform SYN scan and aggressive scan (OS detection, version detection, and traceroute)."},
}

# Nmap scan options for Segmentation Check
nmap_segmentation_options = {
    1: {"name": "TCP ACK Scan", "option": "-sA", "description": "Bypass stateful firewalls by sending TCP ACK packets."},
    2: {"name": "Fragmentation Scan", "option": "-sS -f", "description": "Evade security devices by sending fragmented packets."},
    3: {"name": "Idle Scan", "option": "-sI <zombie_host>", "description": "Perform a stealthy scan using a zombie host."},
    4: {"name": "TTL-based Scan", "option": "--ttl 50", "description": "Manipulate TTL to evade inspection by security devices."},
    5: {"name": "Reverse Path Filtering Scan", "option": "--badsum", "description": "Use malformed packets to detect weaknesses in firewall configuration."},
    6: {"name": "TCP SYN/FIN Scan", "option": "-sF", "description": "Send TCP FIN packets to bypass SYN-blocking firewalls."},
    7: {"name": "IP Protocol Scan", "option": "-sO", "description": "Test different IP protocols to identify less inspected paths."},
    8: {"name": "Timing Manipulation Scan", "option": "-T0", "description": "Slow scan to bypass IDS/IPS by reducing traffic bursts."},
}

# Nmap scan options for Generic scan
nmap_generic_options = {
    1: {"name": "TCP Connect Scan", "option": "-sT", "description": "Perform a TCP connect scan."},
    2: {"name": "SYN Scan", "option": "-sS", "description": "Perform a SYN scan (most popular and faster)."},
    3: {"name": "UDP Scan", "option": "-sU", "description": "Perform a UDP scan (slower)."},
    4: {"name": "Service Version Detection", "option": "-sV", "description": "Detect service versions."},
    5: {"name": "OS Detection", "option": "-O", "description": "Enable OS detection."},
    6: {"name": "Aggressive Scan", "option": "-A", "description": "Enable OS detection, version detection, script scanning, and traceroute."},
    7: {"name": "Ping Scan", "option": "-sn", "description": "Discover online hosts without scanning ports."},
}

# Valid status are taken from the libnmap library
SCAN_STATUS = [
    db.SqlHandler.Scan.STATUS_DONE,
    db.SqlHandler.Scan.STATUS_READY,
    db.SqlHandler.Scan.STATUS_RUNNING,
    db.SqlHandler.Scan.STATUS_CANCELLED,
    db.SqlHandler.Scan.STATUS_FAILED,
]

def _scan_callback(nmap_proc):
    if nmap_proc not in nmapproc_scanid:
        cli.print_error(f"\n[+] NmapProc not found in association dictionary, something went wrong")
        cli.print_error(f"\n[+] Cancelling scan...")
        nmap_proc.stop()
        return

    # Retrieve the scan ID from the dictionary holding NmapProcs as keys
    scanid = nmapproc_scanid[nmap_proc]

    # Update scan status in DB
    sess = db.sqlhandler.Session()
    scan = sess.query(db.SqlHandler.Scan).get(scanid)
    if not scan:
        cli.print_error(f"\n[+] No scan found in DB with the given ID [ID: {scanid}]")
        cli.print_error(f"\n[+] Cancelling scan...")
        nmap_proc.stop()
        del nmapproc_scanid[nmap_proc]
        sess.close()
        return
    
    # Translate NmapProc state to our DB's status
    scan.status = SCAN_STATUS[nmap_proc.state]
    scan.percentage = nmap_proc.progress

    if scan.status == db.SqlHandler.Scan.STATUS_FAILED:
        cli.print_error(f"\n[+] Scan failed! [ID: {scanid}]")
        cli.print_error(nmap_proc.stderr)
        del nmapproc_scanid[nmap_proc]
    if scan.status == db.SqlHandler.Scan.STATUS_CANCELLED:
        cli.print_error(f"\n[+] Scan was cancelled [ID: {scanid}]")
        del nmapproc_scanid[nmap_proc]
    elif scan.status == db.SqlHandler.Scan.STATUS_DONE:
        cli.print_success(f"\n[+] Scan finished! [ID: {scanid}]")
        del nmapproc_scanid[nmap_proc]
        parsed = None
        try:
            parsed = NmapParser.parse(nmap_proc.stdout)
        except NmapParserException as e:
            cli.repl.error(f"Exception raised while parsing scan: {e.msg}")
        report = db.SqlHandler.Report(parsed)
        sess.add(report)
        scan.reports.append(report)

    sess.commit()
    sess.close()

    #if nmaptask:
    #    print(
    #        "Task {0} ({1}): ETC: {2} DONE: {3}%".format(
    #            nmaptask.name, nmaptask.status, nmaptask.etc, nmaptask.progress
    #        )
    #    )

# Recon scan
def recon_scan(target=None, silent_mode=False):
    """Performs the Recon scans based on the user's selection."""
    
    if not target:
        target = _get_local_ip_range()  # Detect the local network range if target is not provided
        print(f"{Fore.YELLOW}No target provided. Using local IP range: {target}{Style.RESET_ALL}")
    
    timing_option = "-T2" if silent_mode else ""
    scan_option = _display_recon_menu()

    flags = f"{scan_option} {timing_option}"

    scan = db.SqlHandler.Scan(
        name="Recon scan",
        nmap_target=target,
        nmap_flags=flags,
        scan_type=SCAN_TYPE_RECON,
        source_ip=_get_local_ip()
    )

    scanid = db.sqlhandler.insert(scan)

    print(f"{Fore.MAGENTA}Performing {scan_option} on {target}{Style.RESET_ALL} [ID: {scanid}]")
    nmap_proc = NmapProcess(targets=target, options=flags, event_callback=_scan_callback)
    nmapproc_scanid[nmap_proc] = scanid
    nmap_proc.sudo_run_background()

# Segmentation Check scan
def segmentation_check_scan(target, silent_mode=False):
    """Performs the Segmentation Check scans based on the user's selection."""
    
    timing_option = "-T2" if silent_mode else ""
    scan_option = _display_segmentation_menu()

    flags = f"{scan_option} {timing_option}"

    scan = db.SqlHandler.Scan(
        name="Segmentation check scan",
        nmap_target=target,
        nmap_flags=flags,
        scan_type=SCAN_TYPE_SEGMENTATION,
        source_ip=_get_local_ip()
    )

    scanid = db.sqlhandler.insert(scan)

    print(f"{Fore.MAGENTA}Starting Segmentation Check Scan on target: {target}{Style.RESET_ALL} [ID: {scanid}]")
    nmap_proc = NmapProcess(targets=target, options=flags, event_callback=_scan_callback)
    nmapproc_scanid[nmap_proc] = scanid
    nmap_proc.sudo_run_background()

# Generic scan
def generic_scan(target, ports, ping_off=True, silent_mode=False):
    """Performs the Generic scan using Nmap based on the user's selection."""
    if not target:
        print(f"{Fore.RED}Error: Target is required for the Generic scan.{Style.RESET_ALL}")
        return
    
    print(f"{Fore.MAGENTA}Starting Generic Scan on target: {target}{Style.RESET_ALL}")
    
    timing_option = "-T2" if silent_mode else ""
    scan_option = _display_generic_menu()
        
    port_option = "" if scan_option == "-sn" else ("-p-" if ports is None else f"-p {ports}")
    ping_option = "-Pn" if ping_off else ""

    flags = f"{scan_option} {port_option} {ping_option} {timing_option}".strip()

    scan = db.SqlHandler.Scan(
        name="Generic scan",
        nmap_target=target,
        nmap_flags=flags,
        scan_type=SCAN_TYPE_GENERIC,
        source_ip=_get_local_ip()
    )

    scanid = db.sqlhandler.insert(scan)

    print(f"{Fore.CYAN}Performing scan with option: {scan_option}{Style.RESET_ALL} [ID: {scanid}]")

    nmap_proc = NmapProcess(targets=target, options=flags, event_callback=_scan_callback)
    nmapproc_scanid[nmap_proc] = scanid
    nmap_proc.sudo_run_background()

# Nmap custom scan using full nmap flags
def nmap_custom_scan(nmap_flags):
    """Perform custom Nmap scans using full nmap flags."""

    scan = db.SqlHandler.Scan(
        name="Custom nmap scan",
        nmap_target="custom",
        nmap_flags=nmap_flags,
        scan_type=SCAN_TYPE_CUSTOM_NMAP,
        source_ip=_get_local_ip()
    )

    scanid = db.sqlhandler.insert(scan)
    
    print(f"{Fore.MAGENTA}Starting Custom Nmap Scan with flags: {nmap_flags}{Style.RESET_ALL} [ID: {scanid}]")

    nmap_proc = NmapProcess(options=nmap_flags, event_callback=_scan_callback)
    nmapproc_scanid[nmap_proc] = scanid
    nmap_proc.sudo_run_background()

def kill_scan(scanid):
    if not scanid:
        print(f"{Fore.RED}Error: Scan ID is required.{Style.RESET_ALL}")
        return
    
    with db.sqlhandler.Session() as sess:
        scan = sess.query(db.SqlHandler.Scan).get(scanid)
        if not scan:
            cli.print_error(f"No Scan with this identifier. Status: {scan.status}")
            return
        scan_type = scan.scan_type
        if scan_type != db.SqlHandler.Scan.STATUS_RUNNING:
            cli.print_error(f"Scan is not running. Status: {scan.status}")
    
    for nmap_proc in nmapproc_scanid:
        if nmapproc_scanid[nmap_proc] == scanid:
            cli.print_error(f"Requesting Scan stop... [ID: {scanid}]")
            nmap_proc.stop()
    
def rm_scan(scanid):
    if not scanid:
        print(f"{Fore.RED}Error: Scan ID is required.{Style.RESET_ALL}")
        return
    
    with db.sqlhandler.Session() as sess:
        scan = sess.query(db.SqlHandler.Scan).get(scanid)
        if not scan:
            cli.print_error(f"No Scan with this identifier. Status: {scan.status}")
            return
    
        #TODO: implement confirmation message, printing the details of the Scan and specifying if a report is available
        sess.delete(scan)
        sess.commit()
        cli.print_success(f"Scan successfully removed from DB. [ID: {scanid}]")

def list_scans(filter=None):
    scans = None
    with db.sqlhandler.Session() as sess:
        scans = sess.query(db.SqlHandler.Scan).order_by(db.SqlHandler.Scan.inserted)
    
    if filter == "running":
        scans = scans.filter(db.SqlHandler.Scan.status == db.SqlHandler.Scan.STATUS_RUNNING)
    elif filter == "done":
        scans = scans.filter(db.SqlHandler.Scan.status == db.SqlHandler.Scan.STATUS_DONE)

    headers = ["ID", "Type", "Name", "Source", "Target", "Flags", "Status", "Percent."]
    data = [ [scan.id, scan.scan_type, scan.name, scan.source_ip, scan.nmap_target, scan.nmap_flags, scan.status, scan.percentage] for scan in scans ]

    cli.repl.print(tabulate(data, headers=headers, tablefmt='grid'))

def print_scan(scanid):
    if not scanid:
        print(f"{Fore.RED}Error: Scan ID is required.{Style.RESET_ALL}")
        return

    report = None
    scan_type = None
    
    with db.sqlhandler.Session() as sess:
        scan = sess.query(db.SqlHandler.Scan).get(scanid)
        if not scan:
            cli.print_error(f"No Scan with this identifier. Status: {scan.status}")
            return
        scan_type = scan.scan_type
        if len(scan.reports) > 0:
            report = scan.reports[0].decode()
        else:
            cli.print_error(f"No report for this Scan. Status: {scan.status}")
            return
    
    if scan_type == SCAN_TYPE_RECON:
        for h in report.hosts:
            print(f"{Fore.CYAN}Host:{Style.RESET_ALL} {h.address}")
            for serv in h.services:
                if serv.state == "open":  # Only show open ports
                    print(f"  {Fore.YELLOW}Port:{Style.RESET_ALL} {serv.port} - {serv.service} ({serv.state})")
    elif scan_type in [SCAN_TYPE_SEGMENTATION, SCAN_TYPE_GENERIC, SCAN_TYPE_CUSTOM_NMAP]:
        for host in report.hosts:
            print(f"{Fore.CYAN}Host:{Style.RESET_ALL} {host.address} ({', '.join(host.hostnames)})")
            print(f"{Fore.CYAN}State:{Style.RESET_ALL} {host.status}")
            if host.os_fingerprinted and host.os.osmatches:
                print(f"{Fore.CYAN}Operating System:{Style.RESET_ALL} {host.os.osmatches[0].name}")
            print(f"\n{Fore.GREEN}Services (Open Ports Only):{Style.RESET_ALL}")
            for serv in host.services:
                if serv.state == "open":  # Only show open ports
                    print(f"{Fore.YELLOW}Port:{Style.RESET_ALL} {serv.port}")
                    print(f"{Fore.YELLOW}Service:{Style.RESET_ALL} {serv.service}")
                    if serv.scripts_results:
                        print(f"{Fore.YELLOW}NSE Result:{Style.RESET_ALL} {serv.scripts_results}")
                    print("\n")
    else:
        print(f"Unknown scan type {scan_type}, nothing will be printed.")

def export_scan(scanid, output_file):
    if not scanid or not output_file:
        print(f"{Fore.RED}Error: Scan ID and output file are required.{Style.RESET_ALL}")
        return

    report = None
    
    with db.sqlhandler.Session() as sess:
        scan = sess.query(db.SqlHandler.Scan).get(scanid)
        if not scan:
            cli.print_error(f"No Scan with this identfier. Status: {scan.status}")
            return
        if len(scan.reports) > 0:
            report = scan.reports[0].decode()
        else:
            cli.print_error(f"No report for this Scan. Status: {scan.status}")
            return

    results = None
    if output_file.endswith(".txt"):
        results = _format_output_txt(report)
        print(results)
        _write_final_report(results, output_file)
    elif output_file.endswith(".md"):
        results = _format_output_md(report)
        _write_final_report(results, output_file)
    elif output_file.endswith(".json"):
        _generate_and_save_report(report, output_file, _format_output_json)

def _display_recon_menu():
    """Display the Nmap scan menu for the Recon scan."""
    print(f"\n{Fore.CYAN}Available Nmap Recon Scan Options:{Style.RESET_ALL}")
    for num, option in nmap_recon_options.items():
        print(f"{Fore.YELLOW}{num}. {option['name']}{Style.RESET_ALL} - {option['description']}")
    
    while True:
        try:
            choice = int(input(f"\n{Fore.GREEN}Enter the number of the recon scan you want to use: {Style.RESET_ALL}"))
            if choice in nmap_recon_options:
                return nmap_recon_options[choice]["option"]
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")

def _display_segmentation_menu():
    """Display the Nmap scan menu for Segmentation Check."""
    print(f"\n{Fore.CYAN}Available Nmap Segmentation Check Scan Options:{Style.RESET_ALL}")
    for num, option in nmap_segmentation_options.items():
        print(f"{Fore.YELLOW}{num}. {option['name']}{Style.RESET_ALL} - {option['description']}")
    
    while True:
        try:
            choice = int(input(f"\n{Fore.GREEN}Enter the number of the segmentation check scan you want to use: {Style.RESET_ALL}"))
            if choice in nmap_segmentation_options:
                return nmap_segmentation_options[choice]["option"]
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")

def _display_generic_menu():
    """Display the Nmap scan menu for the Generic scan."""
    print(f"\n{Fore.CYAN}Available Nmap Generic Scan Options:{Style.RESET_ALL}")
    for num, option in nmap_generic_options.items():
        print(f"{Fore.YELLOW}{num}. {option['name']}{Style.RESET_ALL} - {option['description']}")
    
    while True:
        try:
            choice = int(input(f"\n{Fore.GREEN}Enter the number of the generic scan you want to use: {Style.RESET_ALL}"))
            if choice in nmap_generic_options:
                return nmap_generic_options[choice]["option"]
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")

# Function to detect the local network range dynamically
def _get_local_ip_range():
    """Get the local IP address range dynamically using the system network interfaces."""
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            ipv4_info = addresses[netifaces.AF_INET][0]
            ip_address = ipv4_info['addr']
            netmask = ipv4_info['netmask']

            # Skip the loopback interface (127.x.x.x)
            if not ip_address.startswith("127."):
                network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                return str(network)
    
    raise RuntimeError("Could not find a valid non-loopback IP address")

# Function to detect the local network range dynamically
def _get_local_ip():
    """Get the local IP dynamically using the system network interfaces."""
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            ipv4_info = addresses[netifaces.AF_INET][0]
            ip_address = ipv4_info['addr']

            # Skip the loopback interface (127.x.x.x)
            if not ip_address.startswith("127."):
                return ip_address
    
    raise RuntimeError("Could not find a valid non-loopback IP address")


# Generate output for each host and append to report
def _generate_and_save_report(report, file_path, format_func):
    """Generate the report for each host and append the result to the final file."""
    report_content = format_func(report)
    _save_output(report_content, file_path)

# Accumulate results for each IP
def _accumulate_results(report, format_func, accumulated_results):
    """Accumulate scan results for multiple hosts."""
    accumulated_results.append(format_func(report))

# Write the final report once all IPs have been scanned
def _write_final_report(results, file_path):
    """Write the final report containing results for all IPs to the output file."""
    with open(file_path, 'w') as f:
        f.write(results)

# Reporting Functions
def _format_output_txt(report):
    """Format the scan results as plain text."""
    output = []
    for host in report.hosts:
        output.append(f"Host: {host.address} ({', '.join(host.hostnames)})")
        output.append(f"State: {host.status}")
        if host.os_fingerprinted and host.os.osmatches:
            output.append(f"Operating System: {host.os.osmatches[0].name}")
        else:
            output.append(f"Operating System: No OS information available")

        output.append(f"Services:")
        for serv in host.services:
            if serv.state == "open":  # Only show open ports
                output.append(f"  Port: {serv.port}")
                output.append(f"  Service: {serv.service}")
                output.append(f"  State: {serv.state}")
                if serv.scripts_results:
                    output.append(f"  NSE Result: {serv.scripts_results}")
        output.append("\n")
    return "\n".join(output)

def _format_output_md(report):
    """Format the scan results as markdown suitable for Obsidian with tables."""
    output = []
    for host in report.hosts:
        output.append(f"### Host: {host.address} ({', '.join(host.hostnames)})")
        output.append(f"- **State**: {host.status}")
        if host.os_fingerprinted and host.os.osmatches:
            output.append(f"- **Operating System**: {host.os.osmatches[0].name}")
        else:
            output.append(f"- **Operating System**: No OS information available")

        if any(serv.state == "open" for serv in host.services):
            output.append(f"#### Services")
            output.append(f"| Port | Service | State | NSE Result |")
            output.append(f"|------|---------|-------|------------|")
            for serv in host.services:
                if serv.state == "open":  # Only show open ports
                    nse_result = serv.scripts_results if serv.scripts_results else "N/A"
                    output.append(f"| {serv.port} | {serv.service} | {serv.state} | {nse_result} |")
            output.append("\n")
        else:
            output.append(f"No open services found.\n")
    return "\n".join(output)

def _format_output_json(report):
    """Format the scan results as JSON."""
    json_output = []
    for host in report.hosts:
        host_info = {
            "host": host.address,
            "hostnames": host.hostnames,
            "state": host.status,
            "os": host.os.osmatches[0].name if host.os.fingerprint and host.os.osmatches else "No OS information available",
            "services": []
        }
        for serv in host.services:
            if serv.state == "open":  # Only show open ports
                service_info = {
                    "port": serv.port,
                    "service": serv.service,
                    "state": serv.state,
                    "nse_result": serv.scripts_results
                }
                host_info["services"].append(service_info)
        json_output.append(host_info)
    return json_output

# Save report as a valid JSON array
def _save_output_json(report_content, file_path):
    """Save the accumulated output to a JSON file as a proper array."""
    try:
        with open(file_path, 'r') as f:
            existing_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = []

    # Extend the existing JSON data with the new results
    existing_data.extend(report_content)

    # Write the final JSON array back to the file
    with open(file_path, "w") as f:
        json.dump(existing_data, f, indent=4)

def _save_output(report_content, file_path):
    """Save the output to the specified file based on the extension."""
    extension = file_path.split('.')[-1]
    
    if extension == "txt":
        with open(file_path, "a") as f:
            f.write(report_content)
    elif extension == "md":
        with open(file_path, "a") as f:
            f.write(report_content)
    elif extension == "json":
        _save_output_json(report_content, file_path)
    else:
        print(f"{Fore.RED}Unsupported file format: {extension}{Style.RESET_ALL}")