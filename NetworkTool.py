import argparse
import ipaddress
import json
import socket
import netifaces
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from colorama import init, Fore, Style

# Initialize colorama for Windows compatibility
init()

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

# Nmap scan options for Recon scan
nmap_recon_options = {
    1: {"name": "Ping Scan", "option": "-sn", "description": "Discover online hosts without scanning ports."},
    2: {"name": "Ping Scan + SYN Scan", "option": "-sS", "description": "Perform SYN scan on hosts discovered by Ping Scan."},
    3: {"name": "Ping Scan + SYN Scan + Version Detection", "option": "-sS -sV", "description": "Perform SYN scan and detect service versions."},
    4: {"name": "Ping Scan + SYN Scan + Aggressive Scan", "option": "-sS -A", "description": "Perform SYN scan and aggressive scan (OS detection, version detection, and traceroute)."},
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

# Function to detect the local network range dynamically
def get_local_ip_range():
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

# Reporting Functions
def format_output_txt(report):
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

def format_output_md(report):
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

def format_output_json(report):
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
def save_output_json(report_content, file_path):
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

def save_output(report_content, file_path):
    """Save the output to the specified file based on the extension."""
    extension = file_path.split('.')[-1]
    
    if extension == "txt":
        with open(file_path, "a") as f:
            f.write(report_content)
    elif extension == "md":
        with open(file_path, "a") as f:
            f.write(report_content)
    elif extension == "json":
        save_output_json(report_content, file_path)
    else:
        print(f"{Fore.RED}Unsupported file format: {extension}{Style.RESET_ALL}")

# Generate output for each host and append to report
def generate_and_save_report(report, file_path, format_func):
    """Generate the report for each host and append the result to the final file."""
    report_content = format_func(report)
    save_output(report_content, file_path)

# Accumulate results for each IP
def accumulate_results(report, format_func, accumulated_results):
    """Accumulate scan results for multiple hosts."""
    accumulated_results.append(format_func(report))

# Write the final report once all IPs have been scanned
def write_final_report(accumulated_results, file_path):
    """Write the final report containing results for all IPs to the output file."""
    with open(file_path, 'w') as f:
        f.write("\n".join(accumulated_results))

# Display scan menus
def display_generic_menu():
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

def display_recon_menu():
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

def display_segmentation_menu():
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

# Recon scan
def recon_scan(target=None, silent_mode=False, output_file=None):
    """Performs the Recon scans in a cascade manner based on the user's selection."""
    
    if not target:
        target = get_local_ip_range()  # Detect the local network range if target is not provided
        print(f"{Fore.YELLOW}No target provided. Using local IP range: {target}{Style.RESET_ALL}")
    
    timing_option = "-T2" if silent_mode else ""
    scan_option = display_recon_menu()

    print(f"{Fore.MAGENTA}Starting Recon Scan (Ping Scan) on target: {target}{Style.RESET_ALL}")
    nmap_proc = NmapProcess(targets=target, options=f"-sn {timing_option}")
    nmap_proc.run()

    if nmap_proc.rc != 0:
        print(f"Nmap ping scan failed: {nmap_proc.stderr}")
        return

    try:
        report = NmapParser.parse(nmap_proc.stdout)
        up_hosts = [host.address for host in report.hosts if host.is_up()]

        if not up_hosts:
            print(f"{Fore.YELLOW}No online hosts detected.{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}Online Hosts detected: {up_hosts}{Style.RESET_ALL}")

        accumulated_results = []

        # Process and report for each host individually
        for host in up_hosts:
            print(f"{Fore.MAGENTA}Performing {scan_option} on {host}{Style.RESET_ALL}")
            nmap_proc_recon = NmapProcess(targets=host, options=f"{scan_option} {timing_option}")
            nmap_proc_recon.run()

            if nmap_proc_recon.rc != 0:
                print(f"Nmap scan failed for {host}: {nmap_proc_recon.stderr}")
            else:
                report_recon = NmapParser.parse(nmap_proc_recon.stdout)
                # Print results to command line
                for h in report_recon.hosts:
                    print(f"{Fore.CYAN}Host:{Style.RESET_ALL} {h.address}")
                    for serv in h.services:
                        if serv.state == "open":  # Only show open ports
                            print(f"  {Fore.YELLOW}Port:{Style.RESET_ALL} {serv.port} - {serv.service} ({serv.state})")
                
                # Accumulate results to write later
                if output_file and (output_file.endswith(".txt") or output_file.endswith(".md")):
                    accumulate_results(report_recon, format_output_txt if output_file.endswith(".txt") else format_output_md, accumulated_results)
                elif output_file and output_file.endswith(".json"):
                    generate_and_save_report(report_recon, output_file, format_output_json)

        # Write accumulated results to file (for txt and md formats)
        if output_file and (output_file.endswith(".txt") or output_file.endswith(".md")):
            write_final_report(accumulated_results, output_file)

    except NmapParserException as e:
        print(f"Failed to parse Nmap scan: {e}")

# Generic scan
def generic_scan(target, ports, ping_off, output_file, silent_mode):
    """Performs the Generic scan using Nmap based on the user's selection."""
    if not target:
        print(f"{Fore.RED}Error: Target is required for the Generic scan.{Style.RESET_ALL}")
        return
    
    print(f"{Fore.MAGENTA}Starting Generic Scan on target: {target}{Style.RESET_ALL}")
    
    timing_option = "-T2" if silent_mode else ""
    scan_option = display_generic_menu()
    
    print(f"{Fore.CYAN}Performing scan with option: {scan_option}{Style.RESET_ALL}")
    
    port_option = "" if scan_option == "-sn" else ("-p-" if ports is None else f"-p {ports}")
    ping_option = "-Pn" if ping_off else ""
    nmap_proc = NmapProcess(targets=target, options=f"{scan_option} {port_option} {ping_option} {timing_option}".strip())
    nmap_proc.run()

    if nmap_proc.rc != 0:
        print(f"Nmap scan failed: {nmap_proc.stderr}")
        return

    try:
        report = NmapParser.parse(nmap_proc.stdout)

        accumulated_results = []

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
            # Accumulate results
            if output_file and (output_file.endswith(".txt") or output_file.endswith(".md")):
                accumulate_results(report, format_output_txt if output_file.endswith(".txt") else format_output_md, accumulated_results)
            elif output_file and output_file.endswith(".json"):
                generate_and_save_report(report, output_file, format_output_json)

        if output_file and (output_file.endswith(".txt") or output_file.endswith(".md")):
            write_final_report(accumulated_results, output_file)

    except NmapParserException as e:
        print(f"Failed to parse Nmap scan: {e}")

# Segmentation Check scan
def segmentation_check_scan(target, silent_mode, output_file=None):
    """Performs the Segmentation Check scans based on the user's selection."""
    
    timing_option = "-T2" if silent_mode else ""
    scan_option = display_segmentation_menu()

    print(f"{Fore.MAGENTA}Starting Segmentation Check Scan on target: {target}{Style.RESET_ALL}")
    nmap_proc = NmapProcess(targets=target, options=f"{scan_option} {timing_option}")
    nmap_proc.run()

    if nmap_proc.rc != 0:
        print(f"Nmap scan failed: {nmap_proc.stderr}")
        return

    try:
        report = NmapParser.parse(nmap_proc.stdout)

        accumulated_results = []

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
            # Accumulate results
            if output_file and (output_file.endswith(".txt") or output_file.endswith(".md")):
                accumulate_results(report, format_output_txt if output_file.endswith(".txt") else format_output_md, accumulated_results)
            elif output_file and output_file.endswith(".json"):
                generate_and_save_report(report, output_file, format_output_json)

        if output_file and (output_file.endswith(".txt") or output_file.endswith(".md")):
            write_final_report(accumulated_results, output_file)

    except NmapParserException as e:
        print(f"Failed to parse Nmap scan: {e}")

# Nmap custom scan using full nmap flags
def nmap_custom_scan(nmap_flags, output_file):
    """Perform custom Nmap scans using full nmap flags."""
    print(f"{Fore.MAGENTA}Starting Custom Nmap Scan with flags: {nmap_flags}{Style.RESET_ALL}")
    
    nmap_proc = NmapProcess(options=nmap_flags)
    nmap_proc.run()

    if nmap_proc.rc != 0:
        print(f"Nmap custom scan failed: {nmap_proc.stderr}")
        return

    try:
        report = NmapParser.parse(nmap_proc.stdout)

        accumulated_results = []

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
            # Accumulate results
            if output_file and (output_file.endswith(".txt") or output_file.endswith(".md")):
                accumulate_results(report, format_output_txt if output_file.endswith(".txt") else format_output_md, accumulated_results)
            elif output_file and output_file.endswith(".json"):
                generate_and_save_report(report, output_file, format_output_json)

        if output_file and (output_file.endswith(".txt") or output_file.endswith(".md")):
            write_final_report(accumulated_results, output_file)

    except NmapParserException as e:
        print(f"Failed to parse Nmap scan: {e}")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Network Scanning Framework")
    
    # Make target required for certain scans only
    subparsers = parser.add_subparsers(dest="scan_type", help="Choose the type of scan to perform.")
    
    # Nmap subcommand
    nmap_parser = subparsers.add_parser('nmap', help="Perform a custom Nmap scan using Nmap flags.")
    nmap_parser.add_argument('--output', type=str, help="Specify output file path (e.g., results.txt, results.md, results.json).")
    nmap_parser.add_argument('nmap_flags', nargs=argparse.REMAINDER, help="Provide Nmap flags for a custom Nmap scan.")
    
    # Generic subcommand
    generic_parser = subparsers.add_parser('Generic', help="Perform a Generic scan.")
    generic_parser.add_argument('--target', type=str, required=True, help="Specify the target IP or domain.")
    generic_parser.add_argument('--ports', type=str, help="Specify ports to scan (e.g., 80,443 or 1-1000). Default is all ports.")
    generic_parser.add_argument('--ping-off', action='store_true', help="Disable ping (host discovery) during scan.")
    generic_parser.add_argument('--output', type=str, help="Specify output file path (e.g., results.txt, results.md, results.json).")
    generic_parser.add_argument('--mode', type=str, choices=['silent', 'normal'], default='normal', help="Run scan in 'silent' or 'normal' mode.")
    
    # Recon subcommand
    recon_parser = subparsers.add_parser('Recon', help="Perform a Recon scan.")
    recon_parser.add_argument('--target', type=str, help="Specify the target IP or domain.")
    recon_parser.add_argument('--output', type=str, help="Specify output file path (e.g., results.txt, results.md, results.json).")
    recon_parser.add_argument('--mode', type=str, choices=['silent', 'normal'], default='normal', help="Run scan in 'silent' or 'normal' mode.")
    
    # SegmentationCheck subcommand
    segmentation_parser = subparsers.add_parser('SegmentationCheck', help="Perform a Segmentation Check scan.")
    segmentation_parser.add_argument('--target', type=str, required=True, help="Specify the target IP or domain.")
    segmentation_parser.add_argument('--output', type=str, help="Specify output file path (e.g., results.txt, results.md, results.json).")
    segmentation_parser.add_argument('--mode', type=str, choices=['silent', 'normal'], default='normal', help="Run scan in 'silent' or 'normal' mode.")
    
    args = parser.parse_args()

    if args.scan_type == 'nmap':
        if not args.nmap_flags:
            print(f"{Fore.RED}No Nmap flags provided! You must specify at least one Nmap option.{Style.RESET_ALL}")
            return
        nmap_custom_scan(" ".join(args.nmap_flags), args.output)

    elif args.scan_type == 'Recon':
        recon_scan(args.target, (args.mode == 'silent'), args.output)

    elif args.scan_type == 'SegmentationCheck':
        segmentation_check_scan(args.target, (args.mode == 'silent'), args.output)

    elif args.scan_type == 'Generic':
        generic_scan(args.target, args.ports, args.ping_off, args.output, (args.mode == 'silent'))

    else:
        print(f"{Fore.RED}Invalid scan type provided!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

