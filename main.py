import argparse
import socket
import sys
import asyncio
from colorama import init, Fore, Style

from src.scanner import AsyncPortScanner
from src.discovery import is_host_up
from src.report import export_json, export_csv, export_html

# Initialize colorama
init(autoreset=True)

def parse_ports(port_arg: str) -> list:
    """Parses string like '80', '1-1000' into list."""
    ports = []
    try:
        if '-' in port_arg:
            start, end = map(int, port_arg.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_arg:
            ports = [int(p) for p in port_arg.split(',')]
        else:
            ports = [int(port_arg)]
    except ValueError:
        print(f"{Fore.RED}[!] Invalid port format.")
        sys.exit(1)
    return ports

def run_cli(args):
    """Runs the Command Line Interface version."""
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"{Fore.RED}[!] Could not resolve hostname {args.target}")
        return

    ports = parse_ports(args.ports)

    print(f"{Fore.CYAN}{Style.BRIGHT}Starting ProLevel Scan on {target_ip}")
    
    if args.ping:
        print(f"{Fore.YELLOW}[*] Performing Host Discovery (Ping Sweep)...")
        if not is_host_up(target_ip):
            print(f"{Fore.RED}[!] Host {target_ip} seems down. Use without --ping to force scan.")
            return
        print(f"{Fore.GREEN}[+] Host is UP. Proceeding with scan.")

    print(f"{Fore.CYAN}Ports: {len(ports)} | Mode: Async | Threads: {args.concurrency}")
    if args.vulns:
        print(f"{Fore.MAGENTA}[*] Vulnerability Engine: ENABLED")
    print("-" * 75)

    scanner = AsyncPortScanner(target_ip, ports, args.timeout, args.concurrency, check_vulns=args.vulns)

    try:
        print(f"{Fore.YELLOW}[*] Scanning... please wait.")
        results = asyncio.run(scanner.run())
        results.sort(key=lambda x: x['port'])

        print(f"\n{Fore.GREEN}[+] Scan Complete. Found {len(results)} open ports:\n")
        print(f"{'PORT':<10} {'STATUS':<10} {'SERVICE/BANNER':<30} {'VULNS'}")
        print("-" * 75)

        for res in results:
            service_color = Fore.YELLOW if res['service'] != "Unknown" else Fore.WHITE
            service_display = str(res['service']).replace('\n', ' ').replace('\r', '')
            if len(service_display) > 28:
                service_display = service_display[:25] + "..."
                
            vulns_str = " | ".join(res['vulns']) if res['vulns'] else "-"
            vuln_color = Fore.RED if res['vulns'] else Fore.WHITE
            
            print(f"{Fore.GREEN}{res['port']:<10} {res['status']:<10} {service_color}{service_display:<30} {vuln_color}{vulns_str}")

        if args.export:
            if args.format == 'json':
                export_json(results, args.export)
            elif args.format == 'csv':
                export_csv(results, args.export)
            elif args.format == 'html':
                export_html(results, args.export, target_ip)
            print(f"\n{Fore.BLUE}[+] Results exported to {args.export} (Format: {args.format.upper()})")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.")


def main():
    parser = argparse.ArgumentParser(description="PST (Port Scan Tool) - ProLevel Modular Async Scanner")
    parser.add_argument("target", help="Target IP address or Hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 80 or 1-1000 or 80,443)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout in seconds")
    parser.add_argument("-c", "--concurrency", type=int, default=500, help="Concurrency limit")
    
    # New Arguments
    parser.add_argument("--ping", action="store_true", help="Perform ICMP ping sweep before scanning")
    parser.add_argument("--vulns", action="store_true", help="Run vulnerability checks on open ports")
    parser.add_argument("-e", "--export", type=str, help="Export results to a file")
    parser.add_argument("-f", "--format", choices=['json', 'csv', 'html'], default='json', help="Export format (default: json)")

    args = parser.parse_args()
    run_cli(args)

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except AttributeError:
        pass
    main()