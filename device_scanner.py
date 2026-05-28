"""
Usage:
    python network_scanner.py
    python network_scanner.py --subnet xxx.xxx.xxx.xxx/xx
    python network_scanner.py --mode ping
"""

import subprocess
import platform
import socket
import ipaddress
import datetime
import csv
import argparse
import concurrent.futures
import sys




def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def ping(ip: str) -> bool:
    """Ping a single IP. Returns True if host responds."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "500", str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]

    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def resolve_hostname(ip: str) -> str:
    """Try reverse DNS lookup; return 'N/A' on failure."""
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except socket.herror:
        return "N/A"


# ARP scan

def arp_scan(subnet: str):
    """
    Use ARP requests to discover devices on the LAN.
    Returns list of dicts: {ip, mac, hostname}
    """
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        print("[!] scapy not installed. Falling back to ping mode.")
        print("    Install with: pip install scapy\n")
        return None

    print(f"[*] Starting ARP scan on {subnet} ...")
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    answered, _ = srp(packet, timeout=2, verbose=False)
    devices = []
    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        hostname = resolve_hostname(ip)
        devices.append({"IP Address": ip, "MAC Address": mac, "Hostname": hostname, "Method": "ARP"})
    return devices


# Ping scan 

def ping_scan(subnet: str):
    """Ping every IP in subnet concurrently. Returns list of active hosts."""
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(network.hosts())
    print(f"[*] Pinging {len(hosts)} hosts on {subnet} ...")

    active = []

    def check(ip):
        if ping(ip):
            hostname = resolve_hostname(str(ip))
            return {"IP Address": str(ip), "MAC Address": "N/A (ping mode)", "Hostname": hostname, "Method": "Ping"}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(check, hosts)

    for r in results:
        if r:
            active.append(r)

    return active


#  Output 

def print_results(devices):
    if not devices:
        print("\n[!] No devices found.")
        return

    print(f"\n{'-'*65}")
    print(f"  {'IP Address':<18} {'MAC Address':<22} {'Hostname'}")
    print(f"{'-'*65}")
    for d in sorted(devices, key=lambda x: ipaddress.IPv4Address(x["IP Address"])):
        print(f"  {d['IP Address']:<18} {d['MAC Address']:<22} {d['Hostname']}")
    print(f"{'-'*65}")
    print(f"  Total devices found: {len(devices)}\n")


def save_csv(devices, subnet):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"network_scan_{timestamp}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["IP Address", "MAC Address", "Hostname", "Method"])
        writer.writeheader()
        writer.writerows(devices)
    print(f"  Results saved to: {filename}")



def main():
    parser = argparse.ArgumentParser(description="Local network scanner")
    parser.add_argument("--subnet", default=None, help="Subnet to scan e.g. 192.168.1.0/24")
    parser.add_argument("--mode", choices=["arp", "ping", "auto"], default="auto",
                        help="Scan mode: arp (needs scapy+root), ping, or auto (tries ARP first)")
    args = parser.parse_args()

    subnet = args.subnet or get_local_subnet()
    print(f"\n")
    print(f"  NETWORK SCANNER")
    print(f"  Target Subnet : {subnet}")
    print(f"  Scan Mode     : {args.mode}")
    print(f"  Started       : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n")

    devices = None

    if args.mode in ("arp", "auto"):
        devices = arp_scan(subnet)

    if devices is None or args.mode == "ping":
        devices = ping_scan(subnet)

    print_results(devices)

    if devices:
        save = input("Save results to CSV? (y/n): ").strip().lower()
        if save == "y":
            save_csv(devices, subnet)


if __name__ == "__main__":
    main()
