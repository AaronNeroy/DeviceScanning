Discovers all active devices on a local network subnet using ARP (with administrator priveleges) or ICMP ping (without). Results are displayed in a formatted table and can be exported to CSV.

## Features

- Diagnoses your local subnet (e.g. `192.168.1.0/24`)
- **ARP mode** — retrieves MAC addresses as well (but requires `scapy` + admin/root)
- **Ping mode** — no permissions needed
- Reverse DNS hostname resolution for each device
- Results are sorted by IP address
- Can export to timestamped CSV file if wanted

## Requirements

scapy for ARP using 'pip install scapy' in terminal


## Usage
python network_scanner.py

# Specify a subnet
python network_scanner.py --subnet 192.168.0.0/24

# Force ping mode (no admin needed)
python network_scanner.py --mode ping


## Example Output


  NETWORK SCANNER
  Target Subnet : 192.168.1.0/24
  Scan Mode     : auto


[*] Starting ARP scan on 192.168.1.0/24 ...

-----------------------------------------------------------------
  IP Address         MAC Address            Hostname
-----------------------------------------------------------------
  192.168.1.1        aa:bb:cc:dd:ee:01      router.local
  192.168.1.5        aa:bb:cc:dd:ee:05      DESKTOP-ABC
  192.168.1.12       aa:bb:cc:dd:ee:0c      N/A
-----------------------------------------------------------------
  Total devices found: 3


## Skills Demonstrated

- Python scripting and argument parsing with `argparse`
- Networking concepts: ARP, ICMP, subnets, DNS
- Use of `scapy` for low-level network packets
- CSV data export
