import subprocess
import argparse
from scapy.all import ARP, Ether, srp
import ipaddress
import socket
import threading
import time
import sys

# Global variable for timing control
delay = 0.5  # Default delay between threads for scanning

# ARP Scan
def arp_scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    result = srp(arp_request_broadcast, timeout=10, verbose=False)[0]

    for i in range(0, len(result)):
        print(f"IP: {result[i][1].psrc} \t MAC: {result[i][1].hwsrc}")

# Ping Scan for entire subnet
def ping_scan(network):
    # Generate all IP addresses
    network = ipaddress.ip_network(network, strict=False)
    for ip in network.hosts():  # Skip network and broadcast address, scan only host's IP
        
        command = ["ping", "-c", "1", str(ip)]
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if response.returncode == 0:
            print(f"Ping Scan: {ip} is alive")

# TCP Connect Scan with threading
def tcp_connect_scan(ip, port):
    try:
        # Create a socket object and attempt to connect to the host on the given port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout after 1 second
        result = sock.connect_ex((ip, port))
        if result == 0:  # Connection was successful
            print(f"TCP Connect Scan: Port {port} on {ip} is open")
        sock.close()
    except socket.error:
        pass

# Wrapper for TCP scan with threading
def tcp_scan_thread(ip, ports):
    threads = []
    for port in ports:
        t = threading.Thread(target=tcp_connect_scan, args=(ip, port))
        threads.append(t)
        t.start()
        time.sleep(delay)  # Sleep to control scan timing (based on -T option)
    
    for t in threads:
        t.join()

# Parse command-line arguments
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target IP or network ")
    parser.add_argument("-a", "--arp", help="Perform ARP scan", action="store_true")
    parser.add_argument("-p", "--ping", help="Perform Ping scan", action="store_true")
    parser.add_argument("-t", "--tcp", help="Perform TCP connect scan", action="store_true")
    parser.add_argument("--ports", help="Ports to scan (default=80,443)")
    parser.add_argument("-T", "--timing", type=int, choices=[1, 2, 3, 4, 5], default=3, help="Timing option (1-5), default is 3")
    return parser.parse_args()

# Adjust delay based on timing option (-T1 to -T5)
def adjust_timing(timing_option):
    global delay
    if timing_option == 1:
        delay = 2.0  # Slow scan
    elif timing_option == 2:
        delay = 1.5  # Slower scan
    elif timing_option == 3:
        delay = 1.0  # Moderate speed (default)
    elif timing_option == 4:
        delay = 0.5  # Faster scan
    elif timing_option == 5:
        delay = 0.2  # Fastest scan

def main():
    args = get_args()
    adjust_timing(args.timing)

    # If no option is selected, perform all scans
    if not any([args.arp, args.ping, args.tcp]):
        args.arp = True
        args.ping = True
        args.tcp = True

    # Perform ARP scan if option is chosen
    if args.arp:
        print("Performing ARP scan...")
        arp_scan(args.target)

    # Perform Ping scan if option is chosen
    if args.ping:
        print("Performing Ping scan...")
        ping_scan(args.target)

    # Perform TCP connect scan if option is chosen
    if args.tcp:
        print("Performing TCP Connect Scan...")
        if args.ports:
            # Split the ports string and convert to integers
            try:
                ports = [int(port) for port in args.ports.split(",")]
            except ValueError:
                print("Error: Invalid port number in the list.")
                sys.exit(1)
        else:
            # If no ports are provided, use default ports
            print("No ports provided, using default ports: 80,443")
            ports = [80, 443]  # Default ports
        
        if ipaddress.ip_network(args.target, strict=False):
            network = ipaddress.ip_network(args.target, strict=False)
            for ip in network.hosts():
                tcp_scan_thread(str(ip), ports)
        else:
            tcp_scan_thread(args.target, ports)

if __name__ == "__main__":
    main()
