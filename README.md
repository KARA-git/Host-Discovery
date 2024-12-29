# Host-Discovery
This Python script is designed to perform network host discovery and scanning using various techniques, including ARP scanning, ping scanning, and TCP connect scanning.
Below is a detailed analysis of the script's components and functionality:

**Purpose**
The script combines multiple network scanning techniques to identify hosts and services in a network. It allows users to perform the following operations:
- **ARP Scan**: Identifies devices in the local network by sending ARP requests.
- **Ping Scan**: Uses ICMP echo requests to check if hosts are reachable.
- **TCP Connect Scan**: Identifies open TCP ports on hosts by attempting to establish connections.
 
**Code Breakdown**

**1. Importing Necessary Libraries**
The script uses various Python libraries:
- `subprocess`: Executes shell commands, used here for ping operations.
- `argparse`: Handles command-line arguments.
- `scapy.all`: Provides low-level network functions like ARP and packet crafting.
- `ipaddress`: Simplifies IP address and network manipulation.
- `socket`: Manages TCP connections.
- `threading`: Allows parallel execution of tasks.
- `time` and `sys`: Control execution flow and handle system-level interactions.

**2. ARP Scan**
The `arp_scan()` function sends ARP requests to discover hosts on the same subnet.  
**How it works:**
- Constructs an ARP request targeting the specified IP.
- Combines it with an Ethernet frame for broadcast.
- Sends the frame using `srp()` from Scapy and processes responses.

**Example Output:**
```
IP: 192.168.1.10 	 MAC: 00:1A:2B:3C:4D:5E
```

**3. Ping Scan**
The `ping_scan()` function checks the availability of hosts in a subnet using ICMP echo requests.  
**How it works:**
- Generates all host IPs in the specified subnet using `ipaddress`.
- Executes the `ping` command for each host.
- Displays hosts that respond to the ping.

**4. TCP Connect Scan**
The `tcp_connect_scan()` function attempts to establish a TCP connection to the specified port.  
**How it works:**
- Creates a socket and tries to connect to the target IP and port.
- If the connection is successful, the port is marked as "open."
- Uses `connect_ex()` to check connection status and handles errors gracefully.

**Threaded Execution:**
The `tcp_scan_thread()` function wraps `tcp_connect_scan()` in threads for parallel scanning of multiple ports. A global delay variable (`delay`) ensures timing control between threads to avoid overwhelming the network.

**5. Command-Line Interface**
The script uses `argparse` to handle input arguments, enabling flexible configuration:
- `--arp`: Perform ARP scan.
- `--ping`: Perform Ping scan.
- `--tcp`: Perform TCP connect scan.
- `--ports`: Specify ports for TCP scan (default: 80, 443).
- `-T`: Set scan timing (1 = slowest, 5 = fastest).

**Example Usage:**
```bash
# Perform an ARP scan
python scanner.py 192.168.1.0/24 --arp

# Perform a Ping scan
python scanner.py 192.168.1.0/24 --ping

# Perform a TCP connect scan on specific ports
python scanner.py 192.168.1.1 --tcp --ports 22,80,443
```

**6. Timing Adjustments**
The `adjust_timing()` function modifies the `delay` variable based on user-selected timing options (`-T1` to `-T5`), providing flexibility for slower or faster scans.

**7. Main Execution Flow**
The `main()` function coordinates the entire script:
- Parses arguments.
- Adjusts timing.
- Determines which scans to perform based on user input.
- Executes the selected scans.

If no specific scan is selected, the script defaults to performing all three types.

**Strengths of the Script**
- **Multi-functionality**: Supports ARP, Ping, and TCP connect scans in one tool.
- **Threading**: Uses threads to optimize TCP scanning speed.
- **User Flexibility**: Command-line arguments and timing options provide customizable scans.
- **Error Handling**: Gracefully handles invalid inputs and connection errors.


**Limitations**
- **ICMP Blockage**: Ping scans may fail if ICMP packets are blocked by firewalls.
- **Permission Requirement**: ARP scans need administrative privileges to execute.
- **Resource Usage**: High thread counts or fast scans may strain system resources or trigger network alarms.


**Potential Enhancements**
1. **Output Logging**: Save results to a file for later analysis.
2. **Protocol Support**: Extend to support UDP scans or other protocols.
3. **Interactive Mode**: Add a mode for live scanning without requiring command-line arguments.

**Conclusion**
This Python script is a powerful tool for host discovery and network scanning. Its modular design and use of threading make it efficient and versatile, suitable for both network administrators and security enthusiasts. By combining multiple scanning techniques, it provides comprehensive insights into network activity and potential vulnerabilities.

