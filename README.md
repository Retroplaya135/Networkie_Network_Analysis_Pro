### Networkie - An Advanced Network Analysis Python Script

A versatile and powerful Python-based network analysis tool for performing ICMP/UDP/TCP checks, OS detection, SNMP queries, traceroutes, and SSH connectivity tests. 

**Supports logging, scheduling, and concurrency for efficient network management.**

---

## Key Features

1. **ICMP, TCP, and UDP Checks**:
   - Test the reachability of hosts using ICMP.
   - Scan for open TCP and UDP ports.

2. **OS Detection**:
   - Guess the operating system of a target using TCP SYN fingerprinting (requires Scapy). For installing Scapy docs at https://scapy.net

3. **SNMP Queries**:
   - Fetch SNMP data for additional insights (requires `pysnmp`). For installing pysnmp see docs at https://pypi.org/project/pysnmp/

4. **Traceroute**:
   - Trace the route packets take to a target host.

5. **SSH Connectivity Test**:
   - Test SSH access using provided credentials (requires `paramiko`). For installing paramiko see docs at https://www.paramiko.org.

6. **Logging**:
   - Detailed logging of operations for debugging and analysis.

7. **Scheduling**:
   - Automate scans at regular intervals. Replace or use along with Cron jobs if required.

8. **Concurrency**:
   - Perform tasks efficiently with multithreading.

9. **Report Generation**:
   - Export results in JSON, CSV, or PDF format.
   - Create visual reports using matplotlib and networkx.
  
---

## Installation

1. Clone the repository:
   ```bash
   git clone 
   cd network-analysis-tool
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure the tool is run with root privileges for certain features:
   ```bash
   sudo python network_analysis.py
   ```
---


---

## Usage Examples

### 1. Basic ICMP Ping
Test if a host is reachable:
```bash
python network_analysis.py -t 192.168.1.1
```


### 2. Scan a Range of IPs
Check multiple hosts for reachability:
```bash
python network_analysis.py -t 192.168.1.1-192.168.1.10
```

### 3. Perform OS Detection
Detect the operating system of a host:
```bash
python network_analysis.py -t 192.168.1.1 --os-detect
```

### 4. SNMP Query
Fetch system information using SNMP:
```bash
python network_analysis.py -t 192.168.1.1 --snmp -c public
```

### 5. Scan Specific TCP and UDP Ports
Check for open TCP and UDP ports:
```bash
python network_analysis.py -t 192.168.1.1 --tcp-ports 22 80 443 --udp-ports 53 123
```

### 6. Traceroute
Trace the route to a target host:
```bash
python network_analysis.py -t 192.168.1.1 --max-hops 20
```

### 7. Test SSH Connectivity
Check if SSH access is available with the given credentials:
```bash
python network_analysis.py -t 192.168.1.1 --ssh-creds username password
```

### 8. Generate a PDF Report
Save results in a PDF file:
```bash
python network_analysis.py -t 192.168.1.1-192.168.1.10 --pdf-report network_report.pdf
```

### 9. Automate Scans with Scheduling
Run scans every 60 seconds:
```bash
python network_analysis.py -t 192.168.1.1 --schedule-interval 60
```

### 10. Export Results to JSON or CSV
Save results for further analysis:
```bash
python network_analysis.py -t 192.168.1.1 --json-out results.json --csv-out results.csv
```

---

## Use Cases

### **Network Diagnostics**
- Quickly identify unreachable hosts in a network.
- Trace packet routes to troubleshoot connectivity issues.

### **Security Audits**
- Detect open TCP and UDP ports to identify potential vulnerabilities.
- Test SSH connectivity to ensure secure access.

### **Infrastructure Monitoring**
- Perform regular pings and SNMP queries to monitor device health.
- Use scheduled scans to automate checks.

### **OS and Device Identification**
- Use OS detection to identify the type of devices in your network.

### **Visual Analysis**
- Generate topology graphs to visualize your network.
- Export ping times to understand latency across devices.

---


## Sample Scenarios

### Scenario 1: Troubleshooting a Server Issue
A server in your network is unreachable. Use the tool to:
1. Ping the server to confirm reachability.
2. Perform a traceroute to identify network issues.
3. Check open ports to ensure services are running.

### Scenario 2: Monitoring Multiple Devices
You manage multiple devices in a network and want to:
1. Ping all devices in a range to check for connectivity.
2. Perform SNMP queries to fetch health data.
3. Generate a PDF report for documentation.

### Scenario 3: Conducting a Security Scan
As part of a security audit, you need to:
1. Scan TCP and UDP ports for open services.
2. Test SSH connectivity with provided credentials.
3. Save results in JSON format for further analysis.



---

## Requirements

- Python 3.8+
- Root privileges for certain features (e.g., traceroute, port scans).
- Libraries:
  - Required: `argparse`, `subprocess`, `socket`, `configparser`
  - Optional: `pysnmp`, `paramiko`, `matplotlib`, `networkx`, `reportlab`

---


## Contributing

We welcome contributions! Feel free to fork the repository, create a new branch, and submit a pull request.

---

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT). Feel free to use and distribute. The software is provided as is without an gaurenty or warrenty. 


