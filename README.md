### Networkie - An Advanced Network Analysis Python Script

A versatile and powerful Python-based network analysis tool for performing ICMP/UDP/TCP checks, OS detection, SNMP queries, traceroutes, and SSH connectivity tests. 

**Supports logging, scheduling, and concurrency for efficient network management.**

---

## Key Features

1. **ICMP, TCP, and UDP Checks**:
   - Test the reachability of hosts using ICMP.
   - Scan for open TCP and UDP ports.

2. **OS Detection**:
   - Guess the operating system of a target using TCP SYN fingerprinting (requires Scapy).

3. **SNMP Queries**:
   - Fetch SNMP data for additional insights (requires `pysnmp`).

4. **Traceroute**:
   - Trace the route packets take to a target host.

5. **SSH Connectivity Test**:
   - Test SSH access using provided credentials (requires `paramiko`).

6. **Logging**:
   - Detailed logging of operations for debugging and analysis.

7. **Scheduling**:
   - Automate scans at regular intervals.

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




