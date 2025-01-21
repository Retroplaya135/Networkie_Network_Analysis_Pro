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





