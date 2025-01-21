#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Analysis Tool
Performs ICMP/UDP/TCP checks, OS detection, SNMP queries, traceroutes
Includes SSH connectivity, logging, scheduling, and concurrency
"""

import argparse
import subprocess
import sys
import os
import socket
import time
import re
import json
import csv
import threading
import queue
import logging
import sched
import configparser
from datetime import datetime

# Optional libraries
try:
    import matplotlib.pyplot as plt
    import networkx as nx
except ImportError:
    plt = None
    nx = None

try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        getCmd, ObjectType, ObjectIdentity
    )
except ImportError:
    pass

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
except ImportError:
    pass

# OS detection (Scapy)
try:
    from scapy.all import sr1, IP, TCP
except ImportError:
    sr1 = None

# SSH check
try:
    import paramiko
except ImportError:
    paramiko = None

###############################################################################
# Logging setup
###############################################################################

logger = logging.getLogger("netanalysis")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

###############################################################################
# Configuration handling
###############################################################################

def load_config_file(path):
    # Reads config from .ini file
    config = configparser.ConfigParser()
    if os.path.exists(path):
        config.read(path)
    return config

###############################################################################
# Utilities
###############################################################################

def ip_to_int(ip):
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
           (int(parts[2]) << 8) + int(parts[3])

def int_to_ip(num):
    return ".".join([
        str(num >> 24 & 255),
        str(num >> 16 & 255),
        str(num >> 8 & 255),
        str(num & 255),
    ])

def parse_ip_range(ip_range):
    # e.g. 192.168.1.1-192.168.1.5
    pattern = r"(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)"
    match = re.match(pattern, ip_range.strip())
    if not match:
        return [ip_range.strip()]
    start_ip = match.group(1)
    end_ip = match.group(2)
    return expand_ip_range(start_ip, end_ip)

def expand_ip_range(start_ip, end_ip):
    start = ip_to_int(start_ip)
    end = ip_to_int(end_ip)
    return [int_to_ip(i) for i in range(start, end + 1)]

def is_reachable(ip, count=1, timeout=2):
    # Ping
    cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]
    try:
        output = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, universal_newlines=True
        )
        if "0 received" in output:
            return False
        return True
    except subprocess.CalledProcessError:
        return False

def average_ping_time(ip, attempts=4):
    # Ping average
    times = []
    for _ in range(attempts):
        start = time.time()
        if is_reachable(ip, count=1, timeout=2):
            times.append((time.time() - start)*1000)
        else:
            times.append(None)
    valid = [x for x in times if x is not None]
    if not valid:
        return None
    return sum(valid)/len(valid)

def traceroute(ip, max_hops=30):
    # Trace
    res = []
    cmd = ["traceroute", "-m", str(max_hops), ip]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
        )
        for line in proc.stdout:
            res.append(line.strip())
        proc.wait()
    except FileNotFoundError:
        res.append("Traceroute not available.")
    return res

def get_snmp_data(ip, community="public", oid="1.3.6.1.2.1.1.1.0"):
    # SNMP GET
    try:
        from pysnmp.hlapi import (
            SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
            getCmd, ObjectType, ObjectIdentity
        )
    except ImportError:
        return "pysnmp not installed."
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161), timeout=1, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        return f"SNMP error: {errorIndication}"
    elif errorStatus:
        return f"SNMP error: {errorStatus.prettyPrint()}"
    else:
        for varBind in varBinds:
            return f"{varBind}"

def resolve_hostname(ip):
    # DNS
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def check_tcp_ports(ip, ports):
    # TCP scan
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((ip, port))
            s.close()
            open_ports.append(port)
        except:
            pass
    return open_ports

def check_udp_ports(ip, ports):
    # UDP scan (basic)
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        try:
            s.sendto(b"", (ip, port))
            s.recvfrom(1024)
            open_ports.append(port)
        except:
            pass
        finally:
            s.close()
    return open_ports

def detect_os(ip):
    # Very naive OS detection (TCP SYN -> typical port)
    # Returns "Unknown" if scapy not installed
    if sr1 is None:
        return "Unknown"
    try:
        # Example: sending SYN to port 80
        pkt = IP(dst=ip)/TCP(dport=80, flags="S")
        response = sr1(pkt, timeout=1, verbose=0)
        if not response:
            return "Unknown"
        # Inspect flags or window size for naive fingerprinting
        window_size = response[TCP].window
        if window_size == 64240:
            return "Linux/Unix-like"
        elif window_size == 8192:
            return "Windows"
        else:
            return "Unknown"
    except:
        return "Unknown"

def ssh_connect_test(ip, user, passwd, port=22):
    # Basic SSH test
    if not paramiko:
        return False
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=port, username=user, password=passwd, timeout=2)
        client.close()
        return True
    except:
        return False

###############################################################################
# Concurrency - Thread worker
###############################################################################

def worker_target(
    ip, community, max_hops, do_snmp, tcp_ports, udp_ports,
    do_os_detect, ssh_creds
):
    data = {}
    data["ip"] = ip
    data["hostname"] = resolve_hostname(ip)
    data["reachable"] = is_reachable(ip)
    data["os_guess"] = None
    data["avg_ping_ms"] = None
    data["traceroute"] = []
    data["snmp_data"] = None
    data["open_tcp_ports"] = []
    data["open_udp_ports"] = []
    data["ssh_accessible"] = None
    if data["reachable"]:
        data["avg_ping_ms"] = average_ping_time(ip)
        data["traceroute"] = traceroute(ip, max_hops)
        if do_snmp:
            data["snmp_data"] = get_snmp_data(ip, community)
        if tcp_ports:
            data["open_tcp_ports"] = check_tcp_ports(ip, tcp_ports)
        if udp_ports:
            data["open_udp_ports"] = check_udp_ports(ip, udp_ports)
        if do_os_detect:
            data["os_guess"] = detect_os(ip)
        if ssh_creds:
            user, passwd = ssh_creds
            data["ssh_accessible"] = ssh_connect_test(ip, user, passwd, port=22)
    return data

###############################################################################
# Concurrency - Thread pool
###############################################################################

def run_analysis_concurrent(
    targets, community, max_hops, do_snmp,
    tcp_ports, udp_ports, do_os_detect,
    ssh_creds, threads
):
    from concurrent.futures import ThreadPoolExecutor
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = []
        for ip in targets:
            future = executor.submit(
                worker_target,
                ip,
                community,
                max_hops,
                do_snmp,
                tcp_ports,
                udp_ports,
                do_os_detect,
                ssh_creds
            )
            future_map.append(future)
        for f in future_map:
            results.append(f.result())
    return results

###############################################################################
# Plotting
###############################################################################

def create_ping_plot(results, out_file="ping_times.png"):
    if not plt:
        return
    valids = [r for r in results if r["reachable"]]
    ips = [r["ip"] for r in valids]
    times = [r["avg_ping_ms"] if r["avg_ping_ms"] else 0 for r in valids]
    plt.figure(figsize=(10, 5))
    plt.bar(ips, times, color='blue')
    plt.title("Average Ping (ms)")
    plt.xlabel("IP")
    plt.ylabel("Time (ms)")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(out_file)
    plt.close()

def create_topology_graph(results, out_file="topology.png"):
    if not nx:
        return
    G = nx.Graph()
    for r in results:
        G.add_node(r["ip"], reachable=r["reachable"])
        for line in r["traceroute"]:
            parts = line.split()
            if len(parts) >= 2:
                hop_ip = parts[1]
                # check if it's an IP
                if re.match(r"(\d+\.){3}\d+", hop_ip):
                    G.add_node(hop_ip)
                    G.add_edge(r["ip"], hop_ip)
    plt.figure(figsize=(10, 7))
    layout = nx.spring_layout(G, k=0.7)
    node_colors = [
        "lightgreen" if G.nodes[n].get("reachable", False) else "lightgray"
        for n in G.nodes()
    ]
    nx.draw_networkx(
        G, layout, node_size=600, node_color=node_colors, font_size=8
    )
    plt.title("Network Topology")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(out_file)
    plt.close()

###############################################################################
# Reporting
###############################################################################

def generate_pdf_report(results, filename="network_report.pdf"):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        logger.info("reportlab not installed, skipping PDF report.")
        return
    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4
    text_obj = c.beginText(50, height - 50)
    text_obj.setFont("Helvetica", 12)
    text_obj.textLine("Network Analysis Report")
    text_obj.moveCursor(0, 20)
    for r in results:
        line = (
            f"IP: {r['ip']}, Host: {r['hostname']}, Reachable: {r['reachable']}, "
            f"OS: {r['os_guess']}, Ports: TCP {r['open_tcp_ports']} UDP {r['open_udp_ports']}, "
            f"SSH: {r['ssh_accessible']}"
        )
        text_obj.textLine(line)
        text_obj.moveCursor(0, 10)
    c.drawText(text_obj)
    c.showPage()
    c.save()

###############################################################################
# Exporters
###############################################################################

def export_json(results, filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

def export_csv(results, filename):
    headers = [
        "ip", "hostname", "reachable", "os_guess",
        "avg_ping_ms", "snmp_data", "open_tcp_ports",
        "open_udp_ports", "ssh_accessible"
    ]
    with open(filename, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in results:
            row = {
                "ip": r["ip"],
                "hostname": r["hostname"],
                "reachable": r["reachable"],
                "os_guess": r["os_guess"],
                "avg_ping_ms": r["avg_ping_ms"],
                "snmp_data": r["snmp_data"],
                "open_tcp_ports": r["open_tcp_ports"],
                "open_udp_ports": r["open_udp_ports"],
                "ssh_accessible": r["ssh_accessible"]
            }
            writer.writerow(row)

###############################################################################
# Main analysis logic
###############################################################################

def run_network_analysis(
    targets,
    community="public",
    max_hops=30,
    do_snmp=False,
    do_plot=False,
    tcp_ports=None,
    udp_ports=None,
    do_os_detect=False,
    ssh_creds=None,
    threads=5
):
    if not tcp_ports:
        tcp_ports = [22, 80, 443]
    if not udp_ports:
        udp_ports = [53, 123]
    results = run_analysis_concurrent(
        targets=targets,
        community=community,
        max_hops=max_hops,
        do_snmp=do_snmp,
        tcp_ports=tcp_ports,
        udp_ports=udp_ports,
        do_os_detect=do_os_detect,
        ssh_creds=ssh_creds,
        threads=threads
    )
    if do_plot:
        create_ping_plot(results)
        create_topology_graph(results)
    return results

###############################################################################
# Scheduling
###############################################################################

def schedule_scan(interval, targets, args):
    # Schedules repeated scans
    s = sched.scheduler(time.time, time.sleep)
    def scan_job():
        logger.info("Scheduled scan triggered.")
        res = run_network_analysis(
            targets,
            community=args.community,
            max_hops=args.max_hops,
            do_snmp=args.snmp,
            do_plot=args.plot,
            tcp_ports=args.tcp_ports,
            udp_ports=args.udp_ports,
            do_os_detect=args.os_detect,
            ssh_creds=args.ssh_creds,
            threads=args.threads
        )
        if args.json_out:
            export_json(res, args.json_out)
        if args.csv_out:
            export_csv(res, args.csv_out)
        if args.pdf_report:
            generate_pdf_report(res, args.pdf_report)
        s.enter(interval, 1, scan_job, ())
    # Schedule first run
    s.enter(interval, 1, scan_job, ())
    s.run()

###############################################################################
# CLI
###############################################################################

def main():
    parser = argparse.ArgumentParser(
        description="Extensive network analysis, scanning, OS detection, concurrency"
    )
    parser.add_argument(
        "-t", "--targets", nargs="+", required=False,
        help="IPs or ranges (e.g. 192.168.1.1-192.168.1.10)"
    )
    parser.add_argument(
        "--config", default=None,
        help="Optional config file (INI)"
    )
    parser.add_argument(
        "-c", "--community", default="public",
        help="SNMP community"
    )
    parser.add_argument(
        "-m", "--max-hops", type=int, default=30,
        help="Traceroute max hops"
    )
    parser.add_argument("--snmp", action="store_true", help="SNMP data")
    parser.add_argument("--plot", action="store_true", help="Generate plots")
    parser.add_argument("--os-detect", action="store_true", help="OS detection")
    parser.add_argument("--threads", type=int, default=5, help="Thread pool size")
    parser.add_argument(
        "--tcp-ports", nargs="*", type=int,
        help="TCP ports to scan (space separated)"
    )
    parser.add_argument(
        "--udp-ports", nargs="*", type=int,
        help="UDP ports to scan"
    )
    parser.add_argument(
        "--ssh-creds", nargs=2, metavar=("USER", "PASS"),
        help="SSH user pass for connectivity test"
    )
    parser.add_argument("--json-out", default=None, help="Export to JSON")
    parser.add_argument("--csv-out", default=None, help="Export to CSV")
    parser.add_argument("--pdf-report", default=None, help="PDF report")
    parser.add_argument(
        "--schedule-interval", type=int, default=None,
        help="Run periodically every X seconds"
    )

    args = parser.parse_args()

    # If config file provided
    config = None
    if args.config:
        config = load_config_file(args.config)
        if config and "SCAN" in config:
            # Example usage from config
            if not args.targets and "targets" in config["SCAN"]:
                args.targets = config["SCAN"]["targets"].split()
            if args.tcp_ports is None and "tcp_ports" in config["SCAN"]:
                args.tcp_ports = list(map(int, config["SCAN"]["tcp_ports"].split()))
            if args.udp_ports is None and "udp_ports" in config["SCAN"]:
                args.udp_ports = list(map(int, config["SCAN"]["udp_ports"].split()))
            if not args.ssh_creds and "ssh_user" in config["SCAN"] and "ssh_pass" in config["SCAN"]:
                args.ssh_creds = (config["SCAN"]["ssh_user"], config["SCAN"]["ssh_pass"])

    if not args.targets:
        logger.error("No targets specified.")
        sys.exit(1)

    # Expand IP ranges
    expanded_targets = []
    for item in args.targets:
        expanded_targets.extend(parse_ip_range(item))
    expanded_targets = list(set(expanded_targets))
    expanded_targets.sort(key=lambda x: ip_to_int(x))

    # Run scheduling or direct
    if args.schedule_interval:
        logger.info("Scheduling mode active.")
        schedule_scan(args.schedule_interval, expanded_targets, args)
    else:
        results = run_network_analysis(
            targets=expanded_targets,
            community=args.community,
            max_hops=args.max_hops,
            do_snmp=args.snmp,
            do_plot=args.plot,
            tcp_ports=args.tcp_ports,
            udp_ports=args.udp_ports,
            do_os_detect=args.os_detect,
            ssh_creds=args.ssh_creds,
            threads=args.threads
        )
        if args.json_out:
            export_json(results, args.json_out)
        if args.csv_out:
            export_csv(results, args.csv_out)
        if args.pdf_report:
            generate_pdf_report(results, args.pdf_report)

        for r in results:
            if r["reachable"]:
                info = (
                    f"{r['ip']} (Host: {r['hostname']}), OS: {r['os_guess']}, "
                    f"Ping: {('%.2f' % r['avg_ping_ms']) if r['avg_ping_ms'] else 'N/A'}, "
                    f"TCP: {r['open_tcp_ports']}, UDP: {r['open_udp_ports']}, "
                    f"SSH: {r['ssh_accessible']}"
                )
                print(info)
            else:
                print(f"{r['ip']} unreachable")

if __name__ == "__main__":
    if os.geteuid() != 0:
        logger.warning("Some operations may require root privileges.")
    main()
