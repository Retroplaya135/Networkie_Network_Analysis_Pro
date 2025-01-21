#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Analysis Script
Performs ping, traceroute, SNMP queries, port scans, and plotting
Generates extensive data exports and optional reports
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

###############################################################################
# Utility functions
###############################################################################

def is_reachable(ip, count=1, timeout=2):
    # Simple ping
    try:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]
        output = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, universal_newlines=True
        )
        if "0 received" in output:
            return False
        return True
    except subprocess.CalledProcessError:
        return False

def average_ping_time(ip, attempts=4):
    # Measure average ping
    times = []
    for _ in range(attempts):
        start = time.time()
        ok = is_reachable(ip, count=1, timeout=2)
        end = time.time()
        if ok:
            delta = (end - start) * 1000
            times.append(delta)
        else:
            times.append(None)
    valid = [t for t in times if t is not None]
    if not valid:
        return None
    return sum(valid) / len(valid)

def traceroute(ip, max_hops=30):
    # Perform traceroute
    res = []
    try:
        cmd = ["traceroute", "-m", str(max_hops), ip]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True
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

def parse_ip_range(ip_range):
    # Parse IP or range
    # Example: 192.168.1.1-192.168.1.5
    pattern = r"(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)"
    match = re.match(pattern, ip_range.strip())
    if not match:
        return [ip_range.strip()]
    start_ip = match.group(1)
    end_ip = match.group(2)
    return expand_ip_range(start_ip, end_ip)

def expand_ip_range(start_ip, end_ip):
    # Expand range into list
    start = ip_to_int(start_ip)
    end = ip_to_int(end_ip)
    return [int_to_ip(i) for i in range(start, end + 1)]

def ip_to_int(ip):
    # IP -> int
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
           (int(parts[2]) << 8) + int(parts[3])

def int_to_ip(num):
    # int -> IP
    return ".".join([
        str(num >> 24 & 255),
        str(num >> 16 & 255),
        str(num >> 8 & 255),
        str(num & 255),
    ])

def resolve_hostname(ip):
    # DNS lookup
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def check_ports(ip, ports=[22, 80, 443]):
    # Basic TCP port scan
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

###############################################################################
# Concurrency wrappers
###############################################################################

def worker_target(ip, community, max_hops, do_snmp, custom_ports):
    # Thread worker
    data = {}
    reachable = is_reachable(ip)
    data["ip"] = ip
    data["hostname"] = resolve_hostname(ip)
    data["reachable"] = reachable
    if reachable:
        data["avg_ping_ms"] = average_ping_time(ip)
        data["traceroute"] = traceroute(ip, max_hops=max_hops)
        if do_snmp:
            data["snmp_data"] = get_snmp_data(ip, community)
        else:
            data["snmp_data"] = None
        data["open_ports"] = check_ports(ip, custom_ports)
    else:
        data["avg_ping_ms"] = None
        data["traceroute"] = []
        data["snmp_data"] = None
        data["open_ports"] = []
    return data

def run_analysis_concurrent(
    targets, community, max_hops, do_snmp, custom_ports, threads
):
    # Thread pool
    from concurrent.futures import ThreadPoolExecutor
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for ip in targets:
            futures.append(
                executor.submit(
                    worker_target, ip, community, max_hops, do_snmp, custom_ports
                )
            )
        for f in futures:
            results.append(f.result())
    return results

###############################################################################
# Plotting
###############################################################################

def create_ping_plot(results, out_file="ping_times.png"):
    # Plot ping times
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
    # Simple topology
    if not nx:
        return
    G = nx.Graph()
    for r in results:
        G.add_node(r["ip"], reachable=r["reachable"])
        for line in r["traceroute"]:
            parts = line.split()
            if len(parts) >= 2:
                hop_ip = parts[1]
                if hop_ip != "*" and re.match(r"(\d+\.){3}\d+", hop_ip):
                    G.add_node(hop_ip)
                    G.add_edge(r["ip"], hop_ip)
    plt.figure(figsize=(10, 7))
    layout = nx.spring_layout(G, k=0.5)
    node_colors = ["lightgreen" if G.nodes[n].get("reachable") else "lightgray"
                   for n in G.nodes()]
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
    # Simple PDF report
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        print("reportlab not installed.")
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
            f"AvgPing: {r['avg_ping_ms']}, Ports: {r['open_ports']}"
        )
        text_obj.textLine(line)
        text_obj.moveCursor(0, 10)
    c.drawText(text_obj)
    c.showPage()
    c.save()

###############################################################################
# Data export
###############################################################################

def export_json(results, filename):
    # Save as JSON
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

def export_csv(results, filename):
    # Save as CSV
    headers = [
        "ip", "hostname", "reachable",
        "avg_ping_ms", "snmp_data", "open_ports"
    ]
    with open(filename, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in results:
            row = {
                "ip": r["ip"],
                "hostname": r["hostname"],
                "reachable": r["reachable"],
                "avg_ping_ms": r["avg_ping_ms"],
                "snmp_data": r["snmp_data"],
                "open_ports": r["open_ports"]
            }
            writer.writerow(row)

###############################################################################
# Main logic
###############################################################################

def run_network_analysis(
    targets, community="public", max_hops=30, do_snmp=False,
    do_plot=False, custom_ports=None, threads=5
):
    if not custom_ports:
        custom_ports = [22, 80, 443]
    results = run_analysis_concurrent(
        targets, community, max_hops, do_snmp, custom_ports, threads
    )
    if do_plot:
        create_ping_plot(results)
        create_topology_graph(results)
    return results

###############################################################################
# CLI
###############################################################################

def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive network analysis with multi-threading"
    )
    parser.add_argument(
        "-t", "--targets", nargs="+", required=True,
        help="Target IPs or ranges (e.g. 192.168.0.1 or 192.168.0.1-192.168.0.10)"
    )
    parser.add_argument(
        "-c", "--community", default="public",
        help="SNMP community string"
    )
    parser.add_argument(
        "-m", "--max-hops", type=int, default=30,
        help="Maximum hops for traceroute"
    )
    parser.add_argument(
        "--snmp", action="store_true",
        help="Enable SNMP data collection"
    )
    parser.add_argument(
        "--ports", nargs="*", type=int,
        default=None,
        help="Ports to scan (space-separated)"
    )
    parser.add_argument(
        "--threads", type=int, default=5,
        help="Number of worker threads"
    )
    parser.add_argument(
        "--plot", action="store_true",
        help="Create ping time and topology plots"
    )
    parser.add_argument(
        "--json-out", default=None,
        help="Export results to JSON"
    )
    parser.add_argument(
        "--csv-out", default=None,
        help="Export results to CSV"
    )
    parser.add_argument(
        "--pdf-report", default=None,
        help="Generate PDF report"
    )
    args = parser.parse_args()

    expanded_targets = []
    for item in args.targets:
        expanded_targets.extend(parse_ip_range(item))
    expanded_targets = list(set(expanded_targets))
    expanded_targets.sort(key=lambda x: ip_to_int(x))

    results = run_network_analysis(
        expanded_targets,
        community=args.community,
        max_hops=args.max_hops,
        do_snmp=args.snmp,
        do_plot=args.plot,
        custom_ports=args.ports,
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
            info = f"{r['ip']} (Host: {r['hostname']}), avg ping: "
            info += f"{r['avg_ping_ms']:.2f} ms" if r["avg_ping_ms"] else "N/A"
            info += f", open ports: {r['open_ports']}"
            print(info)
        else:
            print(f"{r['ip']} unreachable")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Warning: Some features may require root privileges.")
    main()

