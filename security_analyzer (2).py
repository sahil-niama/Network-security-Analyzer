from scapy.all import rdpcap
from collections import Counter
import pandas as pd
import sys

def analyze_pcap(file_path):
    print(f"analyzing file: {file_path}\n")

    packets = []
    try:
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print("Error: File not found. Please check the path.")
        return

    ports=[]
    urls = []

    for pkt in packets:
        if pkt.haslayer("TCP"):
            ports.append(pkt["TCP"].dport)
            ports.append(pkt["TCP"].sport)

        if pkt.haslayer("Raw"):
            try:
                payload = pkt["Raw"].load.decode(errors="ignore")
                if "GET" in payload or "POST" in payload:
                    parts = payload.split()
                    for part in parts:
                        if part.startwith("/") or part.startwith("http"):
                           urls.append(part)
                           break
            except:
                pass

    port_counts = Counter(ports)
    df_ports = pd.DataFrame(port_counts.most_common(5), columns=["Port","Count"])
    print("\n--- Top 5 Ports ---")
    print(df_ports.to_string(index=False))


    unique_urls = list(set(urls))[:5]
    if unique_urls:
       df_urls = pd.DataFrame(unique_urls, columns=["Extracted URLs"])
       print("\n--- Extracted URLs ---")
       print(df_urls.to_string(index=False))
    else:
        print("\nNo URLs found(might be encrypted HTTPS traffic).")

    print("\n--- Security Warnings ---")
    danger_ports = [22, 23, 445]
    warnings_found = False
    for p in danger_ports:
        if p in port_counts:
            print(f"WARNING: Traffic on risky port {p}")
            warnings_found = True
    if not warnings_found:
        print("No risky ports detected")


file_name = r"http.cap"
analyze_pcap(file_name)