import io
import tempfile
import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Any

from ml.config import FEATURE_COLUMNS

def extract_flows_from_pcap(pcap_bytes: bytes, filename: str = "capture.pcap", max_flows: int = 5000) -> pd.DataFrame:
    """
    Parses a raw Wireshark .pcap / .pcapng file, aggregates raw packets
    into bidirectional 5-tuple network flows, and computes the 46 CICIoT features.
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
    except ImportError:
        raise ImportError("Scapy is required for PCAP parsing. Run `pip install scapy`.")

    # Write to a temporary file for Scapy reading
    suffix = ".pcapng" if filename.lower().endswith(".pcapng") else ".pcap"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(pcap_bytes)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except Exception:
            pass

    if not packets or len(packets) == 0:
        raise ValueError("The uploaded Wireshark capture contains 0 valid packets.")

    # Group packets by bidirectional flow key: (ip_a, ip_b, port_a, port_b, proto)
    flows = defaultdict(lambda: {
        "timestamps": [],
        "lengths": [],
        "directions": [], # 'fwd' or 'bwd'
        "src_ip": None,
        "dst_ip": None,
        "src_port": 0,
        "dst_port": 0,
        "proto": 0,
        "flags": defaultdict(int),
        "protocols_seen": set(),
        "header_lengths": []
    })

    for pkt in packets:
        t = float(pkt.time)
        pkt_len = len(pkt)
        
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_port = 0
        dst_port = 0
        proto_num = 0
        hdr_len = 20

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto_num = pkt[IP].proto
            hdr_len = pkt[IP].ihl * 4 if hasattr(pkt[IP], 'ihl') else 20
        elif ARP in pkt:
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            proto_num = 2054 # Custom ARP marker
            hdr_len = 28
        else:
            continue

        # Ports & flags
        is_tcp = False
        is_udp = False
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            is_tcp = True
            flags = pkt[TCP].flags
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            is_udp = True
            flags = None
        else:
            flags = None

        # Canonical flow key (smaller endpoint first)
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        if ep1 <= ep2:
            flow_key = (src_ip, dst_ip, src_port, dst_port, proto_num)
            direction = 'fwd'
        else:
            flow_key = (dst_ip, src_ip, dst_port, src_port, proto_num)
            direction = 'bwd'

        f = flows[flow_key]
        if f["src_ip"] is None:
            f["src_ip"] = src_ip
            f["dst_ip"] = dst_ip
            f["src_port"] = src_port
            f["dst_port"] = dst_port
            f["proto"] = proto_num

        f["timestamps"].append(t)
        f["lengths"].append(pkt_len)
        f["directions"].append(direction)
        f["header_lengths"].append(hdr_len)

        if is_tcp and flags is not None:
            try:
                flag_val = int(flags)
                if flag_val & 0x02: f["flags"]["syn"] += 1
                if flag_val & 0x10: f["flags"]["ack"] += 1
                if flag_val & 0x04: f["flags"]["rst"] += 1
                if flag_val & 0x01: f["flags"]["fin"] += 1
                if flag_val & 0x08: f["flags"]["psh"] += 1
                if flag_val & 0x20: f["flags"]["urg"] += 1
                if flag_val & 0x40: f["flags"]["ece"] += 1
                if flag_val & 0x80: f["flags"]["cwr"] += 1
            except Exception:
                pass

        # Application-level heuristic detection
        ports = {src_port, dst_port}
        if 80 in ports: f["protocols_seen"].add("HTTP")
        if 443 in ports: f["protocols_seen"].add("HTTPS")
        if 53 in ports: f["protocols_seen"].add("DNS")
        if 23 in ports: f["protocols_seen"].add("Telnet")
        if 22 in ports: f["protocols_seen"].add("SSH")
        if 67 in ports or 68 in ports: f["protocols_seen"].add("DHCP")
        if is_tcp: f["protocols_seen"].add("TCP")
        if is_udp: f["protocols_seen"].add("UDP")
        if ICMP in pkt: f["protocols_seen"].add("ICMP")
        if ARP in pkt: f["protocols_seen"].add("ARP")

    # Build flow dataframe
    flow_rows = []
    for (src_ip, dst_ip, src_port, dst_port, proto_num), f in flows.items():
        n_pkts = len(f["lengths"])
        dur = max(f["timestamps"]) - min(f["timestamps"])
        dur = max(dur, 0.0001) # Avoid div zero
        
        fwd_pkts = sum(1 for d in f["directions"] if d == 'fwd')
        bwd_pkts = sum(1 for d in f["directions"] if d == 'bwd')
        
        rate = n_pkts / dur
        srate = fwd_pkts / dur
        drate = bwd_pkts / dur
        
        lengths = np.array(f["lengths"], dtype=np.float32)
        tot_sum = float(np.sum(lengths))
        min_len = float(np.min(lengths))
        max_len = float(np.max(lengths))
        avg_len = float(np.mean(lengths))
        std_len = float(np.std(lengths)) if n_pkts > 1 else 0.0
        
        # Inter-arrival times
        if n_pkts > 1:
            ts = np.sort(f["timestamps"])
            iats = np.diff(ts)
            mean_iat = float(np.mean(iats))
        else:
            mean_iat = 0.0

        fl = f["flags"]
        protos = f["protocols_seen"]

        row = {
            "device_id": f"{f['src_ip']} -> {f['dst_ip']}:{f['dst_port']}",
            "flow_duration": dur,
            "Header_Length": float(np.mean(f["header_lengths"])),
            "Protocol Type": float(proto_num),
            "Duration": dur,
            "Rate": rate,
            "Srate": srate,
            "Drate": drate,
            "fin_flag_number": 1.0 if fl["fin"] > 0 else 0.0,
            "syn_flag_number": 1.0 if fl["syn"] > 0 else 0.0,
            "rst_flag_number": 1.0 if fl["rst"] > 0 else 0.0,
            "psh_flag_number": 1.0 if fl["psh"] > 0 else 0.0,
            "ack_flag_number": 1.0 if fl["ack"] > 0 else 0.0,
            "ece_flag_number": 1.0 if fl["ece"] > 0 else 0.0,
            "cwr_flag_number": 1.0 if fl["cwr"] > 0 else 0.0,
            "ack_count": float(fl["ack"]),
            "syn_count": float(fl["syn"]),
            "fin_count": float(fl["fin"]),
            "urg_count": float(fl["urg"]),
            "rst_count": float(fl["rst"]),
            "HTTP": 1.0 if "HTTP" in protos else 0.0,
            "HTTPS": 1.0 if "HTTPS" in protos else 0.0,
            "DNS": 1.0 if "DNS" in protos else 0.0,
            "Telnet": 1.0 if "Telnet" in protos else 0.0,
            "SSH": 1.0 if "SSH" in protos else 0.0,
            "IRC": 0.0,
            "TCP": 1.0 if "TCP" in protos else 0.0,
            "UDP": 1.0 if "UDP" in protos else 0.0,
            "DHCP": 1.0 if "DHCP" in protos else 0.0,
            "ARP": 1.0 if "ARP" in protos else 0.0,
            "ICMP": 1.0 if "ICMP" in protos else 0.0,
            "IPv": 1.0,
            "LLC": 0.0,
            "Tot sum": tot_sum,
            "Min": min_len,
            "Max": max_len,
            "AVG": avg_len,
            "Std": std_len,
            "Tot size": tot_sum,
            "IAT": mean_iat,
            "Number": float(n_pkts),
            "Magnitue": float(np.sqrt(avg_len)) if avg_len > 0 else 0.0,
            "Radius": float(std_len * 0.5),
            "Covariance": 0.0,
            "Variance": float(std_len ** 2),
            "Weight": float(n_pkts)
        }

        # Fill any missing feature columns with 0.0
        for col in FEATURE_COLUMNS:
            if col not in row:
                row[col] = 0.0

        flow_rows.append(row)

    df_flows = pd.DataFrame(flow_rows)
    if max_flows and len(df_flows) > max_flows:
        df_flows = df_flows.iloc[:max_flows]
    return df_flows
