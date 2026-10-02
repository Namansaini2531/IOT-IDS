import numpy as np
from typing import List, Dict, Any
from ml.config import FEATURE_COLUMNS

# Friendly feature descriptions for security analysts
FEATURE_DESCRIPTIONS = {
    "flow_duration": "Flow Duration (Seconds)",
    "Rate": "Total Packet Rate (pkts/sec)",
    "Srate": "Source-to-Destination Packet Rate",
    "Drate": "Destination-to-Source Packet Rate",
    "Header_Length": "Packet Header Length",
    "syn_flag_number": "SYN Flag Active (Connection Initiation)",
    "syn_count": "Abnormal SYN Count",
    "ack_flag_number": "ACK Flag Active",
    "HTTP": "HTTP Web Traffic Protocol",
    "HTTPS": "Encrypted HTTPS Web Traffic",
    "DNS": "DNS Query / Response",
    "Telnet": "Telnet Protocol (Common Botnet Target)",
    "SSH": "SSH Protocol",
    "TCP": "TCP Transport Layer",
    "UDP": "UDP Transport Layer",
    "ICMP": "ICMP Ping / Flood Protocol",
    "Tot sum": "Total Flow Data Volume (Bytes)",
    "AVG": "Average Packet Size (Bytes)",
    "IAT": "Inter-Arrival Time Between Packets",
    "Number": "Number of Aggregated Packets",
}

def extract_top_deviations(
    feature_deviations: np.ndarray,
    raw_feature_values: np.ndarray,
    top_k: int = 4
) -> List[Dict[str, Any]]:
    """
    Identifies which specific network features contributed most to the anomaly
    score by ranking reconstruction deviations against the benign baseline.
    """
    # Sort indices by deviation score descending
    top_indices = np.argsort(feature_deviations)[::-1][:top_k]
    
    deviations = []
    for idx in top_indices:
        feat_name = FEATURE_COLUMNS[idx]
        dev_score = float(feature_deviations[idx])
        raw_val = float(raw_feature_values[idx])
        
        friendly_label = FEATURE_DESCRIPTIONS.get(feat_name, feat_name)
        
        deviations.append({
            "feature": feat_name,
            "label": friendly_label,
            "deviation_score": round(dev_score, 4),
            "observed_value": round(raw_val, 4),
            "severity": "CRITICAL" if dev_score > 10.0 else ("HIGH" if dev_score > 4.0 else "MODERATE")
        })
        
    return deviations
