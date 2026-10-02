import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODELS_DIR = BASE_DIR / "models"

# Ensure directories exist
PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# CICIoT2023 46 standard network flow features
FEATURE_COLUMNS = [
    "flow_duration",
    "Header_Length",
    "Protocol Type",
    "Duration",
    "Rate",
    "Srate",
    "Drate",
    "fin_flag_number",
    "syn_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "ack_flag_number",
    "ece_flag_number",
    "cwr_flag_number",
    "ack_count",
    "syn_count",
    "fin_count",
    "urg_count",
    "rst_count",
    "HTTP",
    "HTTPS",
    "DNS",
    "Telnet",
    "SMTP",
    "SSH",
    "IRC",
    "TCP",
    "UDP",
    "DHCP",
    "ARP",
    "ICMP",
    "IPv",
    "LLC",
    "Tot sum",
    "Min",
    "Max",
    "AVG",
    "Std",
    "Tot size",
    "IAT",
    "Number",
    "Magnitue",
    "Radius",
    "Covariance",
    "Variance",
    "Weight"
]

LABEL_COLUMN = "label"

# Hierarchical Attack Family Mapping for Stage 2 Multi-class Classifier
ATTACK_FAMILY_MAP = {
    # Benign
    "BenignTraffic": "Benign",
    "Benign": "Benign",
    
    # Mirai Botnet Family
    "Mirai-greeth_flood": "Mirai-Botnet",
    "Mirai-udpplain": "Mirai-Botnet",
    "Mirai-greip_flood": "Mirai-Botnet",
    "Mirai": "Mirai-Botnet",
    
    # DDoS Attacks
    "DDoS-ICMP_Flood": "DDoS",
    "DDoS-UDP_Flood": "DDoS",
    "DDoS-TCP_Flood": "DDoS",
    "DDoS-SYN_Flood": "DDoS",
    "DDoS-RSTFINFlood": "DDoS",
    "DDoS-PSHACK_Flood": "DDoS",
    "DDoS-HTTP_Flood": "DDoS",
    "DDoS-UDP_Fragmentation": "DDoS",
    "DDoS-ICMP_Fragmentation": "DDoS",
    "DDoS-SlowLoris": "DDoS",
    
    # DoS Attacks
    "DoS-UDP_Flood": "DoS",
    "DoS-TCP_Flood": "DoS",
    "DoS-SYN_Flood": "DoS",
    "DoS-HTTP_Flood": "DoS",
    
    # Reconnaissance / Scanning
    "Recon-PortScan": "Reconnaissance",
    "Recon-OSScan": "Reconnaissance",
    "Recon-HostDiscovery": "Reconnaissance",
    "Recon-PingSweep": "Reconnaissance",
    "VulnerabilityScan": "Reconnaissance",
    
    # Web & Brute-Force Attacks
    "SqlInjection": "BruteForce-Web",
    "CommandInjection": "BruteForce-Web",
    "Backdoor_Malware": "BruteForce-Web",
    "DictionaryBruteForce": "BruteForce-Web",
    "BrowserHijacking": "BruteForce-Web",
    "XSS": "BruteForce-Web",
    
    # Spoofing & MITM
    "MITM-ArpSpoofing": "Spoofing",
    "DNS_Spoofing": "Spoofing"
}

# Autoencoder Hyperparameters (Stage 1)
AUTOENCODER_CONFIG = {
    "input_dim": len(FEATURE_COLUMNS),
    "hidden_dims": [32, 16, 8],  # Bottleneck of 8 latent dimensions
    "learning_rate": 1e-3,
    "batch_size": 128,
    "epochs": 20,
    "anomaly_percentile": 98.0  # 98th percentile reconstruction error threshold on validation benign
}

# Classifier Config (Stage 2)
CLASSIFIER_CONFIG = {
    "n_estimators": 120,
    "max_depth": 16,
    "random_state": 42,
    "n_jobs": -1
}

# Risk Engine Weights
RISK_WEIGHTS = {
    "anomaly_weight": 0.5,
    "attack_prob_weight": 0.3,
    "historical_weight": 0.2
}
