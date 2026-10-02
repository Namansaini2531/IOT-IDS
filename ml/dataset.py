import os
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler, LabelEncoder

from ml.config import (
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    ATTACK_FAMILY_MAP,
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    MODELS_DIR,
)

def generate_synthetic_ciciot_dataset(num_samples: int = 25000, random_state: int = 42) -> pd.DataFrame:
    """
    Generates a high-fidelity simulated CICIoT2023 benchmark flow dataset with realistic
    feature distributions, IoT device IDs, and attack signatures for rapid prototyping & validation.
    """
    np.random.seed(random_state)
    
    # Class distribution (mimicking realistic IoT attack lab benchmark)
    classes = [
        ("BenignTraffic", 0.25),
        ("DDoS-ICMP_Flood", 0.15),
        ("DDoS-UDP_Flood", 0.15),
        ("DDoS-SYN_Flood", 0.10),
        ("DoS-UDP_Flood", 0.10),
        ("Mirai-greeth_flood", 0.10),
        ("Recon-PortScan", 0.08),
        ("SqlInjection", 0.04),
        ("MITM-ArpSpoofing", 0.03),
    ]
    
    labels = []
    for cls_name, weight in classes:
        count = int(num_samples * weight)
        labels.extend([cls_name] * count)
    
    # Fill any rounding discrepancy
    while len(labels) < num_samples:
        labels.append("BenignTraffic")
    
    n = len(labels)
    labels = np.array(labels)
    np.random.shuffle(labels)

    # Simulated IoT device pool
    iot_devices = [
        "iot-camera-01 (192.168.1.101)",
        "iot-thermostat-02 (192.168.1.102)",
        "iot-smartlock-03 (192.168.1.103)",
        "iot-bulb-gateway-04 (192.168.1.104)",
        "iot-smartplug-05 (192.168.1.105)",
        "iot-nvr-storage-06 (192.168.1.106)"
    ]
    device_col = np.random.choice(iot_devices, size=n)

    data = {}
    
    # Generate realistic network flow features based on class type
    for col in FEATURE_COLUMNS:
        data[col] = np.zeros(n, dtype=np.float32)

    for i in range(n):
        lbl = labels[i]
        
        if lbl == "BenignTraffic":
            # Normal periodic low-volume IoT telemetry
            flow_dur = np.random.exponential(1.5) + 0.05
            pkt_rate = np.random.uniform(0.5, 25.0)
            data["flow_duration"][i] = flow_dur
            data["Rate"][i] = pkt_rate
            data["Srate"][i] = pkt_rate * 0.6
            data["Drate"][i] = pkt_rate * 0.4
            data["Header_Length"][i] = np.random.choice([20, 32, 54])
            data["Protocol Type"][i] = np.random.choice([6.0, 17.0])  # TCP/UDP
            data["TCP"][i] = 1.0 if data["Protocol Type"][i] == 6.0 else 0.0
            data["UDP"][i] = 1.0 if data["Protocol Type"][i] == 17.0 else 0.0
            data["HTTP"][i] = 1.0 if np.random.rand() < 0.15 else 0.0
            data["HTTPS"][i] = 1.0 if np.random.rand() < 0.20 else 0.0
            data["DNS"][i] = 1.0 if np.random.rand() < 0.25 else 0.0
            data["syn_flag_number"][i] = 1.0 if np.random.rand() < 0.05 else 0.0
            data["ack_flag_number"][i] = 1.0 if np.random.rand() < 0.85 else 0.0
            data["Tot sum"][i] = np.random.uniform(100, 2500)
            data["Min"][i] = np.random.uniform(40, 80)
            data["Max"][i] = np.random.uniform(150, 1500)
            data["AVG"][i] = np.random.uniform(70, 600)
            data["Std"][i] = np.random.uniform(5, 120)
            data["Tot size"][i] = data["Tot sum"][i]
            data["IAT"][i] = np.random.uniform(0.01, 1.2)
            data["Number"][i] = np.random.randint(2, 35)
            data["Magnitue"][i] = np.sqrt(data["AVG"][i])
            data["Radius"][i] = data["Std"][i] * 0.5
            data["Weight"][i] = data["Number"][i] * 1.1

        elif "DDoS" in lbl or "DoS" in lbl:
            # Massive packet rates, floods, anomalous flags
            flow_dur = np.random.uniform(0.001, 0.5)
            pkt_rate = np.random.uniform(500.0, 15000.0)
            data["flow_duration"][i] = flow_dur
            data["Rate"][i] = pkt_rate
            data["Srate"][i] = pkt_rate * 0.95
            data["Drate"][i] = pkt_rate * 0.05
            data["Header_Length"][i] = np.random.choice([20, 40, 60])
            
            if "ICMP" in lbl:
                data["Protocol Type"][i] = 1.0
                data["ICMP"][i] = 1.0
            elif "UDP" in lbl:
                data["Protocol Type"][i] = 17.0
                data["UDP"][i] = 1.0
            else:
                data["Protocol Type"][i] = 6.0
                data["TCP"][i] = 1.0
                data["syn_flag_number"][i] = 1.0 if "SYN" in lbl else 0.0
                data["ack_flag_number"][i] = 0.0 if "SYN" in lbl else 1.0

            data["Tot sum"][i] = np.random.uniform(5000, 80000)
            data["Min"][i] = 40.0
            data["Max"][i] = np.random.uniform(1000, 1500)
            data["AVG"][i] = np.random.uniform(800, 1400)
            data["Std"][i] = np.random.uniform(0.1, 15)
            data["Tot size"][i] = data["Tot sum"][i]
            data["IAT"][i] = np.random.uniform(0.0001, 0.005)
            data["Number"][i] = np.random.randint(150, 2000)
            data["Magnitue"][i] = np.sqrt(data["AVG"][i])
            data["Radius"][i] = data["Std"][i] * 0.2
            data["Weight"][i] = data["Number"][i] * 2.0

        elif "Mirai" in lbl:
            # Botnet command & control / brute sync flood
            flow_dur = np.random.uniform(0.01, 0.8)
            pkt_rate = np.random.uniform(200.0, 4500.0)
            data["flow_duration"][i] = flow_dur
            data["Rate"][i] = pkt_rate
            data["Srate"][i] = pkt_rate * 0.9
            data["Drate"][i] = pkt_rate * 0.1
            data["Telnet"][i] = 1.0 if np.random.rand() < 0.6 else 0.0
            data["SSH"][i] = 1.0 if np.random.rand() < 0.3 else 0.0
            data["TCP"][i] = 1.0
            data["syn_flag_number"][i] = 1.0
            data["ack_flag_number"][i] = 0.2
            data["Tot sum"][i] = np.random.uniform(2000, 25000)
            data["Min"][i] = 50.0
            data["Max"][i] = 1200.0
            data["AVG"][i] = np.random.uniform(400, 900)
            data["Std"][i] = np.random.uniform(10, 80)
            data["Tot size"][i] = data["Tot sum"][i]
            data["IAT"][i] = np.random.uniform(0.001, 0.08)
            data["Number"][i] = np.random.randint(40, 600)
            data["Magnitue"][i] = np.sqrt(data["AVG"][i])
            data["Radius"][i] = data["Std"][i] * 0.8
            data["Weight"][i] = data["Number"][i] * 1.5

        elif "Recon" in lbl:
            # Rapid port scan, high SYN, low duration, small packets
            flow_dur = np.random.uniform(0.001, 0.05)
            pkt_rate = np.random.uniform(50.0, 800.0)
            data["flow_duration"][i] = flow_dur
            data["Rate"][i] = pkt_rate
            data["Srate"][i] = pkt_rate * 0.98
            data["Drate"][i] = pkt_rate * 0.02
            data["TCP"][i] = 1.0
            data["syn_flag_number"][i] = 1.0
            data["syn_count"][i] = np.random.randint(10, 100)
            data["Tot sum"][i] = np.random.uniform(60, 300)
            data["Min"][i] = 40.0
            data["Max"][i] = 60.0
            data["AVG"][i] = 48.0
            data["Std"][i] = 2.0
            data["Tot size"][i] = data["Tot sum"][i]
            data["IAT"][i] = np.random.uniform(0.001, 0.03)
            data["Number"][i] = np.random.randint(1, 5)
            data["Magnitue"][i] = np.sqrt(data["AVG"][i])
            data["Radius"][i] = 1.0
            data["Weight"][i] = data["Number"][i]

        else:
            # Web/Brute-force / Spoofing
            flow_dur = np.random.uniform(0.5, 4.0)
            pkt_rate = np.random.uniform(5.0, 120.0)
            data["flow_duration"][i] = flow_dur
            data["Rate"][i] = pkt_rate
            data["Srate"][i] = pkt_rate * 0.5
            data["Drate"][i] = pkt_rate * 0.5
            data["HTTP"][i] = 1.0 if "Sql" in lbl else 0.0
            data["ARP"][i] = 1.0 if "Arp" in lbl else 0.0
            data["DNS"][i] = 1.0 if "DNS" in lbl else 0.0
            data["TCP"][i] = 1.0 if "Arp" not in lbl else 0.0
            data["Tot sum"][i] = np.random.uniform(800, 15000)
            data["Min"][i] = 54.0
            data["Max"][i] = 1500.0
            data["AVG"][i] = np.random.uniform(300, 1100)
            data["Std"][i] = np.random.uniform(50, 350)
            data["Tot size"][i] = data["Tot sum"][i]
            data["IAT"][i] = np.random.uniform(0.01, 0.4)
            data["Number"][i] = np.random.randint(10, 80)
            data["Magnitue"][i] = np.sqrt(data["AVG"][i])
            data["Radius"][i] = data["Std"][i] * 0.7
            data["Weight"][i] = data["Number"][i] * 1.2

    df = pd.DataFrame(data)
    df["device_id"] = device_col
    df[LABEL_COLUMN] = labels
    df["attack_family"] = [ATTACK_FAMILY_MAP.get(lbl, "Other") for lbl in labels]
    
    return df


def load_or_prepare_dataset(num_samples: int = 30000, random_state: int = 42):
    """
    Loads raw dataset if available in data/raw, or generates benchmark CICIoT data.
    Builds the session/device-aware splits and fits/saves the RobustScaler.
    """
    csv_files = list(RAW_DATA_DIR.glob("*.csv"))
    if csv_files:
        print(f"[Dataset] Loading raw data from {csv_files[0]}...")
        df = pd.read_csv(csv_files[0])
        # Map attack family if not present
        if "attack_family" not in df.columns and LABEL_COLUMN in df.columns:
            df["attack_family"] = df[LABEL_COLUMN].map(lambda x: ATTACK_FAMILY_MAP.get(x, "Other"))
    else:
        print(f"[Dataset] No raw CSV found in {RAW_DATA_DIR}. Generating synthetic CICIoT2023 dataset ({num_samples} flows)...")
        df = generate_synthetic_ciciot_dataset(num_samples=num_samples, random_state=random_state)
        # Save raw reference copy
        df.to_csv(RAW_DATA_DIR / "ciciot2023_sample.csv", index=False)
        print(f"[Dataset] Saved sample raw dataset to {RAW_DATA_DIR / 'ciciot2023_sample.csv'}")

    # Ensure all required features are present
    missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")

    # 1. Device-aware split to avoid near-duplicate leakage
    devices = df["device_id"].unique() if "device_id" in df.columns else [f"dev_{i}" for i in range(6)]
    np.random.seed(random_state)
    
    # Train devices vs Test devices
    train_devices, test_devices = train_test_split(devices, test_size=0.33, random_state=random_state)
    
    if "device_id" in df.columns:
        train_mask = df["device_id"].isin(train_devices)
        test_mask = df["device_id"].isin(test_devices)
        train_df = df[train_mask].copy()
        test_df = df[test_mask].copy()
    else:
        train_df, test_df = train_test_split(df, test_size=0.33, random_state=random_state, stratify=df["attack_family"])

    # 2. Fit Scaler ONLY on Benign training traffic to prevent data contamination
    benign_train_mask = (train_df["attack_family"] == "Benign")
    benign_train_df = train_df[benign_train_mask]
    
    scaler = RobustScaler()
    scaler.fit(benign_train_df[FEATURE_COLUMNS])
    joblib.dump(scaler, MODELS_DIR / "scaler.joblib")
    print(f"[Dataset] Saved RobustScaler to {MODELS_DIR / 'scaler.joblib'}")

    # 3. Label Encoder for Attack Families
    label_encoder = LabelEncoder()
    label_encoder.fit(df["attack_family"])
    joblib.dump(label_encoder, MODELS_DIR / "label_encoder.joblib")
    print(f"[Dataset] Saved LabelEncoder to {MODELS_DIR / 'label_encoder.joblib'} (Classes: {list(label_encoder.classes_)})")

    # 4. Create Stage 1 Train (Benign only) and Validation (Benign only)
    benign_tr, benign_val = train_test_split(benign_train_df, test_size=0.20, random_state=random_state)
    
    # Save splits
    benign_tr.to_csv(PROCESSED_DATA_DIR / "train_benign_autoencoder.csv", index=False)
    benign_val.to_csv(PROCESSED_DATA_DIR / "val_benign_autoencoder.csv", index=False)
    train_df.to_csv(PROCESSED_DATA_DIR / "train_supervised_classifier.csv", index=False)
    test_df.to_csv(PROCESSED_DATA_DIR / "test_evaluation_set.csv", index=False)
    
    print(f"[Dataset] Generated Splits:")
    print(f"  - Stage 1 Autoencoder Train (Benign only): {len(benign_tr)} flows")
    print(f"  - Stage 1 Autoencoder Val (Benign only):   {len(benign_val)} flows")
    print(f"  - Stage 2 Classifier Train (Full):        {len(train_df)} flows")
    print(f"  - Evaluation Test Set (Unseen Devices):   {len(test_df)} flows")

    return benign_tr, benign_val, train_df, test_df

if __name__ == "__main__":
    load_or_prepare_dataset()
