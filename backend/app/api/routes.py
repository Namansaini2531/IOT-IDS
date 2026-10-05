import io
import json
import gzip
import math
import torch
import pandas as pd
import numpy as np
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from typing import Dict, Any, Optional, List

from ml.config import MODELS_DIR, FEATURE_COLUMNS
from backend.app.services.inference import pipeline_instance
from backend.app.services.traffic_simulator import traffic_simulator

router = APIRouter()

class FlowInferenceRequest(BaseModel):
    device_id: Optional[str] = "iot-camera-01 (192.168.1.101)"
    flow_features: Dict[str, float]

# Extensive column aliases for mapping arbitrary datasets (Wireshark, Zeek, Snort, CICFlowMeter, NetFlow, Suricata, etc.)
COLUMN_ALIASES = {
    "flow_duration": ["duration", "dur", "flow_duration", "time_delta", "time", "flow_dur", "f_duration", "delta", "td"],
    "Header_Length": ["header_length", "hdr_len", "header_len", "ihl", "tot_hdr_len", "fwd_header_length", "bwd_header_length", "head_len"],
    "Protocol Type": ["protocol", "proto", "protocol_type", "ip_proto", "trans_protocol", "proto_num", "ip_p"],
    "Duration": ["duration", "dur", "flow_duration", "time_delta", "flow_duration_sec", "dur_sec"],
    "Rate": ["rate", "packet_rate", "pkt_rate", "packets_per_sec", "flow_rate", "pkts_per_sec", "packets/s", "flow_pkts_s"],
    "Srate": ["srate", "src_rate", "source_rate", "fwd_rate", "fwd_pkts_per_sec", "fwd_packets/s"],
    "Drate": ["drate", "dst_rate", "dest_rate", "bwd_rate", "bwd_pkts_per_sec", "bwd_packets/s"],
    "fin_flag_number": ["fin", "fin_flag", "tcp_fin", "fin_flag_number", "fin_flag_cnt", "fin_cnt", "f_flag"],
    "syn_flag_number": ["syn", "syn_flag", "tcp_syn", "syn_flag_number", "syn_flag_cnt", "syn_cnt", "s_flag"],
    "rst_flag_number": ["rst", "rst_flag", "tcp_rst", "rst_flag_number", "rst_flag_cnt", "rst_cnt", "r_flag"],
    "psh_flag_number": ["psh", "psh_flag", "tcp_psh", "psh_flag_number", "psh_flag_cnt", "psh_cnt", "p_flag"],
    "ack_flag_number": ["ack", "ack_flag", "tcp_ack", "ack_flag_number", "ack_flag_cnt", "ack_cnt", "a_flag"],
    "ece_flag_number": ["ece", "ece_flag", "tcp_ece", "ece_flag_number", "ece_cnt", "e_flag"],
    "cwr_flag_number": ["cwr", "cwr_flag", "tcp_cwr", "cwr_flag_number", "cwr_cnt", "c_flag"],
    "ack_count": ["ack_count", "ack_cnt", "num_acks", "ack"],
    "syn_count": ["syn_count", "syn_cnt", "num_syns", "syn"],
    "fin_count": ["fin_count", "fin_cnt", "num_fins", "fin"],
    "urg_count": ["urg_count", "urg_cnt", "num_urgs", "urg", "urg_flag_cnt"],
    "rst_count": ["rst_count", "rst_cnt", "num_rsts", "rst"],
    "HTTP": ["http", "is_http", "service_http", "proto_http"],
    "HTTPS": ["https", "is_https", "tls", "ssl", "service_ssl", "service_https"],
    "DNS": ["dns", "is_dns", "service_dns", "proto_dns"],
    "Telnet": ["telnet", "is_telnet", "service_telnet", "proto_telnet"],
    "SMTP": ["smtp", "is_smtp", "service_smtp", "proto_smtp"],
    "SSH": ["ssh", "is_ssh", "service_ssh", "proto_ssh"],
    "IRC": ["irc", "is_irc", "service_irc", "proto_irc"],
    "TCP": ["tcp", "is_tcp", "proto_tcp"],
    "UDP": ["udp", "is_udp", "proto_udp"],
    "DHCP": ["dhcp", "is_dhcp", "service_dhcp", "proto_dhcp", "bootp"],
    "ARP": ["arp", "is_arp", "proto_arp"],
    "ICMP": ["icmp", "is_icmp", "proto_icmp"],
    "IPv": ["ipv", "is_ipv4", "is_ip", "ip_version", "ip_ver"],
    "LLC": ["llc", "is_llc"],
    "Tot sum": ["tot_sum", "tot_bytes", "total_bytes", "bytes", "length", "size", "bytes_total", "flow_bytes", "tot_len", "flow_byts/s", "total_length", "tot_payload_bytes"],
    "Min": ["min", "min_size", "min_pkt_len", "pkt_len_min", "min_packet_size", "fwd_pkt_len_min"],
    "Max": ["max", "max_size", "max_pkt_len", "pkt_len_max", "max_packet_size", "fwd_pkt_len_max"],
    "AVG": ["avg", "avg_size", "mean_size", "packet_size_avg", "mean_pkt_len", "pkt_len_mean", "avg_packet_size", "fwd_pkt_len_mean"],
    "Std": ["std", "std_size", "std_pkt_len", "pkt_len_std", "std_packet_size", "fwd_pkt_len_std"],
    "Tot size": ["tot_size", "tot_sum", "tot_bytes", "total_bytes", "tot_len", "total_size", "fwd_header_length"],
    "IAT": ["iat", "inter_arrival_time", "flow_iat_mean", "mean_iat", "iat_mean", "flow_iat_avg"],
    "Number": ["number", "packet_count", "packets", "pkt_count", "tot_packets", "total_packets", "tot_pkts", "flow_pkts/s", "count"],
    "Magnitue": ["magnitue", "magnitude", "pkt_magnitude"],
    "Radius": ["radius", "pkt_radius"],
    "Covariance": ["covariance", "pkt_covariance"],
    "Variance": ["variance", "var", "pkt_variance"],
    "Weight": ["weight", "packet_weight", "pkt_weight"]
}

def map_arbitrary_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flexibly matches columns from Wireshark, Zeek, Snort, Suricata,
    or arbitrary CSV/JSON logs to the 46 features expected by the 2-Stage pipeline.
    """
    mapped_df = pd.DataFrame()
    df_cols_lower = {col.lower().replace("-", "_").replace(" ", "_").replace(".", "_"): col for col in df.columns}

    for target_col in FEATURE_COLUMNS:
        target_lower = target_col.lower().replace("-", "_").replace(" ", "_")
        if target_lower in df_cols_lower:
            mapped_df[target_col] = pd.to_numeric(df[df_cols_lower[target_lower]], errors='coerce').fillna(0.0)
        elif target_col in COLUMN_ALIASES:
            found = False
            for alias in COLUMN_ALIASES[target_col]:
                if alias in df_cols_lower:
                    mapped_df[target_col] = pd.to_numeric(df[df_cols_lower[alias]], errors='coerce').fillna(0.0)
                    found = True
                    break
            if not found:
                mapped_df[target_col] = 0.0
        else:
            mapped_df[target_col] = 0.0

    # Device or IP identification candidate search
    dev_col = None
    for candidate in ["device_id", "device", "src_ip", "source_ip", "id.orig_h", "srcip", "ip_src", "host", "source", "client", "ip"]:
        for orig_col in df.columns:
            if candidate in orig_col.lower():
                dev_col = orig_col
                break
        if dev_col:
            break

    if dev_col:
        mapped_df["device_id"] = df[dev_col].astype(str)
    else:
        # Create deterministic pseudo device identifiers based on row clustering
        mapped_df["device_id"] = [f"iot-node-{(i % 8) + 1:02d} (192.168.1.{(i % 8) + 101})" for i in range(len(df))]

    # Ground truth label capture if present in dataset
    label_col = None
    for candidate in ["label", "attack_family", "attack", "category", "label_type", "class", "threat"]:
        for orig_col in df.columns:
            if candidate == orig_col.lower() or orig_col.lower().startswith("label"):
                label_col = orig_col
                break
        if label_col:
            break

    if label_col:
        mapped_df["ground_truth"] = df[label_col].astype(str)

    return mapped_df

def parse_uploaded_file_to_df(contents: bytes, filename: str, max_rows: Optional[int] = 5000) -> tuple[pd.DataFrame, int, str]:
    """
    Universally parses uploaded binary PCAP, CSV, TSV, JSON, JSONL, Zeek logs,
    or compressed gzip logs into a normalized DataFrame ready for 2-Stage inference.
    Caps parsing to max_rows (default 5000 records) for fast sub-second analysis.
    Returns: (mapped_df, total_file_records, file_type_desc)
    """
    fn_lower = filename.lower()
    read_nrows = min(int(max_rows), 5000) if (max_rows is not None and max_rows > 0) else 5000

    # 1. Native Wireshark / Tcpdump PCAP / PCAPNG
    if fn_lower.endswith((".pcap", ".pcapng", ".cap")) or contents[:4] in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"]:
        from backend.app.services.pcap_extractor import extract_flows_from_pcap
        mapped_df = extract_flows_from_pcap(contents, filename=filename, max_flows=read_nrows)
        return mapped_df, len(mapped_df), "Wireshark Packet Capture (PCAP/PCAPNG)"

    # 2. GZIP-compressed CSV/JSON
    if fn_lower.endswith(".gz") or contents[:2] == b"\x1f\x8b":
        decompressed = gzip.decompress(contents)
        try:
            df = pd.read_csv(io.BytesIO(decompressed), nrows=read_nrows, low_memory=False)
            mapped_df = map_arbitrary_dataframe(df)
            return mapped_df, len(df), "GZIP Compressed CSV Archive"
        except Exception:
            df = pd.read_json(io.BytesIO(decompressed), nrows=read_nrows)
            mapped_df = map_arbitrary_dataframe(df)
            return mapped_df, len(df), "GZIP Compressed JSON Archive"

    # 3. JSON / JSON-Lines
    if fn_lower.endswith((".json", ".jsonl")):
        try:
            df = pd.read_json(io.BytesIO(contents), nrows=read_nrows)
        except Exception:
            try:
                df = pd.read_json(io.BytesIO(contents), lines=True, nrows=read_nrows)
            except Exception:
                raw_json = json.loads(contents.decode("utf-8", errors="replace"))
                if isinstance(raw_json, dict):
                    for key in ["data", "rows", "flows", "events", "records"]:
                        if key in raw_json and isinstance(raw_json[key], list):
                            raw_json = raw_json[key]
                            break
                if isinstance(raw_json, list) and read_nrows and len(raw_json) > read_nrows:
                    raw_json = raw_json[:read_nrows]
                df = pd.DataFrame(raw_json)
        mapped_df = map_arbitrary_dataframe(df)
        return mapped_df, len(df), "JSON / JSON-Lines Dataset"

    # 4. Zeek / Bro Log format (e.g. conn.log, dns.log, http.log)
    if fn_lower.endswith(".log") or b"#separator" in contents[:100] or b"#fields" in contents[:200]:
        try:
            text_data = contents.decode("utf-8", errors="replace")
            lines = [l for l in text_data.splitlines() if not l.startswith("#close")]
            header_line = next((l for l in lines if l.startswith("#fields")), None)
            if header_line:
                fields = header_line.replace("#fields", "").strip().split()
                data_lines = [l.split("\t") if "\t" in l else l.split() for l in lines if not l.startswith("#")]
                if read_nrows:
                    data_lines = data_lines[:read_nrows]
                df = pd.DataFrame(data_lines, columns=fields[:len(data_lines[0])] if data_lines else None)
                mapped_df = map_arbitrary_dataframe(df)
                return mapped_df, len(df), "Zeek Network Security Log"
        except Exception:
            pass

    # 5. Fast Standard C CSV Reader with fallback
    for encoding in ["utf-8", "latin1", "cp1252"]:
        try:
            df = pd.read_csv(io.BytesIO(contents), nrows=read_nrows, low_memory=False, encoding=encoding)
            mapped_df = map_arbitrary_dataframe(df)
            return mapped_df, len(df), f"CSV/Delimited Dataset ({len(df.columns)} cols)"
        except Exception:
            continue

    # Fallback default reader
    df = pd.read_csv(io.BytesIO(contents), nrows=read_nrows, encoding="latin1", low_memory=False)
    mapped_df = map_arbitrary_dataframe(df)
    return mapped_df, len(df), "CSV Dataset"

@router.get("/status")
def get_system_status():
    """
    Returns the operational status of models, thresholds, and pipeline components.
    """
    if not pipeline_instance.is_loaded:
        try:
            pipeline_instance.load_artifacts()
        except Exception as e:
            return {"status": "INITIALIZING", "error": str(e)}

    return {
        "status": "OPERATIONAL",
        "stage1_autoencoder": "Loaded (PyTorch Autoencoder)",
        "stage2_classifier": "Loaded (Random Forest Multi-Class)",
        "reconstruction_threshold": pipeline_instance.threshold,
        "features_count": len(FEATURE_COLUMNS),
        "tracked_devices_count": len(pipeline_instance.risk_engine.device_history),
        "supported_file_formats": ["PCAP (.pcap, .pcapng, .cap)", "CSV (.csv, .tsv)", "JSON (.json, .jsonl)", "Zeek Logs (.log)", "GZIP (.csv.gz)"]
    }

@router.get("/evaluation-report")
def get_evaluation_report():
    """
    Returns the comprehensive metrics report (Precision, Recall, F1 per class, Confusion Matrix, Latency).
    """
    report_path = MODELS_DIR / "evaluation_report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Evaluation report not found. Run evaluation script first.")
    
    with open(report_path, "r") as f:
        data = json.load(f)
    return data

@router.post("/predict")
def predict_single_flow(request: FlowInferenceRequest):
    """
    Classifies a manual network flow payload through the 2-Stage pipeline.
    """
    try:
        result = pipeline_instance.predict_flow(
            flow_features=request.flow_features,
            device_id=request.device_id or "manual-test-device"
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/upload-and-analyze")
async def upload_and_analyze_dataset(
    file: UploadFile = File(...),
    max_rows: int = Form(5000),
    page: int = Form(1),
    page_size: int = Form(100)
):
    """
    Universal ingestion and analysis endpoint:
    Processes Wireshark captures (.pcap, .pcapng), CSV datasets, JSON logs, or Zeek telemetry
    through the 2-Stage ML Pipeline (Autoencoder Anomaly Gate + Supervised Attack Classifier)
    with feature explainability, fleet risk quantification, and server-side pagination support.
    Scans up to 5,000 records for fast, responsive processing.
    """
    import gc
    import math

    if not pipeline_instance.is_loaded:
        pipeline_instance.load_artifacts()

    try:
        # Enforce max 5,000 records for fast cloud inference
        safe_max_rows = min(int(max_rows), 5000) if int(max_rows) > 0 else 5000

        contents = await file.read()
        if not contents or len(contents) == 0:
            raise HTTPException(status_code=400, detail="The uploaded file is empty.")

        mapped_df, total_file_records, file_type_desc = parse_uploaded_file_to_df(
            contents, file.filename, max_rows=safe_max_rows
        )

        # Release raw upload bytes from memory
        del contents
        gc.collect()

        if len(mapped_df) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file produced 0 valid network flow records.")

        if safe_max_rows and len(mapped_df) > safe_max_rows:
            mapped_df = mapped_df.iloc[:safe_max_rows]

        # Extract features matrix and scale
        X_raw = mapped_df[FEATURE_COLUMNS].values.astype(np.float32)
        X_scaled = pipeline_instance.scaler.transform(X_raw)
        
        # Stage 1: Batch PyTorch Autoencoder Anomaly Scoring
        with torch.no_grad():
            tensor_vals = torch.tensor(X_scaled, dtype=torch.float32).to(pipeline_instance.device)
            recon_errors = pipeline_instance.autoencoder.compute_reconstruction_error(tensor_vals)
            feature_deviations = pipeline_instance.autoencoder.get_feature_deviations(tensor_vals)
            del tensor_vals

        # Stage 2: Supervised Multi-class Attack Attribution
        class_probs = pipeline_instance.classifier.predict_proba(X_scaled)
        pred_class_indices = np.argmax(class_probs, axis=1)
        class_names = pipeline_instance.label_encoder.classes_
        pred_classes = class_names[pred_class_indices]
        attack_confidences = np.max(class_probs, axis=1)

        threshold = pipeline_instance.threshold
        is_anomalies = recon_errors >= threshold
        normalized_anomaly_scores = np.clip(recon_errors / (threshold * 2.5), 0.0, 1.0)

        device_ids = mapped_df["device_id"].astype(str).tolist()
        has_ground_truth = "ground_truth" in mapped_df.columns
        ground_truths = mapped_df["ground_truth"].tolist() if has_ground_truth else []

        results = []
        anomaly_count = int(np.sum(is_anomalies))
        attack_distribution = {}
        severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        high_risk_devices = set()
        device_summary = {}
        top_deviating_features_fleet = {}

        from ml.explainability import extract_top_deviations

        total_records = len(mapped_df)

        for idx in range(total_records):
            dev_id = device_ids[idx]
            is_anom = bool(is_anomalies[idx])
            raw_recon = float(recon_errors[idx])
            norm_anom = float(normalized_anomaly_scores[idx])
            pred_cls = str(pred_classes[idx])
            conf = float(attack_confidences[idx])

            if is_anom and pred_cls == "Benign":
                final_status = "Suspected Novel Anomaly"
                atk_prob = 0.65
            elif is_anom:
                final_status = pred_cls
                atk_prob = conf
            else:
                final_status = "Benign"
                atk_prob = 0.05

            # Calculate Risk Assessment
            risk_result = pipeline_instance.risk_engine.calculate_risk(
                device_id=dev_id,
                anomaly_score=norm_anom,
                attack_probability=atk_prob
            )

            severity = risk_result["severity"]
            risk_val = risk_result["risk_score"]

            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1

            if is_anom and severity in ["CRITICAL", "HIGH"]:
                high_risk_devices.add(dev_id)

            attack_distribution[final_status] = attack_distribution.get(final_status, 0) + 1

            # Extract top deviations for flow explainability (for anomalies or first 100 rows)
            top_dev = None
            if is_anom or idx < 100:
                top_devs = extract_top_deviations(feature_deviations[idx], X_raw[idx], top_k=2)
                top_dev = top_devs[0] if top_devs else None
                if top_dev:
                    feat_name = top_dev["feature"]
                    top_deviating_features_fleet[feat_name] = top_deviating_features_fleet.get(feat_name, 0) + 1

            # Aggregate Device Rollup
            if dev_id not in device_summary:
                device_summary[dev_id] = {
                    "device_id": dev_id,
                    "total_flows": 0,
                    "anomaly_flows": 0,
                    "max_risk_score": 0.0,
                    "risk_scores": [],
                    "attacks_seen": {},
                    "severities": {},
                    "top_deviating_signals": []
                }
            
            dev_rec = device_summary[dev_id]
            dev_rec["total_flows"] += 1
            if is_anom:
                dev_rec["anomaly_flows"] += 1
            dev_rec["risk_scores"].append(risk_val)
            dev_rec["max_risk_score"] = max(dev_rec["max_risk_score"], risk_val)
            dev_rec["attacks_seen"][final_status] = dev_rec["attacks_seen"].get(final_status, 0) + 1
            dev_rec["severities"][severity] = dev_rec["severities"].get(severity, 0) + 1
            
            if top_dev and len(dev_rec["top_deviating_signals"]) < 3:
                label_val = f"{top_dev['label']} ({round(top_dev['observed_value'], 1)})"
                if label_val not in dev_rec["top_deviating_signals"]:
                    dev_rec["top_deviating_signals"].append(label_val)

            # Keep row record in response (up to 500 rows to keep JSON response lightweight)
            if len(results) < 500 or is_anom:
                row_record = {
                    "row_index": idx + 1,
                    "device_id": dev_id,
                    "is_anomaly": is_anom,
                    "classification": final_status,
                    "reconstruction_error": round(raw_recon, 6),
                    "anomaly_score": round(norm_anom, 4),
                    "attack_confidence": round(conf, 4),
                    "risk_score": risk_val,
                    "severity": severity,
                    "top_deviation": top_dev
                }
                if has_ground_truth:
                    row_record["ground_truth"] = ground_truths[idx]

                results.append(row_record)

        # Format device summaries
        formatted_devices = []
        for dev_id, d in device_summary.items():
            avg_risk = sum(d["risk_scores"]) / len(d["risk_scores"]) if d["risk_scores"] else 0.0
            primary_attack = max(d["attacks_seen"].items(), key=lambda x: x[1])[0] if d["attacks_seen"] else "Benign"
            
            if d["max_risk_score"] >= 0.7 or "CRITICAL" in d["severities"]:
                overall_health = "CRITICAL"
            elif d["max_risk_score"] >= 0.4 or "HIGH" in d["severities"]:
                overall_health = "HIGH_RISK"
            elif d["anomaly_flows"] > 0 or "MEDIUM" in d["severities"]:
                overall_health = "SUSPICIOUS"
            else:
                overall_health = "BENIGN_HEALTHY"

            formatted_devices.append({
                "device_id": dev_id,
                "total_flows": d["total_flows"],
                "anomaly_flows": d["anomaly_flows"],
                "anomaly_rate": round((d["anomaly_flows"] / d["total_flows"]) * 100, 1) if d["total_flows"] > 0 else 0,
                "max_risk_score": round(d["max_risk_score"] * 100, 1),
                "avg_risk_score": round(avg_risk * 100, 1),
                "primary_attack": primary_attack,
                "overall_health": overall_health,
                "top_signals": d["top_deviating_signals"]
            })

        formatted_devices.sort(key=lambda x: x["max_risk_score"], reverse=True)

        # Sort fleet signals by frequency
        sorted_fleet_signals = sorted(top_deviating_features_fleet.items(), key=lambda x: x[1], reverse=True)[:5]
        top_signals_summary = [{"feature": f, "anomalous_occurrences": count} for f, count in sorted_fleet_signals]

        # Explicit garbage collection
        del mapped_df, X_raw, X_scaled
        gc.collect()

        total_pages = max(1, math.ceil(total_records / max(1, page_size)))

        return {
            "filename": file.filename,
            "file_type": file_type_desc,
            "page": int(page),
            "page_size": int(page_size),
            "total_pages": total_pages,
            "total_records_analyzed": total_records,
            "total_file_records": total_file_records,
            "anomalies_detected": anomaly_count,
            "anomaly_rate_percentage": round((anomaly_count / total_records) * 100, 2) if total_records > 0 else 0.0,
            "attack_family_breakdown": attack_distribution,
            "severity_breakdown": severity_distribution,
            "high_risk_devices_affected": list(high_risk_devices),
            "total_devices_scanned": len(formatted_devices),
            "device_summaries": formatted_devices,
            "top_fleet_signals": top_signals_summary,
            "reconstruction_threshold_used": pipeline_instance.threshold,
            "rows": results
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process file '{file.filename}': {str(e)}")

@router.post("/load-custom-stream")
async def load_custom_dataset_into_stream(file: UploadFile = File(...)):
    """
    Loads an uploaded Wireshark (.pcap/.pcapng), CSV, TSV, or JSON dataset directly into the live simulator replay stream!
    """
    try:
        contents = await file.read()
        if not contents or len(contents) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        mapped_df, total_rows, file_desc = parse_uploaded_file_to_df(contents, file.filename)

        if len(mapped_df) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file contains 0 valid flows.")

        traffic_simulator.df = mapped_df
        traffic_simulator.current_idx = 0
        traffic_simulator.loaded_filename = file.filename

        return {
            "status": "SUCCESS",
            "message": f"Successfully loaded {len(mapped_df)} flows from '{file.filename}' ({file_desc}) into live WebSocket stream!",
            "total_flows": len(mapped_df),
            "file_type": file_desc
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stream file '{file.filename}': {str(e)}")
