import io
import json
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

# Common column aliases for mapping arbitrary datasets (Windhawk, Zeek, Wireshark, CICFlowMeter, etc.)
COLUMN_ALIASES = {
    "flow_duration": ["duration", "dur", "flow_duration", "time_delta", "time"],
    "Rate": ["rate", "packet_rate", "pkt_rate", "packets_per_sec", "flow_rate"],
    "Srate": ["srate", "src_rate", "source_rate", "fwd_rate"],
    "Drate": ["drate", "dst_rate", "dest_rate", "bwd_rate"],
    "Header_Length": ["header_length", "hdr_len", "header_len", "ihl"],
    "Protocol Type": ["protocol", "proto", "protocol_type", "ip_proto"],
    "syn_flag_number": ["syn", "syn_flag", "syn_count", "tcp_syn"],
    "ack_flag_number": ["ack", "ack_flag", "ack_count", "tcp_ack"],
    "rst_flag_number": ["rst", "rst_flag", "tcp_rst"],
    "fin_flag_number": ["fin", "fin_flag", "tcp_fin"],
    "psh_flag_number": ["psh", "psh_flag", "tcp_psh"],
    "TCP": ["tcp", "is_tcp"],
    "UDP": ["udp", "is_udp"],
    "ICMP": ["icmp", "is_icmp"],
    "HTTP": ["http", "is_http"],
    "HTTPS": ["https", "is_https", "tls", "ssl"],
    "DNS": ["dns", "is_dns"],
    "Tot sum": ["tot_sum", "tot_bytes", "total_bytes", "bytes", "length", "size", "bytes_total", "flow_bytes"],
    "AVG": ["avg", "avg_size", "mean_size", "packet_size_avg", "mean_pkt_len"],
    "Min": ["min", "min_size", "min_pkt_len"],
    "Max": ["max", "max_size", "max_pkt_len"],
    "Std": ["std", "std_size", "std_pkt_len"],
    "IAT": ["iat", "inter_arrival_time", "flow_iat_mean", "mean_iat"],
    "Number": ["number", "packet_count", "packets", "pkt_count", "tot_packets", "total_packets"]
}

def map_arbitrary_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flexibly matches columns from Windhawk/Zeek/Wireshark/CSV files
    to the 46 features expected by the CICIoT-trained 2-Stage pipeline.
    """
    mapped_df = pd.DataFrame()
    df_cols_lower = {col.lower().replace("-", "_").replace(" ", "_"): col for col in df.columns}

    for target_col in FEATURE_COLUMNS:
        found = False
        # Direct match check
        target_lower = target_col.lower().replace("-", "_").replace(" ", "_")
        if target_lower in df_cols_lower:
            mapped_df[target_col] = pd.to_numeric(df[df_cols_lower[target_lower]], errors='coerce').fillna(0.0)
            found = True
        elif target_col in COLUMN_ALIASES:
            for alias in COLUMN_ALIASES[target_col]:
                if alias in df_cols_lower:
                    mapped_df[target_col] = pd.to_numeric(df[df_cols_lower[alias]], errors='coerce').fillna(0.0)
                    found = True
                    break
        
        if not found:
            mapped_df[target_col] = 0.0

    # Device or IP identification
    dev_col = None
    for candidate in ["device_id", "device", "src_ip", "source_ip", "ip", "host", "source", "client"]:
        for orig_col in df.columns:
            if candidate in orig_col.lower():
                dev_col = orig_col
                break
        if dev_col:
            break

    if dev_col:
        mapped_df["device_id"] = df[dev_col].astype(str)
    else:
        mapped_df["device_id"] = [f"custom-device-{(i % 5) + 1:02d}" for i in range(len(df))]

    return mapped_df

@router.get("/status")
def get_system_status():
    """
    Returns the status of models, thresholds, and pipeline components.
    """
    if not pipeline_instance.is_loaded:
        try:
            pipeline_instance.load_artifacts()
        except Exception as e:
            return {"status": "INITIALIZING", "error": str(e)}

    return {
        "status": "OPERATIONAL",
        "stage1_autoencoder": "Loaded (PyTorch)",
        "stage2_classifier": "Loaded (Random Forest)",
        "reconstruction_threshold": pipeline_instance.threshold,
        "features_count": len(FEATURE_COLUMNS),
        "tracked_devices_count": len(pipeline_instance.risk_engine.device_history)
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
    max_rows: int = Form(500)
):
    """
    Upload any Wireshark (.pcap/.pcapng) capture or CSV/JSON dataset
    to perform batch anomaly detection and attack family triage with explainability.
    """
    if not pipeline_instance.is_loaded:
        pipeline_instance.load_artifacts()

    try:
        contents = await file.read()
        filename = file.filename.lower()

        # 1. Native Wireshark PCAP / PCAPNG parser
        if filename.endswith(".pcap") or filename.endswith(".pcapng") or filename.endswith(".cap"):
            from backend.app.services.pcap_extractor import extract_flows_from_pcap
            mapped_df = extract_flows_from_pcap(contents, filename=file.filename)
            total_uploaded_rows = len(mapped_df)
        elif filename.endswith(".json"):
            df = pd.read_json(io.BytesIO(contents))
            total_uploaded_rows = len(df)
            mapped_df = map_arbitrary_dataframe(df)
        else:
            # Default to CSV / Wireshark CSV export
            df = pd.read_csv(io.BytesIO(contents))
            total_uploaded_rows = len(df)
            mapped_df = map_arbitrary_dataframe(df)

        if len(mapped_df) == 0:
            raise HTTPException(status_code=400, detail="Uploaded capture or dataset contains 0 flows.")

        if len(mapped_df) > max_rows:
            mapped_df = mapped_df.iloc[:max_rows]

        results = []
        anomaly_count = 0
        attack_distribution = {}
        high_risk_devices = set()
        device_summary = {}

        for idx, row in mapped_df.iterrows():
            row_dict = row.to_dict()
            dev_id = str(row_dict.get("device_id", f"node-{(idx % 6) + 1}"))
            pred = pipeline_instance.predict_flow(row_dict, device_id=dev_id)
            
            is_anom = pred["is_anomaly"]
            severity = pred["risk_assessment"]["severity"]
            risk_val = pred["risk_assessment"]["risk_score"]
            cls = pred["classification"]
            top_dev = pred["top_deviating_features"][0] if pred["top_deviating_features"] else None

            if is_anom:
                anomaly_count += 1
                if severity in ["CRITICAL", "HIGH"]:
                    high_risk_devices.add(dev_id)

            attack_distribution[cls] = attack_distribution.get(cls, 0) + 1

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
            dev_rec["attacks_seen"][cls] = dev_rec["attacks_seen"].get(cls, 0) + 1
            dev_rec["severities"][severity] = dev_rec["severities"].get(severity, 0) + 1
            if top_dev and len(dev_rec["top_deviating_signals"]) < 3:
                label_val = f"{top_dev['label']} ({round(top_dev['observed_value'], 2)})"
                if label_val not in dev_rec["top_deviating_signals"]:
                    dev_rec["top_deviating_signals"].append(label_val)

            results.append({
                "row_index": idx + 1,
                "device_id": dev_id,
                "is_anomaly": is_anom,
                "classification": cls,
                "reconstruction_error": pred["reconstruction_error"],
                "anomaly_score": pred["anomaly_score"],
                "attack_confidence": pred["attack_confidence"],
                "risk_score": risk_val,
                "severity": severity,
                "top_deviation": top_dev
            })

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

        return {
            "filename": file.filename,
            "total_records_analyzed": len(results),
            "total_file_records": total_uploaded_rows,
            "anomalies_detected": anomaly_count,
            "anomaly_rate_percentage": round((anomaly_count / len(results)) * 100, 2),
            "attack_family_breakdown": attack_distribution,
            "high_risk_devices_affected": list(high_risk_devices),
            "total_devices_scanned": len(formatted_devices),
            "device_summaries": formatted_devices,
            "reconstruction_threshold_used": pipeline_instance.threshold,
            "rows": results
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process Wireshark/dataset file: {str(e)}")

@router.post("/load-custom-stream")
async def load_custom_dataset_into_stream(file: UploadFile = File(...)):
    """
    Loads an uploaded Wireshark (.pcap/.pcapng) or CSV dataset directly into the live simulator replay stream!
    """
    try:
        contents = await file.read()
        filename = file.filename.lower()

        if filename.endswith(".pcap") or filename.endswith(".pcapng") or filename.endswith(".cap"):
            from backend.app.services.pcap_extractor import extract_flows_from_pcap
            mapped_df = extract_flows_from_pcap(contents, filename=file.filename)
        elif filename.endswith(".json"):
            df = pd.read_json(io.BytesIO(contents))
            mapped_df = map_arbitrary_dataframe(df)
        else:
            df = pd.read_csv(io.BytesIO(contents))
            mapped_df = map_arbitrary_dataframe(df)

        if len(mapped_df) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file contains 0 flows.")

        traffic_simulator.df = mapped_df
        traffic_simulator.current_idx = 0
        traffic_simulator.loaded_filename = file.filename

        return {
            "status": "SUCCESS",
            "message": f"Loaded {len(mapped_df)} flows from Wireshark capture {file.filename} into live WebSocket stream!",
            "total_flows": len(mapped_df)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stream Wireshark capture: {str(e)}")
