import json
import time
import joblib
import torch
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_fscore_support,
    accuracy_score
)

from ml.config import (
    FEATURE_COLUMNS,
    PROCESSED_DATA_DIR,
    MODELS_DIR
)
from ml.models.autoencoder import IoTAnomalyAutoencoder
from ml.models.classifier import IoTAttackClassifier

def evaluate_full_pipeline():
    print("=" * 70)
    print("--- Running End-to-End Evaluation on Unseen Test Dataset ---")
    print("=" * 70)

    # 1. Load Test Set
    test_path = PROCESSED_DATA_DIR / "test_evaluation_set.csv"
    df_test = pd.read_csv(test_path)
    scaler = joblib.load(MODELS_DIR / "scaler.joblib")
    label_encoder = joblib.load(MODELS_DIR / "label_encoder.joblib")

    with open(MODELS_DIR / "stage1_threshold.json", "r") as f:
        threshold_meta = json.load(f)
    threshold = threshold_meta["threshold"]

    X_test_raw = df_test[FEATURE_COLUMNS].values
    y_test_family = df_test["attack_family"].values
    y_test_binary = (y_test_family != "Benign").astype(int)  # 0 = Benign, 1 = Attack

    X_test_scaled = scaler.transform(X_test_raw)

    # 2. Load Models
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    autoencoder = IoTAnomalyAutoencoder(input_dim=len(FEATURE_COLUMNS)).to(device)
    autoencoder.load_state_dict(torch.load(MODELS_DIR / "stage1_autoencoder.pt", map_location=device))
    autoencoder.eval()

    classifier = IoTAttackClassifier.load(MODELS_DIR / "stage2_classifier.joblib")

    # 3. Stage 1 Evaluation (Unsupervised Anomaly Detection)
    test_tensor = torch.tensor(X_test_scaled, dtype=torch.float32).to(device)
    
    t0 = time.time()
    reconstruction_errors = autoencoder.compute_reconstruction_error(test_tensor)
    stage1_latency_ms = ((time.time() - t0) / len(X_test_raw)) * 1000.0

    stage1_preds = (reconstruction_errors >= threshold).astype(int)

    # Metrics for Stage 1 (Binary Anomaly Detection)
    s1_prec, s1_rec, s1_f1, _ = precision_recall_fscore_support(y_test_binary, stage1_preds, average="binary")
    s1_acc = accuracy_score(y_test_binary, stage1_preds)
    try:
        s1_auc = float(roc_auc_score(y_test_binary, reconstruction_errors))
    except Exception:
        s1_auc = 0.0

    # False Positive Rate on Benign: FP / (FP + TN)
    tn = np.sum((stage1_preds == 0) & (y_test_binary == 0))
    fp = np.sum((stage1_preds == 1) & (y_test_binary == 0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    print("\n--- STAGE 1: Unsupervised Autoencoder Anomaly Detection ---")
    print(f"Decision Threshold (98th percentile): {threshold:.6f}")
    print(f"Accuracy:  {s1_acc:.4f}")
    print(f"Precision: {s1_prec:.4f}")
    print(f"Recall:    {s1_rec:.4f} (Malicious Traffic Catch Rate)")
    print(f"F1-Score:  {s1_f1:.4f}")
    print(f"ROC-AUC:   {s1_auc:.4f}")
    print(f"False Positive Rate (FPR on Benign): {fpr:.4f} ({fpr*100:.2f}%)")
    print(f"Stage 1 Inference Latency: {stage1_latency_ms:.4f} ms/flow")

    # 4. Stage 2 Evaluation (Supervised Attack Family Classifier)
    t0 = time.time()
    y_test_encoded = label_encoder.transform(y_test_family)
    stage2_preds_encoded = classifier.predict(X_test_scaled)
    stage2_latency_ms = ((time.time() - t0) / len(X_test_raw)) * 1000.0

    target_names = list(label_encoder.classes_)
    report_dict = classification_report(
        y_test_encoded,
        stage2_preds_encoded,
        target_names=target_names,
        output_dict=True,
        zero_division=0
    )
    conf_mat = confusion_matrix(y_test_encoded, stage2_preds_encoded).tolist()

    print("\n--- STAGE 2: Supervised Attack Family Classification Report ---")
    print(classification_report(y_test_encoded, stage2_preds_encoded, target_names=target_names, digits=4, zero_division=0))
    print(f"Stage 2 Inference Latency: {stage2_latency_ms:.4f} ms/flow")

    # 5. Combined Two-Stage Pipeline Evaluation
    # Pipeline Logic:
    # If Stage 1 flags as Normal (< threshold) -> Output "Benign"
    # If Stage 1 flags as Anomaly (>= threshold) -> Output Stage 2 predicted family
    combined_preds = []
    benign_idx = list(label_encoder.classes_).index("Benign")
    
    for i in range(len(X_test_raw)):
        if stage1_preds[i] == 0:
            combined_preds.append("Benign")
        else:
            pred_class = label_encoder.inverse_transform([stage2_preds_encoded[i]])[0]
            # If classifier thought it was benign but autoencoder flagged it, keep as Suspected-Anomaly
            combined_preds.append(pred_class if pred_class != "Benign" else "Suspected-Anomaly")

    # Compile Full Evaluation Report
    eval_report = {
        "dataset_summary": {
            "total_test_flows": len(df_test),
            "benign_flows": int(np.sum(y_test_binary == 0)),
            "attack_flows": int(np.sum(y_test_binary == 1)),
            "attack_classes": target_names
        },
        "stage1_autoencoder": {
            "threshold": threshold,
            "accuracy": round(s1_acc, 4),
            "precision": round(s1_prec, 4),
            "recall": round(s1_rec, 4),
            "f1_score": round(s1_f1, 4),
            "roc_auc": round(s1_auc, 4),
            "false_positive_rate": round(fpr, 4),
            "inference_latency_ms": round(stage1_latency_ms, 4)
        },
        "stage2_classifier": {
            "per_class_metrics": report_dict,
            "macro_f1": round(report_dict["macro avg"]["f1-score"], 4),
            "weighted_f1": round(report_dict["weighted avg"]["f1-score"], 4),
            "accuracy": round(report_dict["accuracy"], 4),
            "confusion_matrix": conf_mat,
            "inference_latency_ms": round(stage2_latency_ms, 4)
        },
        "two_stage_combined": {
            "total_inference_latency_ms": round(stage1_latency_ms + stage2_latency_ms, 4),
            "pipeline_architecture": "Gatekeeper Autoencoder + Attribution Classifier"
        }
    }

    report_path = MODELS_DIR / "evaluation_report.json"
    with open(report_path, "w") as f:
        json.dump(eval_report, f, indent=4)

    print(f"\n[Evaluation] Comprehensive report saved to {report_path}")
    return eval_report

if __name__ == "__main__":
    evaluate_full_pipeline()
