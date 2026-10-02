import json
import joblib
import torch
import numpy as np
from typing import Dict, Any, List

from ml.config import FEATURE_COLUMNS, MODELS_DIR
from ml.models.autoencoder import IoTAnomalyAutoencoder
from ml.models.classifier import IoTAttackClassifier
from ml.explainability import extract_top_deviations
from backend.app.core.risk_engine import DeviceRiskEngine

class TwoStageInferencePipeline:
    """
    Production-grade inference pipeline combining:
    1. Unsupervised Autoencoder Anomaly Gatekeeper
    2. Supervised Attack Attribution Classifier
    3. Explainability Deviations Engine
    4. Auditable Device Risk Engine
    """
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.scaler = None
        self.label_encoder = None
        self.autoencoder = None
        self.classifier = None
        self.threshold = 0.05
        self.threshold_meta = {}
        self.risk_engine = DeviceRiskEngine()
        self.is_loaded = False

    def load_artifacts(self):
        print("[Inference Pipeline] Loading model artifacts...")
        scaler_path = MODELS_DIR / "scaler.joblib"
        encoder_path = MODELS_DIR / "label_encoder.joblib"
        ae_path = MODELS_DIR / "stage1_autoencoder.pt"
        clf_path = MODELS_DIR / "stage2_classifier.joblib"
        thresh_path = MODELS_DIR / "stage1_threshold.json"

        if not (scaler_path.exists() and ae_path.exists() and clf_path.exists()):
            raise FileNotFoundError("Model artifacts missing. Run ml training scripts first.")

        self.scaler = joblib.load(scaler_path)
        self.label_encoder = joblib.load(encoder_path)
        
        # Load Autoencoder
        self.autoencoder = IoTAnomalyAutoencoder(input_dim=len(FEATURE_COLUMNS)).to(self.device)
        self.autoencoder.load_state_dict(torch.load(ae_path, map_location=self.device))
        self.autoencoder.eval()

        # Load Classifier
        self.classifier = IoTAttackClassifier.load(clf_path)

        # Load Threshold
        with open(thresh_path, "r") as f:
            self.threshold_meta = json.load(f)
            self.threshold = float(self.threshold_meta.get("threshold", 0.05))

        self.is_loaded = True
        print(f"[Inference Pipeline] Successfully loaded! Anomaly threshold: {self.threshold:.6f}")

    def predict_flow(self, flow_features: Dict[str, Any], device_id: str = "iot-device-01") -> Dict[str, Any]:
        """
        Executes complete 2-stage inference on a single network flow dict.
        """
        if not self.is_loaded:
            self.load_artifacts()

        # Extract features in exact order
        raw_vals = np.array([float(flow_features.get(col, 0.0)) for col in FEATURE_COLUMNS], dtype=np.float32)
        raw_vals_2d = raw_vals.reshape(1, -1)
        
        # Scale
        scaled_vals = self.scaler.transform(raw_vals_2d)
        tensor_vals = torch.tensor(scaled_vals, dtype=torch.float32).to(self.device)

        # --- Stage 1: Autoencoder Anomaly Detection ---
        recon_error = float(self.autoencoder.compute_reconstruction_error(tensor_vals)[0])
        is_anomaly = bool(recon_error >= self.threshold)
        
        # Normalized anomaly score 0.0 to 1.0 (relative to 2.5x threshold ceiling)
        normalized_anomaly_score = min(max(recon_error / (self.threshold * 2.5), 0.0), 1.0)

        # --- Stage 2: Supervised Attack Attribution ---
        class_probs = self.classifier.predict_proba(scaled_vals)[0]
        pred_class_idx = int(np.argmax(class_probs))
        predicted_attack_family = str(self.label_encoder.classes_[pred_class_idx])
        attack_confidence = float(class_probs[pred_class_idx])

        # If Autoencoder flags anomaly but classifier predicts Benign, attribute as "Unknown / Novel Anomaly"
        if is_anomaly and predicted_attack_family == "Benign":
            final_status = "Suspected Novel Anomaly"
            attack_prob_for_risk = 0.65
        elif is_anomaly:
            final_status = predicted_attack_family
            attack_prob_for_risk = attack_confidence
        else:
            final_status = "Benign"
            attack_prob_for_risk = 0.05

        # --- Stage 3: Explainability Deviations ---
        feature_deviations = self.autoencoder.get_feature_deviations(tensor_vals)[0]
        top_deviations = extract_top_deviations(feature_deviations, raw_vals, top_k=4)

        # --- Stage 4: Auditable Risk Assessment ---
        risk_result = self.risk_engine.calculate_risk(
            device_id=device_id,
            anomaly_score=normalized_anomaly_score,
            attack_probability=attack_prob_for_risk
        )

        return {
            "device_id": device_id,
            "is_anomaly": is_anomaly,
            "classification": final_status,
            "reconstruction_error": round(recon_error, 6),
            "threshold": round(self.threshold, 6),
            "anomaly_score": round(normalized_anomaly_score, 4),
            "attack_confidence": round(attack_confidence, 4),
            "all_class_probabilities": {
                cls_name: round(float(prob), 4)
                for cls_name, prob in zip(self.label_encoder.classes_, class_probs)
            },
            "risk_assessment": risk_result,
            "top_deviating_features": top_deviations,
            "raw_flow": {k: round(float(v), 2) if isinstance(v, (int, float)) else v for k, v in list(flow_features.items())[:8]}
        }

# Global pipeline instance
pipeline_instance = TwoStageInferencePipeline()
