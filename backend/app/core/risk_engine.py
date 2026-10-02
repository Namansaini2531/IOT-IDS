from typing import Dict
from collections import defaultdict
from ml.config import RISK_WEIGHTS

class DeviceRiskEngine:
    """
    Computes an auditable, transparent security risk score for IoT devices.
    Formula:
        Risk = 0.5 * anomaly_score + 0.3 * attack_probability + 0.2 * historical_score
    """
    def __init__(
        self,
        anomaly_weight: float = RISK_WEIGHTS["anomaly_weight"],
        attack_prob_weight: float = RISK_WEIGHTS["attack_prob_weight"],
        historical_weight: float = RISK_WEIGHTS["historical_weight"],
        decay_factor: float = 0.85
    ):
        self.w_anomaly = anomaly_weight
        self.w_attack = attack_prob_weight
        self.w_history = historical_weight
        self.decay = decay_factor
        
        # In-memory historical risk tracking per device
        self.device_history: Dict[str, float] = defaultdict(float)

    def calculate_risk(
        self,
        device_id: str,
        anomaly_score: float,     # Normalized 0.0 to 1.0 (or clipped)
        attack_probability: float  # Classifier confidence 0.0 to 1.0
    ) -> Dict[str, float]:
        """
        Computes current flow risk and updates the device's moving risk score.
        """
        # Ensure inputs are bounded between 0.0 and 1.0
        norm_anomaly = min(max(float(anomaly_score), 0.0), 1.0)
        norm_attack = min(max(float(attack_probability), 0.0), 1.0)
        
        hist_score = self.device_history[device_id]
        
        current_risk = (
            (self.w_anomaly * norm_anomaly) +
            (self.w_attack * norm_attack) +
            (self.w_history * hist_score)
        )
        
        current_risk = min(max(current_risk, 0.0), 1.0)
        
        # Exponential moving average update for device history
        new_hist = (self.decay * hist_score) + ((1 - self.decay) * current_risk)
        self.device_history[device_id] = new_hist
        
        # Severity categorization
        if current_risk >= 0.75:
            severity = "CRITICAL"
        elif current_risk >= 0.50:
            severity = "HIGH"
        elif current_risk >= 0.25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": round(current_risk, 4),
            "anomaly_component": round(norm_anomaly, 4),
            "attack_component": round(norm_attack, 4),
            "historical_component": round(hist_score, 4),
            "severity": severity
        }

    def reset(self):
        self.device_history.clear()
