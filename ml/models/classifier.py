import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from ml.config import CLASSIFIER_CONFIG, MODELS_DIR

class IoTAttackClassifier:
    """
    Stage 2 Supervised Classifier for categorizing flagged anomalies
    into known attack families (Mirai, DDoS, DoS, Reconnaissance, etc.).
    """
    def __init__(self, model_type: str = "rf"):
        self.model_type = model_type
        if model_type == "rf":
            self.model = RandomForestClassifier(
                n_estimators=CLASSIFIER_CONFIG["n_estimators"],
                max_depth=CLASSIFIER_CONFIG["max_depth"],
                random_state=CLASSIFIER_CONFIG["random_state"],
                n_jobs=CLASSIFIER_CONFIG["n_jobs"],
                class_weight="balanced"  # Combats class imbalance
            )
        elif model_type == "xgboost":
            self.model = XGBClassifier(
                n_estimators=CLASSIFIER_CONFIG["n_estimators"],
                max_depth=6,
                learning_rate=0.1,
                random_state=CLASSIFIER_CONFIG["random_state"],
                n_jobs=CLASSIFIER_CONFIG["n_jobs"],
                eval_metric="mlogloss"
            )
        else:
            raise ValueError(f"Unsupported model type: {model_type}")

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def save(self, filepath: Path = MODELS_DIR / "stage2_classifier.joblib"):
        joblib.dump({"model": self.model, "type": self.model_type}, filepath)

    @classmethod
    def load(cls, filepath: Path = MODELS_DIR / "stage2_classifier.joblib"):
        data = joblib.load(filepath)
        instance = cls(model_type=data["type"])
        instance.model = data["model"]
        return instance
