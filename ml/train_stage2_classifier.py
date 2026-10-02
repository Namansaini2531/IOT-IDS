import json
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix

from ml.config import (
    FEATURE_COLUMNS,
    PROCESSED_DATA_DIR,
    MODELS_DIR
)
from ml.models.classifier import IoTAttackClassifier

def train_classifier(model_type: str = "rf"):
    print("=" * 65)
    print(f"--- Training Stage 2: Supervised Attack Classifier ({model_type.upper()}) ---")
    print("=" * 65)

    train_path = PROCESSED_DATA_DIR / "train_supervised_classifier.csv"
    if not train_path.exists():
        from ml.dataset import load_or_prepare_dataset
        load_or_prepare_dataset()

    df_train = pd.read_csv(train_path)
    scaler = joblib.load(MODELS_DIR / "scaler.joblib")
    label_encoder = joblib.load(MODELS_DIR / "label_encoder.joblib")

    X_train_raw = df_train[FEATURE_COLUMNS].values
    y_train_str = df_train["attack_family"].values

    X_train_scaled = scaler.transform(X_train_raw)
    y_train = label_encoder.transform(y_train_str)

    print(f"Training on {len(df_train)} samples across {len(label_encoder.classes_)} attack classes...")
    print(f"Classes: {list(label_encoder.classes_)}")

    # Instantiate and fit classifier
    clf = IoTAttackClassifier(model_type=model_type)
    clf.fit(X_train_scaled, y_train)

    # Save classifier
    clf.save(MODELS_DIR / "stage2_classifier.joblib")
    print(f"[Stage 2] Saved model to {MODELS_DIR / 'stage2_classifier.joblib'}")

    return clf

if __name__ == "__main__":
    train_classifier()
