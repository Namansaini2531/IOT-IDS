import json
import joblib
import torch
import numpy as np
import pandas as pd
from pathlib import Path
from torch.utils.data import DataLoader, TensorDataset

from ml.config import (
    FEATURE_COLUMNS,
    AUTOENCODER_CONFIG,
    PROCESSED_DATA_DIR,
    MODELS_DIR
)
from ml.models.autoencoder import IoTAnomalyAutoencoder

def train_autoencoder():
    print("=" * 65)
    print("--- Training Stage 1: Benign-Only IoT Autoencoder ---")
    print("=" * 65)

    # 1. Load Benign Splits
    train_benign_path = PROCESSED_DATA_DIR / "train_benign_autoencoder.csv"
    val_benign_path = PROCESSED_DATA_DIR / "val_benign_autoencoder.csv"

    if not train_benign_path.exists() or not val_benign_path.exists():
        from ml.dataset import load_or_prepare_dataset
        load_or_prepare_dataset()

    df_train = pd.read_csv(train_benign_path)
    df_val = pd.read_csv(val_benign_path)
    scaler = joblib.load(MODELS_DIR / "scaler.joblib")

    X_train_raw = df_train[FEATURE_COLUMNS].values
    X_val_raw = df_val[FEATURE_COLUMNS].values

    # Scale features
    X_train_scaled = scaler.transform(X_train_raw)
    X_val_scaled = scaler.transform(X_val_raw)

    train_tensor = torch.tensor(X_train_scaled, dtype=torch.float32)
    val_tensor = torch.tensor(X_val_scaled, dtype=torch.float32)

    train_loader = DataLoader(
        TensorDataset(train_tensor),
        batch_size=AUTOENCODER_CONFIG["batch_size"],
        shuffle=True
    )

    # 2. Instantiate Model
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = IoTAnomalyAutoencoder(input_dim=len(FEATURE_COLUMNS)).to(device)
    criterion = torch.nn.MSELoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=AUTOENCODER_CONFIG["learning_rate"], weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=2)

    print(f"Device: {device} | Training on {len(df_train)} benign samples for {AUTOENCODER_CONFIG['epochs']} epochs")

    # 3. Training Loop
    best_val_loss = float("inf")
    for epoch in range(1, AUTOENCODER_CONFIG["epochs"] + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            x_batch = batch[0].to(device)
            optimizer.zero_grad()
            reconstructed = model(x_batch)
            loss = criterion(reconstructed, x_batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(x_batch)

        train_loss = total_loss / len(train_tensor)

        # Validation Loss
        model.eval()
        with torch.no_grad():
            val_x = val_tensor.to(device)
            val_recon = model(val_x)
            val_loss = criterion(val_recon, val_x).item()

        scheduler.step(val_loss)

        if epoch % 5 == 0 or epoch == AUTOENCODER_CONFIG["epochs"]:
            print(f"Epoch [{epoch:02d}/{AUTOENCODER_CONFIG['epochs']:02d}] - Train Loss: {train_loss:.6f} | Val Loss: {val_loss:.6f}")

    # 4. Calibrate Reconstruction Threshold on Held-Out Benign Validation Set
    model.eval()
    with torch.no_grad():
        val_errors = model.compute_reconstruction_error(val_tensor.to(device))

    p95 = float(np.percentile(val_errors, 95))
    p98 = float(np.percentile(val_errors, 98))
    p99 = float(np.percentile(val_errors, 99))
    chosen_threshold = p98  # Defensible choice: bounds theoretical benign FPR to ~2%

    print("\n--- Autoencoder Threshold Calibration (Validation Benign) ---")
    print(f"95th Percentile MSE: {p95:.6f}")
    print(f"98th Percentile MSE: {p98:.6f} (Selected Threshold)")
    print(f"99th Percentile MSE: {p99:.6f}")

    # Save artifacts
    torch.save(model.state_dict(), MODELS_DIR / "stage1_autoencoder.pt")
    
    threshold_meta = {
        "threshold": chosen_threshold,
        "percentile_chosen": 98.0,
        "p95": p95,
        "p98": p98,
        "p99": p99,
        "val_mean_mse": float(np.mean(val_errors)),
        "val_std_mse": float(np.std(val_errors))
    }
    with open(MODELS_DIR / "stage1_threshold.json", "w") as f:
        json.dump(threshold_meta, f, indent=4)

    print(f"[Stage 1] Saved model weights to {MODELS_DIR / 'stage1_autoencoder.pt'}")
    print(f"[Stage 1] Saved threshold metadata to {MODELS_DIR / 'stage1_threshold.json'}")

    return model, threshold_meta

if __name__ == "__main__":
    train_autoencoder()
