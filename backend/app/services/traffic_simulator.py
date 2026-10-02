import asyncio
import json
import pandas as pd
from typing import Generator, Dict, Any
from pathlib import Path

from ml.config import PROCESSED_DATA_DIR, RAW_DATA_DIR, FEATURE_COLUMNS
from backend.app.services.inference import pipeline_instance

class TrafficSimulator:
    """
    Replays network flows from the CICIoT test set or dataset sample,
    passing each through the 2-Stage inference pipeline to generate live event stream.
    """
    def __init__(self):
        self.df = None
        self.current_idx = 0
        self.is_running = False
        self.load_traffic_data()

    def load_traffic_data(self):
        test_path = PROCESSED_DATA_DIR / "test_evaluation_set.csv"
        raw_path = RAW_DATA_DIR / "ciciot2023_sample.csv"

        if test_path.exists():
            self.df = pd.read_csv(test_path)
            print(f"[TrafficSimulator] Loaded {len(self.df)} test flows.")
        elif raw_path.exists():
            self.df = pd.read_csv(raw_path)
            print(f"[TrafficSimulator] Loaded {len(self.df)} sample flows.")
        else:
            print("[TrafficSimulator] No data found yet.")

    def get_next_flow(self) -> Dict[str, Any]:
        if self.df is None or len(self.df) == 0:
            self.load_traffic_data()
            if self.df is None or len(self.df) == 0:
                return {}

        row = self.df.iloc[self.current_idx].to_dict()
        self.current_idx = (self.current_idx + 1) % len(self.df)

        device_id = str(row.get("device_id", "iot-device-01"))
        ground_truth = str(row.get("attack_family", row.get("label", "Unknown")))

        # Run 2-Stage ML Inference
        prediction = pipeline_instance.predict_flow(row, device_id=device_id)
        prediction["ground_truth"] = ground_truth
        return prediction

traffic_simulator = TrafficSimulator()
