import asyncio
import json
import pandas as pd
from typing import Generator, Dict, Any
from pathlib import Path

from ml.config import PROCESSED_DATA_DIR, RAW_DATA_DIR, FEATURE_COLUMNS
from backend.app.services.inference import pipeline_instance

class TrafficSimulator:
    """
    Replays user-uploaded Wireshark (.pcap/.pcapng) or custom datasets,
    passing each flow through the 2-Stage inference pipeline to generate live event stream.
    """
    def __init__(self):
        self.df = None
        self.current_idx = 0
        self.is_running = False
        self.loaded_filename = None

    def load_traffic_data(self):
        # We do NOT load CICIoT2023 by default. Awaiting user Wireshark/dataset upload.
        pass

    def get_next_flow(self) -> Dict[str, Any]:
        if self.df is None or len(self.df) == 0:
            return {}

        row = self.df.iloc[self.current_idx].to_dict()
        self.current_idx = (self.current_idx + 1) % len(self.df)

        device_id = str(row.get("device_id", "wireshark-endpoint-01"))
        ground_truth = str(row.get("attack_family", row.get("label", "Wireshark Traffic")))

        # Run 2-Stage ML Inference
        prediction = pipeline_instance.predict_flow(row, device_id=device_id)
        prediction["ground_truth"] = ground_truth
        prediction["source_file"] = self.loaded_filename or "User Upload"
        return prediction

traffic_simulator = TrafficSimulator()
