import json
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional

from ml.config import MODELS_DIR, FEATURE_COLUMNS
from backend.app.services.inference import pipeline_instance

router = APIRouter()

class FlowInferenceRequest(BaseModel):
    device_id: Optional[str] = "iot-camera-01 (192.168.1.101)"
    flow_features: Dict[str, float]

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
