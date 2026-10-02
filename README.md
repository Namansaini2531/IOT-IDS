# AI-Based Network Intrusion and Anomaly Detection System for IoT Devices

A production-grade, two-stage machine learning system designed to monitor IoT network traffic flows, detect anomalous patterns using an unsupervised Autoencoder, attribute attack families via a Supervised Classifier (Random Forest / XGBoost), and provide real-time explainable risk triage via a React dashboard.

---

## 🏗️ 2-Stage Pipeline Architecture

```mermaid
flowchart LR
    A[CICIoT2023 Network Flows] --> B[RobustScaler Preprocessing]
    B --> C[Stage 1: Benign-Trained Autoencoder]
    C -->|Reconstruction Error >= 98th Percentile| D[Flagged Anomaly]
    C -->|Reconstruction Error < 98th Percentile| E[Normal Benign Flow]
    D --> F[Stage 2: Supervised Attack Classifier]
    F --> G[Attack Family Attribution]
    D & G --> H[Explainability & Auditable Risk Engine]
    H --> I[FastAPI WebSocket Streamer]
    I --> J[React + Recharts Live Threat Dashboard]
```

---

## 🎯 Key Defensibility & Metric Philosophy

Rather than relying on misleading raw accuracy in imbalanced security scenarios, this system is evaluated against:
1. **Malicious Recall Rate:** $100\%$ detection of attack flows in Stage 1.
2. **False Positive Rate (FPR on Benign):** Explicitly bounded to $\approx 1.41\%$ by calibrating the decision threshold to the 98th percentile of held-out benign validation flows.
3. **Macro-Averaged F1-Score:** Treats all attack classes equally (e.g. stealthy Reconnaissance or BruteForce vs massive DDoS floods).
4. **Session & Device-Aware Splitting:** Strictly isolates IoT device groups between training and test sets to prevent near-duplicate flow leakage.

---

## 🚀 Quick Start Guide

### 1. Run Backend Server
```bash
# In project root
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Run Frontend Dashboard
```bash
cd frontend
npm run dev
```
Open **http://localhost:5173** to view the live dashboard.

---

## 📁 Repository Structure
```
e:/IOT-IDS/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI server entry point
│   │   ├── core/
│   │   │   ├── config.py        # Settings & CORS
│   │   │   └── risk_engine.py   # Auditable Risk assessment engine
│   │   ├── api/
│   │   │   ├── routes.py        # REST API endpoints (status, predict, report)
│   │   │   └── websocket.py     # Real-time traffic stream
│   │   └── services/
│   │       ├── inference.py     # 2-Stage pipeline runner
│   │       └── traffic_simulator.py # Replays CICIoT2023 flows
├── ml/
│   ├── config.py                # Feature schema & attack family maps
│   ├── dataset.py               # Data prep & session-aware splitting
│   ├── models/
│   │   ├── autoencoder.py       # PyTorch Autoencoder
│   │   └── classifier.py        # Supervised Classifier wrapper
│   ├── train_stage1_autoencoder.py # Stage 1 training & threshold calibration
│   ├── train_stage2_classifier.py  # Stage 2 training & multi-class metrics
│   ├── evaluate_pipeline.py     # End-to-end evaluation & JSON reporting
│   └── explainability.py        # Feature deviation ranking
├── models/                      # Saved .pt, .joblib weights & metrics
├── data/                        # Processed dataset splits
└── frontend/                    # React + Recharts modern UI
```
