@echo off
echo ===================================================
echo Starting IoT-IDS AI Defense System
echo ===================================================

start cmd /k "echo Starting FastAPI Backend... && python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload"
timeout /t 2 /nobreak >nul

start cmd /k "echo Starting React Dashboard... && cd frontend && npm run dev"

echo System launched!
echo - Backend API: http://127.0.0.1:8000/docs
echo - Frontend UI: http://localhost:5173
