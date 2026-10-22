import os
from pathlib import Path
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "CortexIO AI Defense Monitor"
    API_V1_STR: str = "/api/v1"
    CORS_ORIGINS: list[str] = ["*"]
    
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent
    MODELS_DIR: Path = BASE_DIR / "models"
    DATA_DIR: Path = BASE_DIR / "data"
    
    # Simulation defaults
    REPLAY_INTERVAL_SECONDS: float = 0.8
    DEFAULT_BATCH_SIZE: int = 1
    
    # Groq AI Cyber Advisor settings
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

settings = Settings()
