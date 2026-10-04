from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from backend.app.core.config import settings
from backend.app.api.routes import router as api_router
from backend.app.api.websocket import router as ws_router
from backend.app.services.inference import pipeline_instance

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-load models on startup
    try:
        pipeline_instance.load_artifacts()
    except Exception as e:
        print(f"[Warning] Could not preload models on startup: {e}")
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# CORS configuration for unrestricted cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Include Routers
app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(ws_router)

@app.get("/")
def root():
    return {
        "service": settings.PROJECT_NAME,
        "docs": "/docs",
        "api": f"{settings.API_V1_STR}/status",
        "websocket": "/ws/traffic-stream"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
