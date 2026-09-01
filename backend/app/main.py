import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.db.base import Base
from app.db.session import engine

load_dotenv()
Base.metadata.create_all(bind=engine)




def _cors_origins() -> list[str]:
    """Use explicit browser origins; deployments opt in to their own frontend URL."""

    configured = os.getenv(
        "MAILTRACE_CORS_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173",
    )
    origins = [origin.strip().rstrip("/") for origin in configured.split(",") if origin.strip()]
    return origins or ["http://127.0.0.1:5173", "http://localhost:5173"]


app = FastAPI(
    title="MAILTRACE AI",
    description="AI-powered email threat detection and forensic intelligence API.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}
