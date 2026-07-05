from fastapi import FastAPI

from app.core.config import settings
from app.modules.auth.router import router as auth_router
from app.modules.nlq.router import router as nlq_router
from app.modules.registry.router import router as registry_router

app = FastAPI(
    title="Vulnerability Registry & Intelligent Security Query Interface",
    version="0.1.0",
)

app.include_router(auth_router)
app.include_router(registry_router)
app.include_router(nlq_router)


@app.get("/healthz")
async def health():
    return {"status": "ok", "environment": settings.environment}
