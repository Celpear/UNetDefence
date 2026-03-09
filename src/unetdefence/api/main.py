"""FastAPI application and CLI entrypoint."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

# Load .env from project root so UNETDEFENCE_* overrides apply (e.g. LLM_MODEL)
try:
    from dotenv import load_dotenv
    _root = Path(__file__).resolve().parent.parent.parent.parent  # api -> unetdefence -> src -> project root
    load_dotenv(_root / ".env")
except Exception:
    pass
from fastapi.middleware.cors import CORSMiddleware

from unetdefence.api.routes import devices, events, analytics, llm as llm_routes, health, db as db_routes
from unetdefence.storage import init_pool, close_pool


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_pool()
    yield
    await close_pool()


def create_app() -> FastAPI:
    app = FastAPI(
        title="UNetDefence API",
        description="Local network security analysis: IDS, enrichment, PostgreSQL, LLM analyst",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    # Root: Vue.js chat frontend
    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        html_path = _root / "static" / "chat" / "index.html"
        if html_path.exists():
            return HTMLResponse(html_path.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>UNetDefence</h1><p>Frontend not found. Did you pull the latest code?</p>")
    app.include_router(health.router, prefix="/health", tags=["health"])
    app.include_router(events.router, prefix="/api/events", tags=["events"])
    app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
    app.include_router(analytics.router, prefix="/api/analytics", tags=["analytics"])
    app.include_router(llm_routes.router, prefix="/api/llm", tags=["llm"])
    app.include_router(db_routes.router, prefix="/api/db", tags=["db"])
    return app


app = create_app()


def main() -> None:
    import uvicorn
    from unetdefence.config import get_settings
    uvicorn.run(
        "unetdefence.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=get_settings().environment == "development",
    )


if __name__ == "__main__":
    main()
