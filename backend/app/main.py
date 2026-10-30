"""CipherTwin FastAPI application factory."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import api_router
from app.core.config import settings
from app.seed import run_all
from app.workers.pipeline import start_background, status as pipeline_status

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s :: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Run database schema + seed data on startup.
    run_all()

    # 2. Declare RabbitMQ topology (topic exchange, queues, DLX, bindings)
    if settings.rabbitmq_enabled:
        try:
            from app.services.rabbitmq_topology import get_topology
            get_topology().declare()
            logging.info("RabbitMQ telemetry topology successfully declared on broker.")
        except Exception as exc:
            logging.warning("RabbitMQ topology declaration warning: %s", exc)

    # 3. Start Twin Events Consumer (processes remote VM ingest, Cowrie events, IAM/EDR/NetFlow)
    from app.workers.twin_consumer import twin_consumer
    twin_consumer.start()

    # 4. Start Cowrie Honeypot Monitor (syncs container logs and publishes to RabbitMQ)
    from app.workers.cowrie_monitor import cowrie_monitor
    if settings.cowrie_bridge_enabled:
        cowrie_monitor.start()

    # 5. Start continuous attack & telemetry feed
    from app.services.event_engine import event_engine
    if settings.enable_simulation:
        event_engine.start()
        logging.info("Continuous dynamic attack and telemetry engine started (1 event/sec).")

    # 6. Pre-warm local LLM in background so the first chat prompt is instant
    import threading
    from app.guide.llm import warmup_ollama
    threading.Thread(target=warmup_ollama, daemon=True, name="ollama-warmup").start()

    yield

    # Graceful shutdown
    if settings.enable_simulation:
        event_engine.stop()
    twin_consumer.stop()
    if settings.cowrie_bridge_enabled:
        cowrie_monitor.stop()


app = FastAPI(
    title=settings.app_name,
    description=(
        "CipherTwin – Autonomous Cyber Defense Framework combining a Digital "
        "Twin, Explainable Zero Trust, Adaptive Deception, Threat "
        "Intelligence and PennyLane QAOA circuit execution with a classical fallback."
    ),
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/")
def root():
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "ok",
        "pipeline": pipeline_status(),
        "endpoints": {
            "docs": "/docs",
            "openapi": "/openapi.json",
            "auth": "/api/auth/login",
            "analytics_overview": "/api/analytics/overview",
        },
    }


@app.get("/health")
@app.get("/api/health")
@app.get("/health/live")
@app.get("/api/health/live")
def health():
    return {"status": "ok", "pipeline": pipeline_status()}
