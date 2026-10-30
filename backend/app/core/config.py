"""Application configuration."""
from pathlib import Path
from typing import List, Optional
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables (.env supported)."""

    model_config = SettingsConfigDict(env_file=BACKEND_DIR.parent / ".env", extra="ignore")

    @model_validator(mode="after")
    def resolve_paths(self):
        if self.database_url.startswith("sqlite:///./"):
            rel_part = self.database_url.replace("sqlite:///./", "")
            self.database_url = f"sqlite:///{WORKSPACE_ROOT / rel_part}"
        elif self.database_url == "sqlite:///data/ciphertwin.db":
            self.database_url = f"sqlite:///{WORKSPACE_ROOT / 'data' / 'ciphertwin.db'}"

        if not Path(self.cowrie_log_path).is_absolute():
            candidate = WORKSPACE_ROOT / self.cowrie_log_path.lstrip("./")
            if candidate.exists():
                self.cowrie_log_path = str(candidate)
            else:
                backend_candidate = BACKEND_DIR / self.cowrie_log_path.lstrip("./")
                if backend_candidate.exists():
                    self.cowrie_log_path = str(backend_candidate)
                else:
                    self.cowrie_log_path = str(candidate)
        return self

    app_name: str = "CipherTwin"
    app_version: str = "0.1.0"

    # JWT
    secret_key: str = ""
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 8

    # First-run seed credentials must be supplied explicitly via environment.
    seed_admin_password: str = ""
    seed_analyst_password: str = ""
    seed_soc_lead_password: str = ""

    # Database
    database_url: str = f"sqlite:///{BACKEND_DIR / 'data' / 'ciphertwin.db'}"

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000", "http://localhost", "http://localhost:80"]

    # Telemetry Feed & Generator
    telemetry_interval_seconds: float = 2.5
    enable_simulation: bool = True
    enable_telemetry_feed: bool = True

    # Zero Trust risk thresholds
    risk_threshold_allow: int = 30
    risk_threshold_restricted: int = 60
    risk_threshold_deny: int = 75

    # Deception trigger threshold
    deception_risk_threshold: int = 60
    # Explicit HTTP redirect broker destination for the local isolated decoy.
    decoy_web_public_url: str = "http://127.0.0.1:8081"

    # RabbitMQ Telemetry Pipeline (topic exchange topology)
    rabbitmq_enabled: bool = False
    rabbitmq_host: str = "localhost"
    rabbitmq_port: int = 5672
    rabbitmq_mgmt_port: int = 15672
    rabbitmq_user: str = "guest"
    rabbitmq_password: str = "guest"
    rabbitmq_vhost: str = "/"
    rabbitmq_queue: str = "ciphertwin.telemetry"
    rabbitmq_dlq: str = "ciphertwin.telemetry.dlq"
    rabbitmq_exchange: str = "ciphertwin.events"

    # Topic exchange topology for multi-source telemetry
    topic_exchange: str = "telemetry"
    dlx_exchange: str = "telemetry.dlx"
    twin_events_queue: str = "twin.events"
    routing_key_edr: str = "telemetry.edr"
    routing_key_iam: str = "telemetry.iam"
    routing_key_netflow: str = "telemetry.netflow"
    routing_key_cowrie: str = "telemetry.cowrie"

    # Ingest API (remote VM path)
    ingest_api_key: str = ""  # no default; required for /ingest endpoints
    ingest_rate_limit_per_minute: int = 60
    ingest_max_batch_size: int = 100
    ingest_max_body_bytes: int = 1048576  # 1 MB

    # Remote VM publisher (direct AMQP path)
    vm_publisher_user: str = "vm_publisher"
    vm_publisher_password: str = ""

    # Neo4j Digital Twin
    neo4j_enabled: bool = False
    neo4j_url: str = "http://localhost:7474"
    neo4j_bolt_url: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "ciphertwin"

    # Cowrie Deception
    cowrie_enabled: bool = False
    cowrie_log_path: str = str(BACKEND_DIR / "data" / "cowrie.json")
    cowrie_bridge_enabled: bool = False
    deception_mode: str = "DECOY"  # DECOY | COWRIE | STANDALONE

    # CipherGuide Assistant Settings
    llm_provider_order: str = "xai,ollama,offline"
    xai_base_url: str = "https://api.x.ai/v1"
    xai_api_key: Optional[str] = None
    xai_model: str = "grok-beta"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b"


settings = Settings()
