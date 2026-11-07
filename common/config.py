"""
common.config – Centralized configuration loader using pydantic-settings.

All values can be overridden via environment variables or a .env file.
Secrets (SERVICE_TOKEN) are NEVER committed — load from environment only.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Platform-wide configuration.

    Env-var precedence: OS env > .env file > defaults.
    """

    # ── Service URLs (defaults to localhost for host runs; overridden by Docker env) ──
    m1_url: str = "http://localhost:8001"
    m2_url: str = "http://localhost:8002"
    m3_url: str = "http://localhost:8003"
    m4_url: str = "http://localhost:8004"
    m5_url: str = "http://localhost:8005"
    dashboard_url: str = "http://localhost:8080"
    resource_app_url: str = "http://localhost:8090"
    webhook_url: str = "http://localhost:8099/webhook"

    # ── Auth ─────────────────────────────────────────────────────────────────
    service_token: str = "dev-secret-change-in-prod"

    # ── ML / training ────────────────────────────────────────────────────────
    model_seed: int = 42
    train_normal_count: int = 10_000
    train_attack_count: int = 500
    contamination: float = 0.05

    # ── Logging ──────────────────────────────────────────────────────────────
    log_level: str = "INFO"

    # ── Posture weights (also loaded from YAML by M4) ───────────────────────
    posture_weight_patch: float = 0.40
    posture_weight_os: float = 0.30
    posture_weight_av: float = 0.20
    posture_weight_vuln: float = 0.10

    # ── Policy TTLs (seconds) ────────────────────────────────────────────────
    ttl_low_risk: int = 300
    ttl_medium_risk: int = 60
    ttl_high_risk: int = 30

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings singleton."""
    return Settings()
