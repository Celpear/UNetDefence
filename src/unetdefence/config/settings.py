"""Application settings from environment and config file."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database connection. Default: SQLite (no server). Use PostgreSQL URL for production."""

    model_config = SettingsConfigDict(env_prefix="UNETDEFENCE_DATABASE_")

    url: str = Field(
        default="sqlite:///./unetdefence.db",
        description="Database URL: sqlite:///./unetdefence.db (default) or postgresql://...",
    )
    pool_size: int = Field(default=5, ge=1, le=50)
    max_overflow: int = Field(default=10, ge=0)


class GeoIPSettings(BaseSettings):
    """GeoIP / MaxMind configuration (optional for lite setups)."""

    model_config = SettingsConfigDict(env_prefix="UNETDEFENCE_GEOIP_")

    db_path: str | None = Field(default=None, description="Path to MaxMind GeoLite2-City or Country DB")
    enabled: bool = Field(default=False, description="Set True and set db_path for country/ASN enrichment")


class EmbeddingSettings(BaseSettings):
    """Embedding provider configuration (for semantic search). Lite default: disabled."""

    model_config = SettingsConfigDict(env_prefix="UNETDEFENCE_EMBEDDING_")

    provider: Literal["openai", "ollama", "sentence-transformers", "disabled"] = Field(
        default="disabled",
        description="Embedding provider; set to 'ollama' for local lite use",
    )
    model: str = Field(default="nomic-embed-text", description="Model name (e.g. nomic-embed-text for Ollama)")
    base_url: str | None = Field(default="http://localhost:11434", description="Base URL for API (Ollama)")
    api_key: str | None = Field(default=None, description="API key if required")
    dimensions: int = Field(default=384, ge=64, le=3072)
    batch_size: int = Field(default=32, ge=1, le=256)
    timeout_seconds: float = Field(default=30.0, gt=0)


class LLMSettings(BaseSettings):
    """LLM provider configuration (analyst layer). Lite default: Ollama with small model."""

    model_config = SettingsConfigDict(env_prefix="UNETDEFENCE_LLM_")

    provider: Literal["openai", "ollama", "anthropic", "disabled"] = Field(
        default="ollama",
        description="LLM provider; 'ollama' for local lite use",
    )
    model: str = Field(default="llama3.2:1b", description="Model name (small: llama3.2:1b, phi3:mini; larger: llama3.2:3b)")
    base_url: str | None = Field(default="http://localhost:11434", description="Base URL for Ollama")
    api_key: str | None = Field(default=None, description="API key if required (OpenAI/Anthropic)")
    timeout_seconds: float = Field(default=60.0, gt=0)
    max_tokens: int = Field(default=1024, ge=256, le=8192)


class FritzBoxSettings(BaseSettings):
    """FRITZ!Box / router context (optional)."""

    model_config = SettingsConfigDict(env_prefix="UNETDEFENCE_FRITZ_")

    enabled: bool = Field(default=False)
    base_url: str = Field(default="http://fritz.box", description="Router base URL")
    username: str | None = Field(default=None)
    password: str | None = Field(default=None)
    poll_interval_seconds: int = Field(default=60, ge=10)


class IngestSettings(BaseSettings):
    """Ingest worker paths and behaviour."""

    model_config = SettingsConfigDict(env_prefix="UNETDEFENCE_INGEST_")

    zeek_log_dir: str | None = Field(default=None, description="Directory with Zeek log files")
    suricata_eve_path: str | None = Field(default=None, description="Path to Suricata eve.json or directory")
    batch_size: int = Field(default=500, ge=1, le=5000)
    poll_interval_seconds: float = Field(default=1.0, gt=0)
    dedup_window_seconds: int = Field(default=300, ge=0)


class Settings(BaseSettings):
    """Root application settings."""

    model_config = SettingsConfigDict(
        env_prefix="UNETDEFENCE_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["development", "staging", "production"] = Field(default="development")
    log_level: str = Field(default="INFO")
    secret_key: str | None = Field(default=None, description="For encrypting stored secrets")

    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    geoip: GeoIPSettings = Field(default_factory=GeoIPSettings)
    embedding: EmbeddingSettings = Field(default_factory=EmbeddingSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    fritz: FritzBoxSettings = Field(default_factory=FritzBoxSettings)
    ingest: IngestSettings = Field(default_factory=IngestSettings)


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance."""
    return Settings()
