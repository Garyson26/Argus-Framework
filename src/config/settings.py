"""
Pydantic-based configuration management for FuFuFaFa.

Environment variables can be loaded from a .env file or set directly.
All settings use the FUFUFAFA_ prefix.
"""

from functools import lru_cache
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with validation."""

    model_config = SettingsConfigDict(
        env_prefix="FUFUFAFA_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "FuFuFaFa"
    app_version: str = "0.1.0"
    debug: bool = False
    log_level: str = "INFO"

    # PostgreSQL Database
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "fufufafa"
    postgres_password: str = "fufufafa_secret"
    postgres_db: str = "fufufafa"

    @property
    def postgres_url(self) -> str:
        """Construct PostgreSQL connection URL."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def postgres_sync_url(self) -> str:
        """Construct synchronous PostgreSQL connection URL for Alembic."""
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # Neo4j Graph Database
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "neo4j_secret"

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None

    @property
    def redis_url(self) -> str:
        """Construct Redis connection URL."""
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # Celery
    celery_broker_url: Optional[str] = None
    celery_result_backend: Optional[str] = None

    @property
    def celery_broker(self) -> str:
        """Get Celery broker URL."""
        return self.celery_broker_url or self.redis_url

    @property
    def celery_backend(self) -> str:
        """Get Celery result backend URL."""
        return self.celery_result_backend or self.redis_url

    # AWS Configuration
    aws_profile: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    aws_region: str = "us-east-1"
    aws_assume_role_arn: Optional[str] = None

    # Scanning Configuration
    max_concurrent_scans: int = Field(default=5, ge=1, le=50)
    scan_timeout: int = Field(default=3600, ge=60, le=86400)  # 1 hour default, max 24 hours
    max_findings_per_scan: int = Field(default=10000, ge=100, le=100000)

    # Secret Scanner Configuration
    secret_entropy_threshold: float = Field(default=4.5, ge=3.0, le=6.0)
    secret_max_file_size_mb: int = Field(default=10, ge=1, le=100)
    secret_scan_git_history: bool = True
    secret_max_commits: int = Field(default=1000, ge=1, le=10000)

    # IaC Scanner Configuration
    iac_checkov_enabled: bool = True
    iac_skip_checks: list[str] = Field(default_factory=list)
    iac_custom_rules_path: Optional[str] = None

    # Report Configuration
    report_output_dir: str = "./reports"
    report_format: str = "json"  # json, markdown, html

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is valid."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return v_upper

    @field_validator("report_format")
    @classmethod
    def validate_report_format(cls, v: str) -> str:
        """Validate report format."""
        valid_formats = {"json", "markdown", "html"}
        v_lower = v.lower()
        if v_lower not in valid_formats:
            raise ValueError(f"report_format must be one of {valid_formats}")
        return v_lower


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
