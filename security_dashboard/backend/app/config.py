from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mongodb_uri: str
    security_monitor_secret: str
    mongodb_database: str = "security_monitor"
    retention_days: int = 90
    max_findings_per_run: int = 5000

    @field_validator("mongodb_uri")
    @classmethod
    def validate_mongodb_uri(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith(("mongodb+srv://", "mongodb://")):
            raise ValueError("MONGODB_URI must use mongodb+srv:// or mongodb://")
        return value

    @field_validator("security_monitor_secret")
    @classmethod
    def validate_monitor_secret(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("SECURITY_MONITOR_SECRET is required")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
