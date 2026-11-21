"""Application settings loaded from environment / .env via pydantic-settings."""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = Field(default="Cyber Recovery Orchestrator", alias="APP_NAME")
    version: str = Field(default="1.0.0", alias="APP_VERSION")
    database_url: str = Field(default="sqlite:///./data/cyber_recovery.db", alias="DATABASE_URL")
    llm_mode: str = Field(default="mock", alias="LLM_MODE")
    llm_base_url: str = Field(default="http://localhost:8000/v1", alias="LLM_BASE_URL")
    llm_api_key: str = Field(default="", alias="LLM_API_KEY")
    llm_model: str = Field(default="gpt-4o-mini", alias="LLM_MODEL")
    cors_origins: str = Field(
        default="http://localhost:8011,http://127.0.0.1:8011", alias="CORS_ORIGINS"
    )
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    enable_fault_injection: bool = Field(default=False, alias="ENABLE_FAULT_INJECTION")

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_mock_llm(self) -> bool:
        return self.llm_mode.lower() == "mock"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
