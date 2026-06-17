import os
from typing import Set
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator

class Settings(BaseSettings):
    # API Settings
    PROJECT_NAME: str = "Threat Intelligence Platform (TIP)"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Security
    # In production, these should be securely stored (e.g., hash comparison in DB).
    # For bootstrap, we define default keys and roles.
    ADMIN_API_KEYS: Set[str] = Field(
        default_factory=lambda: {"admin-secret-key-12345"}
    )
    ANALYST_API_KEYS: Set[str] = Field(
        default_factory=lambda: {"analyst-secret-key-67890"}
    )
    
    # Infrastructure
    POSTGRES_SERVER: str = Field(default="localhost")
    POSTGRES_USER: str = Field(default="postgres")
    POSTGRES_PASSWORD: str = Field(default="postgres")
    POSTGRES_DB: str = Field(default="threat_intel")
    POSTGRES_PORT: int = Field(default=5432)
    
    REDIS_HOST: str = Field(default="localhost")
    REDIS_PORT: int = Field(default=6379)
    REDIS_DB: int = Field(default=0)
    
    # Dynamic calculated fields
    @property
    def DATABASE_URL_SYNC(self) -> str:
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        
    @property
    def DATABASE_URL_ASYNC(self) -> str:
        return f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    @property
    def REDIS_URL(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # Enrichment API Keys & Configs
    VIRUSTOTAL_API_KEY: str = Field(default="mock_vt_key")
    VIRUSTOTAL_RATE_LIMIT_RPM: int = Field(default=4)  # Free tier default: 4 requests per minute
    
    SHODAN_API_KEY: str = Field(default="mock_shodan_key")
    SHODAN_RATE_LIMIT_RPS: int = Field(default=1)  # Free tier default: 1 request per second
    
    # Threat Scoring & Decay
    # Lambda determines the speed of decay. e.g., lambda = 0.05 means score drops ~5% per day.
    DECAY_LAMBDA: float = Field(default=0.05)
    
    # Cache settings
    DEFAULT_CACHE_TTL_SECONDS: int = Field(default=300)  # 5 minutes
    
    # Configuration setup
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8", 
        case_sensitive=True,
        extra="ignore"
    )

settings = Settings()
