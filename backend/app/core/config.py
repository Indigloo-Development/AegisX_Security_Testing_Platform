from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AegisX Security Platform"
    environment: str = "development"
    database_url: str = "sqlite:///./aegisx.db"
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    log_level: str = "INFO"
    docs_enabled: bool = True
    trusted_proxy_ips: str = ""
    request_timeout_seconds: int = 30
    max_scan_concurrency: int = 4

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
