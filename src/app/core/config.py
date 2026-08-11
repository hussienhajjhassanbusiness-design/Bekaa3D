from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    debug: bool = False
    base_url: str = "http://localhost:8000"
    app_version: str = "0.1.0"
    git_commit_sha: str = "unknown"

    database_url: str
    redis_url: str

    jwt_signing_key: str
    csrf_secret: str
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    ip_hash_salt: str

    storage_root: str = "/data"
    stl_private_dir: str = "/data/stl_private"
    uploads_private_dir: str = "/data/uploads_private"
    media_public_dir: str = "/data/media_public"
    xaccel_prefix: str = "/protected"

    payment_provider: str = "mock"
    whish_base_url: str = ""
    whish_channel: str = ""
    whish_secret: str = ""
    whish_webhook_ips: str = ""
    whish_verify_signature: bool = False

    email_provider: str = "console"
    email_provider_key: str = ""
    email_from: str = "no-reply@example.com"

    turnstile_secret: str = ""

    sentry_dsn: str = ""
    log_level: str = "INFO"

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
