from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Infra
    database_url: str = "postgresql+asyncpg://iam:iam@localhost:5432/iam"
    redis_url: str = "redis://localhost:6379/0"

    # JWT
    jwt_secret: str = "change-me-in-production-use-a-long-random-string"
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 900          # 15 min
    refresh_token_ttl_seconds: int = 604800       # 7 days

    # Sessions (server-side, cookie)
    session_ttl_seconds: int = 86400              # 1 day
    session_cookie_name: str = "iam_session"

    # Passwordless / OTP / magic links
    otp_ttl_seconds: int = 300                    # 5 min
    magic_link_ttl_seconds: int = 600             # 10 min
    reset_token_ttl_seconds: int = 1800

    # TOTP / MFA
    totp_issuer: str = "IAM Platform"
    step_up_ttl_seconds: int = 300                # how long a step-up auth is valid

    # WebAuthn
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "IAM Platform"
    webauthn_origin: str = "http://localhost:8080"

    # OAuth2 provider (this app acting as an IdP)
    oauth_code_ttl_seconds: int = 60
    device_code_ttl_seconds: int = 900

    # External providers — mock mode when creds are absent
    provider_mode: str = "mock"                   # "mock" | "real"
    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    smtp_host: str = ""

    # CORS
    cors_origins: str = "http://localhost:5173,http://localhost:3000,http://localhost:8080"

    log_level: str = "INFO"

    # Postgres (compose substitution)
    postgres_user: str = "iam"
    postgres_password: str = "iam"
    postgres_db: str = "iam"

    def get_cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()
