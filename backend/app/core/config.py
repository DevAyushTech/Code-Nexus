from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: Literal["local", "testing", "production"] = "local"
    api_auth_mode: Literal["demo", "protected_demo"] = "demo"
    database_url: str = "sqlite:///./nexus.db"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000", "http://localhost:5173"])
    request_timeout_seconds: float = 8.0
    max_response_bytes: int = 1_000_000
    max_redirects: int = 5
    rate_limit_window_seconds: int = 60
    url_analysis_rate_limit: int = 10
    message_analysis_rate_limit: int = 10
    threat_report_rate_limit: int = 5
    api_auth_key: SecretStr | None = None
    supabase_project_url: str = "https://zbtbesczdshgfgcxueev.supabase.co"
    supabase_jwks_url: str = "https://zbtbesczdshgfgcxueev.supabase.co/auth/v1/.well-known/jwks.json"
    supabase_jwt_issuer: str = "https://zbtbesczdshgfgcxueev.supabase.co/auth/v1"
    supabase_jwt_audience: str = "authenticated"
    supabase_jwt_algorithms: list[str] = Field(default_factory=lambda: ["ES256"])
    urlhaus_api_url: str = "https://urlhaus-api.abuse.ch/v1/url/"
    urlhaus_auth_key: SecretStr | None = None
    google_safe_browsing_key: SecretStr | None = None
    google_safe_browsing_url: str = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    ai_enabled: bool = False
    ai_provider: Literal["disabled", "openai_compatible", "gemini"] = "disabled"
    ai_api_key: SecretStr | None = None
    ai_base_url: str = "https://openrouter.ai/api/v1"
    ai_model: str = "openai/gpt-4o-mini"
    blockchain_rpc_url: str | None = None
    blockchain_contract_address: str | None = None
    blockchain_private_key: SecretStr | None = None
    blockchain_mode: Literal["mock", "sepolia"] = "mock"
    blockchain_chain_id: int = 11155111
    blockchain_confirmations: int = Field(default=2, ge=0)
    blockchain_tx_timeout: int = Field(default=120, gt=0)
    blockchain_gas_limit: int = Field(default=200_000, gt=0)
    blockchain_account_address: str | None = None

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or "://" not in normalized:
            raise ValueError("DATABASE_URL must be a non-empty SQLAlchemy URL.")
        if normalized.startswith("sqlite://") or normalized.startswith(("postgresql://", "postgresql+psycopg://")):
            return normalized
        raise ValueError("DATABASE_URL must use SQLite or PostgreSQL.")

    @model_validator(mode="after")
    def validate_blockchain_configuration(self) -> "Settings":
        if self.blockchain_chain_id == 1:
            raise ValueError("Mainnet configuration is not supported.")
        if self.blockchain_rpc_url and "mainnet" in self.blockchain_rpc_url.lower():
            raise ValueError("Mainnet RPC endpoints are not supported.")
        if self.blockchain_mode == "mock":
            return self

        if self.blockchain_chain_id != 11155111:
            raise ValueError("Sepolia mode requires blockchain_chain_id=11155111.")
        if not self.blockchain_rpc_url or not self.blockchain_contract_address:
            raise ValueError("Sepolia mode requires RPC URL and contract address.")
        if not self.blockchain_contract_address.startswith("0x") or len(self.blockchain_contract_address) != 42:
            raise ValueError("Invalid blockchain contract address.")
        has_private_key = bool(self.blockchain_private_key and self.blockchain_private_key.get_secret_value().strip())
        has_account_address = bool(self.blockchain_account_address and self.blockchain_account_address.strip())
        if has_private_key != has_account_address:
            raise ValueError("Sepolia write mode requires both account address and private key.")
        if self.blockchain_account_address and (
            not self.blockchain_account_address.startswith("0x") or len(self.blockchain_account_address) != 42
        ):
            raise ValueError("Invalid blockchain account address.")
        if self.blockchain_private_key:
            private_key = self.blockchain_private_key.get_secret_value()
            if not private_key.startswith("0x") or len(private_key) != 66:
                raise ValueError("Invalid blockchain private key format.")
        return self

    @model_validator(mode="after")
    def validate_api_authentication(self) -> "Settings":
        if self.api_auth_mode == "protected_demo" and (
            not self.api_auth_key or not self.api_auth_key.get_secret_value().strip()
        ):
            raise ValueError("Protected demo mode requires a non-empty API_AUTH_KEY.")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
