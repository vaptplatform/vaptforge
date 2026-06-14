"""Application Configuration"""
import secrets
from typing import List, Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "VAPTForge Enterprise"
    APP_VERSION: str = "3.4.1"
    DEBUG: bool = False
    SECRET_KEY: str = secrets.token_urlsafe(64)
    API_TOKEN_EXPIRE_MINUTES: int = 1440

    DATABASE_URL: str = "sqlite+aiosqlite:///./vapt_platform.db"

    # Store as plain strings in .env — parsed by validator below
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:5173"
    ALLOWED_HOSTS: str = "localhost,127.0.0.1,*"

    JWT_ALGORITHM: str = "HS256"
    BCRYPT_ROUNDS: int = 12

    MAX_CONCURRENT_SCANS: int = 3
    SCAN_REQUEST_TIMEOUT: int = 10
    SCAN_CRAWL_DEPTH: int = 5
    SCAN_MAX_URLS: int = 500
    SCAN_RATE_LIMIT: int = 120
    SCANNER_USER_AGENT: str = "VAPTForge/3.4.1 (Authorized Security Scanner)"

    ZAP_API_URL: Optional[str] = None
    ZAP_API_KEY: Optional[str] = None
    NMAP_PATH: str = "nmap"
    NMAP_SAFE_FLAGS: str = "-sV --version-light -T2 --open"

    REPORTS_DIR: str = "./reports"
    MAX_REPORT_AGE_DAYS: int = 90

    FRONTEND_URL: str = "http://localhost:3000"
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASS: Optional[str] = None
    WEBHOOK_SECRET: Optional[str] = None

    # Parsed properties — use these everywhere instead of raw str fields
    @property
    def origins_list(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    @property
    def hosts_list(self) -> List[str]:
        return [h.strip() for h in self.ALLOWED_HOSTS.split(",") if h.strip()]

    model_config = {"env_file": ".env", "case_sensitive": True, "extra": "ignore"}


settings = Settings()
