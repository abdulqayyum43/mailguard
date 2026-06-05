from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    admin_secret: str = "change-me-in-production"
    initial_api_keys: str = "test-key-1,test-key-2"
    rapidapi_proxy_secret: str = ""

    scan_timeout: float = 20.0
    dns_timeout: float = 5.0
    smtp_connect_timeout: float = 5.0

    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60

    environment: Literal["development", "production"] = "development"

    # SMTP email alerts
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "mailguard@yourdomain.com"
    smtp_use_tls: bool = True

    # Monitoring loop interval (seconds)
    monitor_check_interval: int = 300

    # ToyyibPay billing
    toyyibpay_secret_key: str = ""
    toyyibpay_category_code: str = ""

    # Stripe (optional)
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_pro_price_id: str = ""
    stripe_enterprise_price_id: str = ""

    # Public URL
    public_url: str = "http://localhost:8003"

    # Data directory
    data_dir: str = "data"


settings = Settings()
