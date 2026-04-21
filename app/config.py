from functools import lru_cache
from pydantic import BaseModel
import os
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseModel):
    app_title: str = os.getenv("APP_TITLE", "CyberSec Portal")
    host: str = os.getenv("APP_HOST", "0.0.0.0")
    port: int = int(os.getenv("APP_PORT", "8000"))
    debug: bool = os.getenv("APP_DEBUG", "false").lower() == "true"
    base_url: str = os.getenv("APP_BASE_URL", "http://localhost:8000")

    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    shodan_api_key: str = os.getenv("SHODAN_API_KEY", "")
    alienvault_otx_api_key: str = os.getenv("ALIENVAULT_OTX_API_KEY", "")
    urlscan_api_key: str = os.getenv("URLSCAN_API_KEY", "")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
