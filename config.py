import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-forensics-secure-key-2026-prod-fallback")
    
    # Database configuration with psycopg2 driver
    raw_db_url = os.getenv(
        "DATABASE_URL",
        "postgresql://ansan@localhost:5432/digital_forensics_db"
    )
    if raw_db_url.startswith("postgresql://"):
        SQLALCHEMY_DATABASE_URI = raw_db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
    else:
        SQLALCHEMY_DATABASE_URI = raw_db_url

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # Uploads and Evidence Storage
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads", "evidence")
    MAX_CONTENT_LENGTH = 250 * 1024 * 1024  # 250 MB max upload
    ALLOWED_EXTENSIONS = {
        "raw", "dd", "img", "bin", "iso", "vmdk", "e01",
        "pcap", "pcapng", "cap",
        "log", "txt", "csv", "json", "xml", "pdf",
        "zip", "tar", "gz", "7z", "bz2",
        "png", "jpg", "jpeg", "bmp", "tiff",
        "eml", "msg", "pst", "db", "sqlite", "sqlite3",
        "exe", "dll", "elf", "mem", "dmp"
    }

    # Security settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    TEMPLATES_AUTO_RELOAD = True
