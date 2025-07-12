import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database Configuration
    DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:password@postgres:5432/port_scanner_db')
    
    # Flask Configuration
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-change-this-in-production')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    
    # Email Configuration (for alerts)
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USERNAME = os.getenv('SMTP_USERNAME', 'your-email@gmail.com')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'your-app-password')
    ALERT_EMAIL = os.getenv('ALERT_EMAIL', 'admin@example.com')
    
    # Webhook Configuration (for alerts)
    WEBHOOK_URL = os.getenv('WEBHOOK_URL', 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK')
    
    # Scan Configuration
    DEFAULT_SCAN_TIMEOUT = int(os.getenv('DEFAULT_SCAN_TIMEOUT', 300))
    DEFAULT_MAX_THREADS = int(os.getenv('DEFAULT_MAX_THREADS', 100))
    SCHEDULED_SCAN_INTERVAL = int(os.getenv('SCHEDULED_SCAN_INTERVAL', 3600))  # 1 hour in seconds
    
    # Nmap Configuration
    NMAP_TIMING_TEMPLATE = os.getenv('NMAP_TIMING_TEMPLATE', '4')  # 0-5 arası değer
    NMAP_SCRIPT_ARGS = os.getenv('NMAP_SCRIPT_ARGS', 'version-intensity=5') 