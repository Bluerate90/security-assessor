"""
Configuration Management for Security Assessor
Loads environment variables from .env file
"""

import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    print("❌ python-dotenv not installed. Run: pip install python-dotenv")
    sys.exit(1)

# Load .env file from Configuration directory
ENV_FILE = Path(__file__).parent / '.env'
if ENV_FILE.exists():
    load_dotenv(ENV_FILE)
    print(f"✓ Loaded environment from {ENV_FILE}")
else:
    print(f"⚠ .env file not found at {ENV_FILE}")
    print(f"  Create it by copying Configuration/.env.example")


class Config:
    """Configuration - reads from .env via dotenv"""
    
    # API Configuration
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
    GEMINI_MODEL = 'gemini-2.0-flash-exp'
    
    # Flask Configuration
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    PORT = int(os.getenv('PORT', 5000))
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Cache Configuration
    CACHE_DIR = Path(os.getenv('CACHE_DIR', './Runtime/assessor_cache'))
    CACHE_TTL_DAYS = int(os.getenv('CACHE_TTL_DAYS', 7))
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', './logs/assessor.log')
    
    # Timeout Configuration
    REQUEST_TIMEOUT = 30
    CISA_KEV_TIMEOUT = 15
    
    # Request Configuration
    USER_AGENT = 'SecurityAssessor/1.0 (Research Tool)'
    
    @classmethod
    def validate(cls):
        """Validate critical configuration"""
        errors = []
        
        if not cls.GEMINI_API_KEY:
            errors.append("GEMINI_API_KEY is required. Set it in Configuration/.env file")
        
        if not cls.CACHE_DIR:
            errors.append("CACHE_DIR is required")
        
        return errors
    
    @classmethod
    def display(cls):
        """Display configuration (without sensitive data)"""
        print("\n" + "="*70)
        print("⚙️  CONFIGURATION")
        print("="*70)
        print(f"Environment:       {cls.FLASK_ENV}")
        print(f"Debug Mode:        {cls.DEBUG}")
        print(f"Port:              {cls.PORT}")
        print(f"Cache Directory:   {cls.CACHE_DIR}")
        print(f"Cache TTL:         {cls.CACHE_TTL_DAYS} days")
        print(f"Log Level:         {cls.LOG_LEVEL}")
        print(f"Gemini Model:      {cls.GEMINI_MODEL}")
        print(f"API Key Status:    {'✓ Configured' if cls.GEMINI_API_KEY else '✗ Missing'}")
        print("="*70 + "\n")


# Select configuration
config = Config()

# Validate on import
errors = config.validate()
if errors:
    print("\n❌ Configuration Errors:")
    for error in errors:
        print(f"  • {error}")
    print("\nPlease fix these issues before running the application.\n")
    sys.exit(1)