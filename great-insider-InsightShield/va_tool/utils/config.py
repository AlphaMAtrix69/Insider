"""Configuration settings for the vulnerability analysis tool."""

# API keys for NVD access
API_KEYS = [
    "1ded7e2c-e9ab-4f52-9912-28e6813f4ecc",
    "7d9a6100-9e86-4a0f-88fe-fa1a58537cb4",
    "e8eac3c1-6308-43c9-8d04-ddb739fb0aa5",
    "8d7f67cf-9146-4423-b128-876a2093906b",
]

# Visualization settings
PALETTE = ['#0173b2', '#de8f05', '#029e73', '#d55e00', '#cc78bc', 
           '#ca9161', '#fbafe4', '#949494', '#ece133', '#56b4e9']

# Risk-based color mapping
RISK_COLORS = {
    "Critical": "#d62728", 
    "High": "#ff7f0e", 
    "Medium": "#ffbb78", 
    "Low": "#2ca02c"
}

# NVD API settings
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 10
NVD_RETRY_ATTEMPTS = 5
NVD_RETRY_DELAY = 5  # seconds

# Cache settings
DEFAULT_CACHE_DIR = "cache"
DEFAULT_CACHE_FILE = "cve_cache.csv"

# Default output settings
DEFAULT_OUTPUT_DIR = "output"