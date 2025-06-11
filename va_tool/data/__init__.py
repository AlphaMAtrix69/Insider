"""Make the data directory a proper package."""

from va_tool.data.api import fetch_cve_details, get_api_key
from va_tool.data.cache import load_cve_cache, save_cve_cache, clear_cache, get_cache_path
from va_tool.data.loaders import load_vulnerability_file, load_kev_file
from va_tool.data.mappings import BUCKET_MAPPINGS, NAME_MAPPINGS

__all__ = [
    # From api
    'fetch_cve_details', 'get_api_key',
    
    # From cache
    'load_cve_cache', 'save_cve_cache', 'clear_cache', 'get_cache_path',
    
    # From loaders
    'load_vulnerability_file', 'load_kev_file',
    
    # From mappings
    'BUCKET_MAPPINGS', 'NAME_MAPPINGS'
]