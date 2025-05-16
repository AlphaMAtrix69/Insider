"""Cache management for vulnerability data."""

import os
import json
import pandas as pd
import datetime

from va_tool.utils import get_logger, ensure_dir_exists, DEFAULT_CACHE_DIR, DEFAULT_CACHE_FILE

logger = get_logger()


def get_cache_path(output_dir=None, cache_filename=None):
    """
    Get the path to the cache file.
    
    Args:
        output_dir: Base output directory
        cache_filename: Name of the cache file
    
    Returns:
        Path to the cache file
    """
    cache_dir = os.path.join(output_dir or ".", DEFAULT_CACHE_DIR)
    cache_file = cache_filename or DEFAULT_CACHE_FILE
    return os.path.join(cache_dir, cache_file)


def load_cve_cache(cache_file_path):
    """
    Load CVE details from CSV cache file if it exists.
    
    Args:
        cache_file_path: Path to the cache file
    
    Returns:
        Dictionary with cached CVE data
    """
    cache = {}
    try:
        if os.path.exists(cache_file_path):
            logger.info(f"Loading CVE cache from {cache_file_path}")
            cache_df = pd.read_csv(cache_file_path)
            
            # Convert dataframe back to dictionary format
            for _, row in cache_df.iterrows():
                cve_id = row['cve_id']
                date_obj = row['date_obj']
                patch_status = row['patch_status']
                
                # Handle references which are stored as string representation of JSON
                try:
                    references = json.loads(row['references']) if not pd.isna(row['references']) else []
                except:
                    references = []
                
                cache[cve_id] = {
                    "date_obj": date_obj if not pd.isna(date_obj) else None,
                    "patch_info": {"status": patch_status, "references": references}
                }
            
            logger.info(f"Loaded {len(cache)} CVEs from cache")
        return cache
    except Exception as e:
        logger.error(f"Error loading CVE cache: {str(e)}")
        return {}


def save_cve_cache(cache, cache_file_path):
    """
    Save CVE details to CSV cache file.
    
    Args:
        cache: Dictionary with CVE data to cache
        cache_file_path: Path to save the cache file
    
    Returns:
        Boolean indicating success
    """
    try:
        # Convert cache dictionary to dataframe for CSV storage
        cache_data = []
        for cve_id, details in cache.items():
            date_obj = details.get("date_obj")
            patch_info = details.get("patch_info", {})
            patch_status = patch_info.get("status", "Unknown")
            references = json.dumps(patch_info.get("references", []))
            
            cache_data.append({
                "cve_id": cve_id,
                "date_obj": date_obj,
                "patch_status": patch_status,
                "references": references,
                "cached_date": datetime.datetime.now().strftime("%Y-%m-%d")
            })
        
        # Create dataframe and save to CSV
        cache_df = pd.DataFrame(cache_data)
        
        # Ensure directory exists
        ensure_dir_exists(os.path.dirname(cache_file_path))
        
        # Save to CSV
        cache_df.to_csv(cache_file_path, index=False)
        logger.info(f"Saved {len(cache)} CVEs to cache at {cache_file_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving CVE cache: {str(e)}")
        return False


def clear_cache(cache_file_path):
    """Clear the CVE cache file if it exists."""
    if os.path.exists(cache_file_path):
        try:
            os.remove(cache_file_path)
            logger.info(f"Cleared CVE cache: {cache_file_path}")
            return True
        except Exception as e:
            logger.error(f"Error clearing cache: {str(e)}")
            return False
    return True