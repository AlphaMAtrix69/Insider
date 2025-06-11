"""API interaction module for fetching vulnerability data from NVD."""

import time
import datetime
import requests
import urllib3
import json

from va_tool.utils import (
    get_logger, API_KEYS, NVD_BASE_URL, NVD_TIMEOUT, 
    NVD_RETRY_ATTEMPTS, NVD_RETRY_DELAY
)

# Disable insecure request warnings
urllib3.disable_warnings()

# Get logger
logger = get_logger()

# Track API usage to avoid rate limits
_api_key_index = 0
_request_count = 0


def get_api_key():
    """Get the next API key with rotation to avoid rate limits."""
    global _api_key_index, _request_count
    
    if _request_count >= 1000:
        _api_key_index = (_api_key_index + 1) % len(API_KEYS)
        _request_count = 0
    
    _request_count += 1
    return API_KEYS[_api_key_index]


def fetch_cve_details(cve_id, job_cve_cache, timeout_threshold=30):
    """
    Fetch details for a CVE from NVD API.
    
    Args:
        cve_id: CVE identifier to fetch
        job_cve_cache: Dictionary for caching results
        timeout_threshold: Maximum time to wait for API response
    
    Returns:
        Dictionary with CVE details
    """
    # Return from cache if available
    if cve_id in job_cve_cache:
        return job_cve_cache[cve_id]

    url = f"{NVD_BASE_URL}?cveId={cve_id}"
    headers = {"apiKey": get_api_key()}
    start_time = time.time()

    for attempt in range(NVD_RETRY_ATTEMPTS):
        # Check if we've exceeded timeout threshold
        if time.time() - start_time > timeout_threshold:
            logger.warning(f"Timeout threshold exceeded for {cve_id}")
            job_cve_cache[cve_id] = {
                "date_obj": None,
                "patch_info": {"status": "CVE Not Found", "references": []}
            }
            return job_cve_cache[cve_id]
            
        try:
            logger.debug(f"Fetching CVE details for {cve_id} (attempt {attempt+1})")
            response = requests.get(
                url, headers=headers, timeout=NVD_TIMEOUT, verify=False
            )
            
            # Handle rate limiting
            if response.status_code in [403, 429]:
                logger.warning(f"Rate limit hit on attempt {attempt+1}. Waiting...")
                time.sleep(NVD_RETRY_DELAY * (attempt + 1))
                continue
                
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if vulnerabilities:
                cve_data = vulnerabilities[0].get("cve", {})

                # Extract publication date
                published_raw = cve_data.get("published", "")
                published_date = None
                if published_raw:
                    published_date = datetime.datetime.strptime(
                        published_raw.split("T")[0], "%Y-%m-%d"
                    ).date()

                # Extract patch information
                references = cve_data.get("references", [])
                patch_links = []
                for ref in references:
                    tags = ref.get("tags", [])
                    if any(tag.lower() in ["patch", "vendor advisory", "third party advisory"] for tag in tags):
                        patch_links.append({
                            "url": ref.get("url", ""),
                            "source": ref.get("source", "Unknown"),
                            "tags": tags
                        })

                # Determine patch status
                if patch_links:
                    status = "Available"
                else:
                    workarounds = cve_data.get("workarounds", [])
                    status = "Workaround Available" if workarounds else "Not Found"

                patch_info = {
                    "status": status,
                    "references": patch_links
                }

                # Create cache entry
                job_cve_cache[cve_id] = {
                    "date_obj": published_date.isoformat() if published_date else None,
                    "patch_info": patch_info
                }
                
                logger.debug(f"Successfully retrieved data for {cve_id}")
                return job_cve_cache[cve_id]
            else:
                logger.warning(f"No vulnerability data found for {cve_id}")

        except requests.RequestException as e:
            logger.error(f"Request error for {cve_id}: {str(e)}")
            time.sleep(NVD_RETRY_DELAY * (attempt + 1))

    # If we've exhausted all attempts
    logger.warning(f"Failed to fetch data for {cve_id} after {NVD_RETRY_ATTEMPTS} attempts")
    job_cve_cache[cve_id] = {
        "date_obj": None,
        "patch_info": {"status": "CVE Not Found", "references": []}
    }
    return job_cve_cache[cve_id]