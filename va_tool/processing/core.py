"""Core data processing module for vulnerability analysis."""

import datetime
import os

from va_tool.data import (
    fetch_cve_details, load_cve_cache, save_cve_cache,
    get_cache_path, clear_cache
)
from va_tool.processing.categorization import categorize_vulnerabilities
from va_tool.processing.scoring import add_scoring_data
from va_tool.processing.analysis import analyze_vulnerability_data
from va_tool.utils import get_logger

logger = get_logger()


def process_vulnerability_data(vuln_df, kev_set, output_dir, clear_cache_flag=False):
    """
    Process vulnerability data through the entire pipeline.
    
    Args:
        vuln_df: DataFrame with vulnerability data
        kev_set: Set of CVE IDs from KEV list
        output_dir: Directory to save output files
        clear_cache_flag: Whether to clear the CVE cache
    
    Returns:
        Tuple of (original_df, processed_df, checked_df, analyzed_df, results_data)
    """
    logger.info("Starting vulnerability data processing pipeline")
    
    # 1. Setup cache
    cache_file_path = get_cache_path(output_dir)
    
    # Clear cache if requested
    if clear_cache_flag:
        clear_cache(cache_file_path)
    
    # Load existing cache
    job_cve_cache = load_cve_cache(cache_file_path)
    cache_hit_count = 0
    cache_miss_count = 0
    
    # 2. Apply initial categorization
    logger.info("Applying initial categorization")
    df = categorize_vulnerabilities(vuln_df)
    
    # 3. Filter out informational findings
    logger.info("Filtering out informational findings")
    working_df = df[~df["Risk"].isin(["None", "Informational"])]
    
    # 4. Fetch CVE details
    logger.info("Fetching CVE details")
    
    # Extract unique CVEs
    unique_cves = working_df["CVE"].dropna().unique()
    
    # Determine which CVEs need to be fetched
    cves_to_fetch = [cve for cve in unique_cves if cve not in job_cve_cache]
    
    logger.info(f"Found {len(unique_cves)} unique CVEs")
    logger.info(f"- {len(unique_cves) - len(cves_to_fetch)} CVEs loaded from cache")
    logger.info(f"- {len(cves_to_fetch)} CVEs need to be fetched from NVD API")
    
    # Fetch only the CVEs not in cache
    for i, cve in enumerate(cves_to_fetch):
        if i % 10 == 0 or i == len(cves_to_fetch) - 1:
            logger.info(f"Processing CVE {i+1}/{len(cves_to_fetch)}: {cve}")
        fetch_cve_details(cve, job_cve_cache)
        cache_miss_count += 1
    
    # Count cache hits
    cache_hit_count = len(unique_cves) - len(cves_to_fetch)
    
    logger.info(f"CVE processing complete:")
    logger.info(f"- Cache hits: {cache_hit_count}")
    logger.info(f"- Cache misses: {cache_miss_count}")
    
    # Save the updated cache
    save_cve_cache(job_cve_cache, cache_file_path)
    
    # 5. Add scoring data
    logger.info("Adding scoring data")
    scored_df = add_scoring_data(working_df)
    
    # 6. Analyze vulnerability data
    logger.info("Analyzing vulnerability data")
    processed_df, check_needed_df, analyzed_df, results_data = analyze_vulnerability_data(
        scored_df, kev_set, job_cve_cache
    )
    
    logger.info("Data processing complete")
    return vuln_df, processed_df, check_needed_df, analyzed_df, results_data