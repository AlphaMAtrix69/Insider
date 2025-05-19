"""Scoring functionality for vulnerability analysis."""

import pandas as pd
from va_tool.utils import get_logger

logger = get_logger()


def categorize_cvss_score(score):
    """
    Categorize CVSS score into severity levels.
    
    Args:
        score: CVSS score (0-10)
    
    Returns:
        String with severity category
    """
    if pd.isna(score):
        return "Not Assigned"
    try:
        score = float(score)
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        return "Not Assigned"
    except (ValueError, TypeError):
        return "Not Assigned"


def categorize_epss_score(score):
    """
    Categorize EPSS score into severity levels.
    
    Args:
        score: EPSS score (0-1)
    
    Returns:
        String with severity category
    """
    if pd.isna(score):
        return "Not Assigned"
    try:
        score = float(score)
        if score >= 0.9:
            return "Critical"
        elif score >= 0.7:
            return "High"
        elif score >= 0.4:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        return "Not Assigned"
    except (ValueError, TypeError):
        return "Not Assigned"


def categorize_vpr_score(score):
    """
    Categorize VPR score into severity levels.
    
    Args:
        score: VPR score (0-10)
    
    Returns:
        String with severity category
    """
    if pd.isna(score):
        return "Not Assigned"
    try:
        score = float(score)
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        return "Not Assigned"
    except (ValueError, TypeError):
        return "Not Assigned"


def calculate_exploitability_score(row):
    """
    Calculate exploitability score based on EPSS, VPR, and KEV scores.
    
    Args:
        row: DataFrame row with category scores
    
    Returns:
        Integer with combined exploitability score
    """
    # Convert categories to priority scores
    priority_scores = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1,
        'Not Assigned': 0,
        'Yes': 4,
        'No': 0
    }
    
    # Get scores from categories
    epss_score = priority_scores.get(row.get('EPSS Category', 'Not Assigned'), 0)
    vpr_score = priority_scores.get(row.get('VPR Category', 'Not Assigned'), 0)
    kev_score = priority_scores.get(row.get('KEV Listed', 'No'), 0)
    
    # Calculate total exploitability score
    return epss_score + vpr_score + kev_score


def add_scoring_data(df):
    """
    Add scoring-related columns to the vulnerability DataFrame.
    
    Args:
        df: DataFrame with vulnerability data
    
    Returns:
        DataFrame with added scoring columns
    """
    logger.info("Adding scoring categories to vulnerability data")
    
    # Create a copy to avoid modifying the original
    result_df = df.copy()
    
    # Add CVSS Category if CVSS score is available
    if "CVSS v3.0 Base Score" in result_df.columns:
        result_df["CVSS Category"] = result_df["CVSS v3.0 Base Score"].apply(categorize_cvss_score)
    
    # Add EPSS Category if EPSS score is available
    if "EPSS Score" in result_df.columns:
        result_df["EPSS Category"] = result_df["EPSS Score"].apply(categorize_epss_score)
    
    # Add VPR Category if VPR score is available
    if "VPR Score" in result_df.columns:
        result_df["VPR Category"] = result_df["VPR Score"].apply(categorize_vpr_score)
    
    # Calculate exploitability score
    required_cols = ["EPSS Category", "VPR Category", "KEV Listed"]
    if all(col in result_df.columns for col in required_cols):
        result_df["Exploitability Score"] = result_df.apply(calculate_exploitability_score, axis=1)
    
    logger.info("Scoring categorization complete")
    return result_df