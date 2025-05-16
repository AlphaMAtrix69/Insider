"""Categorization functionality for vulnerability analysis."""

import pandas as pd

from va_tool.data import BUCKET_MAPPINGS, NAME_MAPPINGS
from va_tool.utils import get_logger

logger = get_logger()


def assign_severity(name, existing_risk=None):
    """
    Assign severity level based on vulnerability name and existing risk.
    
    Args:
        name: Vulnerability name
        existing_risk: Existing risk level if available
    
    Returns:
        String with assigned severity level
    """
    # Use existing risk if valid
    if existing_risk and existing_risk not in ["None", None] and not pd.isna(existing_risk):
        return existing_risk
    
    # Handle missing name
    if pd.isna(name):
        return "Informational"
    
    # Check against patterns in NAME_MAPPINGS
    name_lower = name.lower()
    
    for severity, name_patterns in NAME_MAPPINGS.items():
        for pattern in name_patterns:
            if pattern.lower() in name_lower:
                return severity
    
    # Default if no match found
    return "Check Needed"


def categorize_name(name):
    """
    Categorize vulnerability by name into defined buckets.
    
    Args:
        name: Vulnerability name
    
    Returns:
        String with comma-separated bucket names
    """
    if pd.isna(name):
        return ""
    
    name_lower = name.lower()
    assigned_buckets = set()
    
    # Check against patterns in BUCKET_MAPPINGS
    for bucket, keywords in BUCKET_MAPPINGS.items():
        for keyword in keywords:
            if keyword.lower() in name_lower:
                assigned_buckets.add(bucket)
                break
    
    return ", ".join(assigned_buckets) if assigned_buckets else "Miscellaneous"


def categorize_vulnerabilities(df):
    """
    Categorize all vulnerabilities in the dataframe.
    
    Args:
        df: DataFrame with vulnerability data
    
    Returns:
        DataFrame with added categorization columns
    """
    logger.info("Categorizing vulnerabilities")
    
    # Create a copy to avoid modifying the original
    result_df = df.copy()
    
    # Assign severity based on name and existing risk
    result_df["Risk"] = result_df.apply(
        lambda row: assign_severity(row["Name"], row.get("Risk")), 
        axis=1
    )
    
    # Add bucket categorization
    result_df["Bucket"] = result_df["Name"].apply(categorize_name)
    
    logger.info("Vulnerability categorization complete")
    return result_df