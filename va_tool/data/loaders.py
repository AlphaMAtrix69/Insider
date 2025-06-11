"""Data loading functionality for vulnerability analysis."""

import pandas as pd
import os
from va_tool.utils import get_logger

logger = get_logger()


def load_vulnerability_file(file_path):
    """
    Load vulnerability data from Excel file.
    
    Args:
        file_path: Path to the Excel file with vulnerability data
    
    Returns:
        pandas DataFrame with vulnerability data or None if error
    """
    try:
        logger.info(f"Loading vulnerability data from {file_path}")
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None
            
        # Load Excel file
        df = pd.read_excel(file_path, engine="openpyxl")
        logger.info(f"Loaded {len(df)} vulnerability records")
        
        # Basic validation
        required_columns = ["Plugin ID", "CVE", "Host", "Name", "Risk"]
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            logger.warning(f"Missing required columns: {', '.join(missing_columns)}")
        
        return df
    except Exception as e:
        logger.error(f"Error loading vulnerability file: {str(e)}")
        return None


def load_kev_file(file_path):
    """
    Load KEV (Known Exploited Vulnerabilities) data from CSV file.
    
    Args:
        file_path: Path to the KEV CSV file
    
    Returns:
        Set of CVE IDs from the KEV list or empty set if error
    """
    try:
        logger.info(f"Loading KEV data from {file_path}")
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return set()
            
        # Load CSV file
        df = pd.read_csv(file_path)
        logger.info(f"Loaded {len(df)} KEV records")
        
        # Extract CVE IDs
        if "cveID" in df.columns:
            kev_set = set(df["cveID"].dropna().astype(str))
            logger.info(f"Extracted {len(kev_set)} unique CVE IDs from KEV list")
            return kev_set
        else:
            logger.warning("KEV file does not contain 'cveID' column")
            return set()
    except Exception as e:
        logger.error(f"Error loading KEV file: {str(e)}")
        return set()