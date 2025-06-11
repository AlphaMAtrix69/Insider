"""Helper functions for vulnerability analysis."""

import pandas as pd
import json


def clean_for_json(df):
    """Clean DataFrame for JSON conversion by handling non-serializable values."""
    return df.replace({pd.NA: None, float('nan'): None, 
                       float('inf'): None, float('-inf'): None}).to_dict(orient="records")


def format_datetime(dt_obj, format_str="%Y%m%d_%H%M%S"):
    """Format datetime object to string using specified format."""
    return dt_obj.strftime(format_str)


def ensure_dir_exists(directory):
    """Create directory if it doesn't exist."""
    import os
    os.makedirs(directory, exist_ok=True)
    return directory