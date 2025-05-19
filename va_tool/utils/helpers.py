"""Helper functions for vulnerability analysis."""

import pandas as pd
import json
import datetime


def clean_for_json(df):
    """
    Clean DataFrame or list for JSON conversion by handling non-serializable values.
    
    Args:
        df: DataFrame or list to clean
    
    Returns:
        Cleaned dictionary or list for JSON
    """
    if isinstance(df, pd.DataFrame):
        return df.replace({pd.NA: None, float('nan'): None, 
                           float('inf'): None, float('-inf'): None}).to_dict(orient="records")
    elif isinstance(df, list):
        # If it's already a list, just make sure each item can be serialized to JSON
        try:
            # This will catch any non-serializable objects
            json_str = json.dumps(df, default=str)
            return json.loads(json_str)
        except Exception as e:
            # If serialization fails, convert to string representation
            return [str(item) for item in df]
    else:
        # If it's neither a DataFrame nor a list, return an empty list
        return []


def format_datetime(dt_obj, format_str="%Y%m%d_%H%M%S"):
    """
    Format datetime object to string using specified format.
    
    Args:
        dt_obj: Datetime object to format
        format_str: Format string (default: %Y%m%d_%H%M%S)
        
    Returns:
        Formatted datetime string
    """
    return dt_obj.strftime(format_str)


def ensure_dir_exists(directory):
    """
    Create directory if it doesn't exist.
    
    Args:
        directory: Directory path to create
        
    Returns:
        Directory path
    """
    import os
    os.makedirs(directory, exist_ok=True)
    return directory