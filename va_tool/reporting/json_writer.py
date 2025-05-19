"""JSON writer functionality for report generation."""

import os
import json
import datetime

from va_tool.utils import get_logger, format_datetime, ensure_dir_exists

logger = get_logger()


def write_json_report(results_data, output_dir, filename="results"):
    """
    Write analysis results to a JSON file.
    
    Args:
        results_data: Dictionary with analysis results
        output_dir: Directory to save the JSON file
        filename: Base filename
    
    Returns:
        Path to the saved JSON file
    """
    logger.info("Creating JSON report")
    
    # Create timestamp
    timestamp = format_datetime(datetime.datetime.now())
    
    # Create directory if it doesn't exist
    ensure_dir_exists(output_dir)
    
    # Create file path
    output_path = os.path.join(output_dir, f"{filename}_{timestamp}.json")
    
    try:
        with open(output_path, "w") as f:
            json.dump(results_data, f, indent=2)
        
        logger.info(f"JSON report saved to {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Error saving JSON report: {str(e)}")
        return None