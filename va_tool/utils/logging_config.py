"""Logging configuration for the vulnerability analysis tool."""

import logging
import os
import sys
from datetime import datetime


def setup_logging(log_level=logging.INFO, log_file=None):
    """
    Configure logging for the application.
    
    Args:
        log_level: The logging level (default: INFO)
        log_file: Optional file path for logging
    
    Returns:
        Logger instance
    """
    # Create logger
    logger = logging.getLogger("va_tool")
    logger.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler if log_file is specified
    if log_file:
        # Ensure directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger():
    """Get the application logger."""
    return logging.getLogger("va_tool")