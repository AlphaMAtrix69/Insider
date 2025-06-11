"""
Script to generate a test DataFrame for sheet-tester.py using main.py's pipeline, but much faster.
Loads an Excel and KEV file, processes them, and saves the output for quick manual revision sheet testing.
"""

import os
import sys
import argparse
import pandas as pd
import json
from va_tool.data.loaders import load_vulnerability_file, load_kev_file
from va_tool.processing.core import process_vulnerability_data
from va_tool.utils import setup_logging, get_logger

def main(excel_path, kev_path=None, output_dir=None, log_level="INFO", log_file=None):
    logger = get_logger()
    setup_logging(log_level=log_level, log_file=log_file)
    logger.info("Starting test DataFrame generation for sheet-tester.")
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), 'output/sheet_tester/test_data')
    os.makedirs(output_dir, exist_ok=True)
    logger.info(f"Output directory set to: {output_dir}")

    # Load the Excel file (and KEV if provided)
    logger.info(f"Loading Excel: {excel_path}")
    vuln_df = load_vulnerability_file(excel_path)
    if vuln_df is None:
        logger.error("Could not load vulnerability Excel file.")
        sys.exit(1)

    kev_set = set()
    if kev_path:
        logger.info(f"Loading KEV: {kev_path}")
        kev_set = load_kev_file(kev_path)
    logger.info(f"Loaded {len(vuln_df)} rows from Excel.")

    logger.info("Processing data (using cache for CVEs if available)...")
    original_df, processed_df, check_needed_df, analyzed_df, results_data = process_vulnerability_data(
        vuln_df, kev_set, output_dir, clear_cache_flag=False
    )
    logger.info(f"Processed data: {len(processed_df)} rows.")

    logger.info("Saving DataFrames and results for sheet-tester...")
    original_df.to_pickle(os.path.join(output_dir, 'original_data.pkl'))
    processed_df.to_pickle(os.path.join(output_dir, 'processed_data.pkl'))
    with open(os.path.join(output_dir, 'results_data.json'), 'w') as f:
        json.dump(results_data, f, indent=2)
    with pd.ExcelWriter(os.path.join(output_dir, 'test_data.xlsx')) as writer:
        original_df.to_excel(writer, sheet_name="Original Data")
        processed_df.to_excel(writer, sheet_name="Processed Data")
    logger.info(f"Data saved to {output_dir}")
    logger.info("You can now use these files in sheet-tester.py for fast manual revision sheet generation.")

def parse_args():
    parser = argparse.ArgumentParser(description="Generate test DataFrame for sheet-tester using main.py pipeline.")
    parser.add_argument('--excel', required=True, help='Path to the input Excel file')
    parser.add_argument('--kev', required=False, help='Path to the KEV file (optional)')
    parser.add_argument('--output', required=False, help='Output directory (optional)')
    parser.add_argument('--log-level', required=False, default="INFO", help='Logging level (default: INFO)')
    parser.add_argument('--log-file', required=False, help='Path to log file (optional)')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    main(args.excel, args.kev, args.output, args.log_level, args.log_file)
