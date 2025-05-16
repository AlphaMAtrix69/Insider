#!/usr/bin/env python3
"""
Enhanced Vulnerability Analysis Tool - Main Entry Point

This is the main entry point for the vulnerability analysis tool.
It handles command-line arguments and orchestrates the overall process.
"""

import argparse
import os
import sys
import time
import datetime

from va_tool import __version__
from va_tool.utils import setup_logging, get_logger, DEFAULT_OUTPUT_DIR
from va_tool.data import load_vulnerability_file, load_kev_file
from va_tool.processing import process_vulnerability_data
from va_tool.reporting import ReportEngine


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Enhanced Vulnerability Analysis Tool - Analyzes vulnerability scan and KEV data"
    )
    
    parser.add_argument(
        "--vuln-file", 
        required=True, 
        help="Path to vulnerability Excel file"
    )
    
    parser.add_argument(
        "--kev-file", 
        required=True, 
        help="Path to KEV CSV file"
    )
    
    parser.add_argument(
        "--output-dir", 
        default=DEFAULT_OUTPUT_DIR, 
        help=f"Directory to save output files (default: {DEFAULT_OUTPUT_DIR})"
    )
    
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear the CVE cache before processing"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level (default: INFO)"
    )
    
    parser.add_argument(
        "--log-file",
        help="Path to log file (default: none, logs to console only)"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"Enhanced Vulnerability Analysis Tool v{__version__}"
    )
    
    return parser.parse_args()


def print_banner():
    """Print a banner with version and start time."""
    print(f"------------------------------------------")
    print(f"Enhanced Vulnerability Analysis Tool v{__version__}")
    print(f"------------------------------------------")
    print(f"Starting analysis at {datetime.datetime.now()}")


def print_summary(results, excel_file, json_file, enhanced_excel):
    """Print a summary of the analysis results."""
    print("\nSummary of findings:")
    print("-------------------")
    
    # Print risk summary if available
    risk_counts = results.get("risk_counts", [])
    if risk_counts:
        print("\nRisk Summary:")
        for item in risk_counts:
            print(f"  {item['Risk Level']}: {item['Count']} vulnerabilities")
    
    # Print critical vulnerabilities count
    critical_vulns = len(results.get("common_critical", []))
    print(f"\nCommon Critical Vulnerabilities: {critical_vulns}")
    
    # Print output file paths
    print("\nOutput files:")
    print(f"- Standard report: {excel_file}")
    print(f"- Enhanced workbook: {enhanced_excel}")
    print(f"- JSON results: {json_file}")


def main():
    """Main function for the vulnerability analysis tool."""
    start_time = time.time()
    
    # Parse command-line arguments
    args = parse_arguments()
    
    # Setup logging
    import logging
    log_level = getattr(logging, args.log_level)
    setup_logging(log_level=log_level, log_file=args.log_file)
    logger = get_logger()
    
    # Print banner
    print_banner()
    
    # Validate input files
    vuln_file = args.vuln_file
    kev_file = args.kev_file
    output_dir = args.output_dir
    clear_cache = args.clear_cache
    
    if not os.path.exists(vuln_file):
        logger.error(f"Vulnerability file not found: {vuln_file}")
        return 1
    
    if not os.path.exists(kev_file):
        logger.error(f"KEV file not found: {kev_file}")
        return 1
    
    logger.info(f"Analyzing vulnerability data from {vuln_file}")
    logger.info(f"Using KEV data from {kev_file}")
    logger.info(f"Results will be saved to {output_dir}")
    
    # Load input data
    vuln_df = load_vulnerability_file(vuln_file)
    if vuln_df is None:
        logger.error("Failed to load vulnerability data")
        return 1
    
    kev_set = load_kev_file(kev_file)
    if not kev_set:
        logger.warning("No KEV data loaded or empty KEV set")
    
    # Process vulnerability data
    try:
        original_df, processed_df, check_needed_df, analyzed_df, results_data = process_vulnerability_data(
            vuln_df, kev_set, output_dir, clear_cache
        )
        
        # Generate reports
        report_engine = ReportEngine(output_dir)
        excel_file, json_file, enhanced_excel = report_engine.generate_all_reports(
            original_df, processed_df, check_needed_df, analyzed_df, results_data
        )
        
        # Print summary
        if excel_file and json_file and enhanced_excel:
            print_summary(results_data, excel_file, json_file, enhanced_excel)
            
            # Display elapsed time
            elapsed_time = time.time() - start_time
            print(f"\nAnalysis completed in {elapsed_time:.2f} seconds")
            
            return 0
        else:
            logger.error("Failed to generate reports")
            return 1
    
    except Exception as e:
        logger.exception(f"Error during processing: {str(e)}")
        print("Analysis failed. Check the log for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())