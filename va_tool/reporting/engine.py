"""Report engine that coordinates all report generation."""

import os
import datetime
from openpyxl import Workbook

from va_tool.utils import get_logger, format_datetime, ensure_dir_exists
from va_tool.reporting.excel_writer import save_excel_workbook, write_full_excel_report
from va_tool.reporting.json_writer import write_json_report
from va_tool.reporting.sheets import (
    SummarySheetGenerator,
    PrioritizationInsightsGenerator,
    ExploitabilitySheetGenerator,
    AgeingSheetGenerator,
    MostExploitableSheetGenerator,
    RiskSummarySheetGenerator,
    Top10CVEsSheetGenerator,
    VulnDensitySheetGenerator,
    RiskTrajectorySheetGenerator,
    # Add new EOL sheet generators
    EOLComponentsSheetGenerator,
    EOLIPsSheetGenerator,
    EOLVersionsSheetGenerator
)

logger = get_logger()


class ReportEngine:
    """Coordinates the generation of reports and sheets."""
    
    def __init__(self, output_dir):
        """
        Initialize the report engine.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = output_dir
        ensure_dir_exists(output_dir)
        
        # Initialize sheet generators
        self.sheet_generators = {
            'summary': SummarySheetGenerator(),
            'prioritization': PrioritizationInsightsGenerator(),
            'exploitability': ExploitabilitySheetGenerator(),
            'ageing': AgeingSheetGenerator(),
            'most_exploitable': MostExploitableSheetGenerator(),
            'risk_summary': RiskSummarySheetGenerator(),
            'top10_cves': Top10CVEsSheetGenerator(),
            'vuln_density': VulnDensitySheetGenerator(),
            'risk_trajectory': RiskTrajectorySheetGenerator(),
            # Add new EOL sheet generators
            'eol_components': EOLComponentsSheetGenerator(),
            'eol_ips': EOLIPsSheetGenerator(),
            'eol_versions': EOLVersionsSheetGenerator()
        }
    
    def create_standard_report(self, original_df, processed_df, check_needed_df, analyzed_df, results_data):
        """
        Create a standard Excel report with multiple sheets.
        
        Args:
            original_df: Original vulnerability DataFrame
            processed_df: Processed vulnerability DataFrame
            check_needed_df: Vulnerabilities that need checking
            analyzed_df: Analyzed vulnerability DataFrame
            results_data: Dictionary with analysis results
        
        Returns:
            Path to the saved Excel file
        """
        logger.info("Creating standard Excel report")
        return write_full_excel_report(
            original_df, processed_df, check_needed_df, analyzed_df, 
            results_data, self.output_dir, "Vulnerability_Analysis"
        )
    
    def create_json_report(self, results_data):
        """
        Create a JSON report with analysis results.
        
        Args:
            results_data: Dictionary with analysis results
        
        Returns:
            Path to the saved JSON file
        """
        logger.info("Creating JSON report")
        return write_json_report(results_data, self.output_dir)
    
    def create_enhanced_report(self, original_df, processed_df, analyzed_df, results_data):
        """
        Create an enhanced Excel report with visualizations.
        
        Args:
            original_df: Original vulnerability DataFrame
            processed_df: Processed vulnerability DataFrame
            analyzed_df: Analyzed vulnerability DataFrame
            results_data: Dictionary with analysis results
        
        Returns:
            Path to the saved Excel file
        """
        logger.info("Creating enhanced Excel report")
        
        # Create new workbook
        wb = Workbook()
        
        # Remove default sheet
        default_sheet = wb.active
        wb.remove(default_sheet)
        
        # Generate sheets in specific order
        self.sheet_generators['summary'].generate(
            wb, results_data, original_df, processed_df
        )
        
        self.sheet_generators['prioritization'].generate(
            wb, results_data, original_df, processed_df
        )
        
        self.sheet_generators['exploitability'].generate(
            wb, processed_df
        )
        
        self.sheet_generators['ageing'].generate(
            wb, processed_df
        )
        
        self.sheet_generators['most_exploitable'].generate(
            wb, processed_df
        )
        
        # Add EOL analysis sheets
        self.sheet_generators['eol_components'].generate(
            wb, processed_df, self.output_dir, results_data
        )
        
        self.sheet_generators['eol_ips'].generate(
            wb, processed_df, self.output_dir, results_data
        )
        
        self.sheet_generators['eol_versions'].generate(
            wb, processed_df, self.output_dir, results_data
        )
        
        self.sheet_generators['risk_summary'].generate(
            wb, processed_df, self.output_dir
        )
        
        self.sheet_generators['top10_cves'].generate(
            wb, processed_df, self.output_dir
        )
        
        self.sheet_generators['vuln_density'].generate(
            wb, processed_df, self.output_dir
        )
        
        self.sheet_generators['risk_trajectory'].generate(
            wb, processed_df, self.output_dir
        )
        
        # Save workbook
        timestamp = format_datetime(datetime.datetime.now())
        output_path = os.path.join(
            self.output_dir, f"Enhanced_Vulnerability_Analysis_{timestamp}.xlsx"
        )
        
        try:
            wb.save(output_path)
            logger.info(f"Enhanced report saved to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error saving enhanced report: {str(e)}")
            return None
    
    def generate_all_reports(self, original_df, processed_df, check_needed_df, analyzed_df, results_data):
        """
        Generate all report types.
        
        Args:
            original_df: Original vulnerability DataFrame
            processed_df: Processed vulnerability DataFrame
            check_needed_df: Vulnerabilities that need checking
            analyzed_df: Analyzed vulnerability DataFrame
            results_data: Dictionary with analysis results
        
        Returns:
            Tuple of (standard_report_path, json_report_path, enhanced_report_path)
        """
        logger.info("Generating all reports")
        
        # Generate standard Excel report
        standard_report = self.create_standard_report(
            original_df, processed_df, check_needed_df, analyzed_df, results_data
        )
        
        # Generate JSON report
        json_report = self.create_json_report(results_data)
        
        # Generate enhanced Excel report
        enhanced_report = self.create_enhanced_report(
            original_df, processed_df, analyzed_df, results_data
        )
        
        return standard_report, json_report, enhanced_report