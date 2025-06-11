"""
Agile sheet tester for Excel sheet generators.
Allows rapid development and visual inspection of all sheet outputs with realistic data.
"""

import os
import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
from openpyxl import Workbook
from va_tool.reporting.sheets.summary import SummarySheetGenerator
from va_tool.reporting.sheets.prioritization import PrioritizationInsightsGenerator
from va_tool.reporting.sheets.exploitability import ExploitabilitySheetGenerator
from va_tool.reporting.sheets.ageing import AgeingSheetGenerator
from va_tool.reporting.sheets.most_exploitable import MostExploitableSheetGenerator
from va_tool.reporting.sheets.ip_insights import IPInsightsSheetGenerator
from va_tool.reporting.sheets.vulnerability_clustering import VulnClusteringSheetGenerator
from va_tool.reporting.sheets.unique_vuln import UniqueVulnSheetGenerator
from va_tool.reporting.sheets.bucket_details import BucketDetailsSheetGenerator

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'output/sheet_tester/')
TEST_DATA_DIR = os.path.join(OUTPUT_DIR, 'test_data')
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(TEST_DATA_DIR, exist_ok=True)

def generate_test_data(num_records=50):
    """Generate comprehensive test data for visual validation of all charts and tables."""
    # Asset name generation
    return "No Plseholder"

def load_real_test_data():
    """Load real data that was previously generated from generate_test_df.py instead of dummy data. Only use 1/4th of the data for faster testing."""
    try:
        print("Loading real test data from files...")
        original_df = pd.read_pickle(os.path.join(TEST_DATA_DIR, 'original_data.pkl'))
        processed_df = pd.read_pickle(os.path.join(TEST_DATA_DIR, 'processed_data.pkl'))
        import json
        with open(os.path.join(TEST_DATA_DIR, 'results_data.json'), 'r') as f:
            results_data = json.load(f)
        print(f"Loaded real data: {len(original_df)} original rows, {len(processed_df)} processed rows")
        # Use only 1/4th of the data for faster testing
        orig_n = len(original_df) // 4
        proc_n = len(processed_df) // 4
        original_df = original_df.iloc[:orig_n]
        processed_df = processed_df.iloc[:proc_n]
        print(f"Using subset: {len(original_df)} original rows, {len(processed_df)} processed rows")
        return original_df, processed_df, results_data
    except FileNotFoundError:
        print("Real test data files not found. Run generate_test_df.py first to generate them.")
        print("Falling back to dummy data generation...")
        return generate_test_data(80)

def test_all_sheets():
    """Test all sheet generators with comprehensive data."""
    print("Generating test data...")
    original_df, processed_df, results_data = load_real_test_data()
    
    # Create a new workbook
    wb = Workbook()
    wb.remove(wb.active)  # Remove default sheet

    # Each generator with appropriate data - in the new requested order
    sheets = [
        (SummarySheetGenerator(), {
            'results_data': results_data, 
            'original_df': original_df, 
            'processed_df': processed_df
        }),
        (PrioritizationInsightsGenerator(), {
            'df': processed_df,
            'results_data': results_data
        }),
        (ExploitabilitySheetGenerator(), {
            'df': processed_df
        }),
        (AgeingSheetGenerator(), {
            'df': processed_df
        }),
        (MostExploitableSheetGenerator(), {
            'df': processed_df
        }),
        (IPInsightsSheetGenerator(), {
            'df': processed_df, 
            'output_dir': OUTPUT_DIR
        }),
        (VulnClusteringSheetGenerator(), {
            'df': processed_df, 
            'output_dir': OUTPUT_DIR
        }),
        (UniqueVulnSheetGenerator(), {
            'df': processed_df
        }),
        (BucketDetailsSheetGenerator(), {
            'df': processed_df
        }),
    ]

    # Save original and processed data for reference
    with pd.ExcelWriter(os.path.join(OUTPUT_DIR, 'test_data.xlsx')) as writer:
        original_df.to_excel(writer, sheet_name="Original Data")
        processed_df.to_excel(writer, sheet_name="Processed Data")

    # Generate all sheets
    for generator, kwargs in sheets:
        try:
            print(f"Generating sheet: {generator.__class__.__name__}")
            generator.generate(wb, **kwargs)
        except Exception as e:
            print(f"Error generating {generator.__class__.__name__}: {str(e)}")
            import traceback
            traceback.print_exc()

    base_name = 'sheet_tester_output'
    ext = '.xlsx'
    i = 1
    while True:
        out_path = os.path.join(OUTPUT_DIR, f'{base_name}_{i}{ext}')
        if not os.path.exists(out_path):
            break
        i += 1
    wb.save(out_path)
    print(f"All sheets generated and saved to {out_path}")

if __name__ == "__main__":
    test_all_sheets()
