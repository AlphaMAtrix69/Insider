"""EOL IPs sheet generator using Excel native charts."""

import pandas as pd
import os
import re
from openpyxl.chart import BarChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.styles import Font, PatternFill, Color

from va_tool.reporting.sheets.base import BaseSheetGenerator
from va_tool.utils import ensure_dir_exists


class EOLIPsSheetGenerator(BaseSheetGenerator):
    """Generator for the EOL IPs sheet."""
    
    def __init__(self):
        """Initialize the generator."""
        super().__init__(title="6.2 EOL IPs")
    
    def generate(self, wb, df=None, output_dir=None, results_data=None, **kwargs):
        """
        Generate the EOL IPs sheet.
        
        Args:
            wb: Excel workbook
            df: DataFrame with vulnerability data
            output_dir: Directory to save chart images
            results_data: Dictionary with analysis results
            **kwargs: Additional arguments
        
        Returns:
            The worksheet
        """
        self.logger.info("Generating EOL IPs sheet")
        ws = super().generate(wb)
        
        # Add title
        self.add_title(
            ws, "Total IPs with EOL Components", 
            font_size=14, merge_range='A1:F1'
        )
        
        # Check if we can get data from results_data first
        if results_data and 'eol_duration_summary' in results_data:
            eol_data = results_data['eol_duration_summary']
            eol_details = eol_data.get('eol_details', [])
            
            if eol_details:
                # Convert to DataFrame for easier processing
                eol_df = pd.DataFrame(eol_details)
                
                # Analyze IPs with EOL components
                ip_summary, top_ips = self.analyze_eol_ips(eol_df)
                
                # Write IP statistics
                self.write_ip_stats(ws, ip_summary)
                
                # Write top IPs with most EOL components
                self.write_top_ips(ws, top_ips)
                
                # Create Excel chart
                if not top_ips.empty:
                    self.create_eol_ip_chart(ws, top_ips)
            else:
                ws['A3'] = "No EOL components found in the vulnerability data."
        elif df is not None:
            # If results_data not available, process the dataframe directly
            # Filter for EOL components
            eol_df = self.filter_eol_components(df)
            
            if not eol_df.empty:
                # Analyze IPs with EOL components
                ip_summary, top_ips = self.analyze_eol_ips(eol_df)
                
                # Write IP statistics
                self.write_ip_stats(ws, ip_summary)
                
                # Write top IPs with most EOL components
                self.write_top_ips(ws, top_ips)
                
                # Create Excel chart
                if not top_ips.empty:
                    self.create_eol_ip_chart(ws, top_ips)
            else:
                ws['A3'] = "No EOL components found in the vulnerability data."
        else:
            ws['A3'] = "No vulnerability data available."
        
        return ws
    
    def filter_eol_components(self, df):
        """Filter dataframe for EOL components."""
        # Filter components with "EOL", "SEoL", "End of Life", "Unsupported", or "Out of Date" in the name
        eol_pattern = r'(?i)(EOL|SEoL|End\s+of\s+Life|Unsupported|Out\s+of\s+Date)'
        eol_df = df[df['Name'].str.contains(eol_pattern, regex=True, na=False)]
        
        self.logger.info(f"Found {len(eol_df)} EOL components")
        return eol_df
    
    def analyze_eol_ips(self, eol_df):
        """Analyze IPs with EOL components."""
        # Count EOL components per IP
        ip_counts = eol_df['Host'].value_counts().reset_index()
        ip_counts.columns = ['IP', 'EOL Component Count']
        
        # Sort by count descending
        ip_counts = ip_counts.sort_values('EOL Component Count', ascending=False)
        
        # Prepare summary statistics
        total_ips = len(ip_counts)
        ip_summary = {
            'Total IPs with EOL Components': total_ips,
            'Average EOL Components per IP': round(ip_counts['EOL Component Count'].mean(), 2) if total_ips > 0 else 0,
            'Maximum EOL Components on Single IP': ip_counts['EOL Component Count'].max() if total_ips > 0 else 0,
            'IPs with 1 EOL Component': len(ip_counts[ip_counts['EOL Component Count'] == 1]),
            'IPs with 2-5 EOL Components': len(ip_counts[(ip_counts['EOL Component Count'] > 1) & 
                                                        (ip_counts['EOL Component Count'] <= 5)]),
            'IPs with >5 EOL Components': len(ip_counts[ip_counts['EOL Component Count'] > 5])
        }
        
        # Get top 15 IPs with most EOL components
        top_ips = ip_counts.head(15) if not ip_counts.empty else pd.DataFrame(columns=['IP', 'EOL Component Count'])
        
        return ip_summary, top_ips
    
    def write_ip_stats(self, ws, ip_summary):
        """Write IP statistics to worksheet."""
        # Write headers
        ws['A3'] = "EOL IP Statistics"
        ws['A3'].font = ws['A3'].font.copy(bold=True)
        
        # Write summary data
        row = 4
        for stat, value in ip_summary.items():
            ws.cell(row=row, column=1, value=stat)
            ws.cell(row=row, column=2, value=value)
            row += 1
        
        # Set column widths
        ws.column_dimensions['A'].width = 40
        ws.column_dimensions['B'].width = 15
    
    def write_top_ips(self, ws, top_ips):
        """Write top IPs with most EOL components to worksheet."""
        # Add section title
        start_row = 12
        self.add_section_title(ws, "Top IPs with Most EOL Components", cell=f"A{start_row}")
        
        # Write headers
        headers = ['IP Address', 'EOL Component Count', 'Risk Level']
        self.write_headers(ws, headers, row=start_row+1)
        
        # Write data
        for row_idx, (_, row) in enumerate(top_ips.iterrows(), start_row+2):
            ip_value = row['IP']
            count_value = row['EOL Component Count']
            
            ws.cell(row=row_idx, column=1, value=ip_value)
            ws.cell(row=row_idx, column=2, value=count_value)
            
            # Determine risk level based on count
            risk_level = "Low"
            if count_value > 10:
                risk_level = "Critical"
                cell_color = "FF0000"  # Red
            elif count_value > 5:
                risk_level = "High"
                cell_color = "FF8000"  # Orange
            elif count_value > 2:
                risk_level = "Medium"
                cell_color = "FFBF00"  # Amber/Yellow
            else:
                cell_color = "00FF00"  # Green
                
            # Set cell value and color
            cell = ws.cell(row=row_idx, column=3, value=risk_level)
            cell.font = cell.font.copy(color=cell_color)
        
        # Set column widths
        ws.column_dimensions['A'].width = 25  # IP Address
        ws.column_dimensions['B'].width = 20  # Component Count
        ws.column_dimensions['C'].width = 15  # Risk Level
    
    def create_eol_ip_chart(self, ws, top_ips):
        """Create Excel native chart for EOL components per IP."""
        # Create a horizontal bar chart
        chart = BarChart()
        chart.type = "bar"  # Horizontal bar chart
        chart.style = 10
        chart.title = "Top 10 IPs by EOL Component Count"
        chart.y_axis.title = "IP Address"
        chart.x_axis.title = "Number of EOL Components"
        
        # Limit to top 10 IPs for better visualization
        display_ips = top_ips.head(10)
        
        # Find the first empty row after our top IPs table
        start_row = 12 + 2  # Header + title
        data_rows = len(display_ips)
        
        # Data references for the chart
        data = Reference(ws, min_col=2, max_col=2, min_row=start_row, max_row=start_row+data_rows)
        cats = Reference(ws, min_col=1, max_col=1, min_row=start_row+1, max_row=start_row+data_rows)
        
        # Add data to chart
        chart.add_data(data, titles_from_data=False)
        chart.set_categories(cats)
        
        # Enable data labels
        chart.dataLabels = DataLabelList()
        chart.dataLabels.showVal = True
        
        # Adjust chart size
        chart.width = 15
        chart.height = 12
        
        # Add the chart to the worksheet
        ws.add_chart(chart, "D4")