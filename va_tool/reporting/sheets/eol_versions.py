"""EOL Versions sheet generator - basic implementation."""

import pandas as pd
import re
from openpyxl.chart import BarChart, PieChart, Reference
from openpyxl.chart.label import DataLabelList

from va_tool.reporting.sheets.base import BaseSheetGenerator
from va_tool.utils import get_logger


class EOLVersionsSheetGenerator(BaseSheetGenerator):
    """Generator for the EOL Versions sheet."""
    
    def __init__(self):
        """Initialize the generator."""
        super().__init__(title="2.3 EOL Versions")
        self.logger = get_logger()
    
    def generate(self, wb, df=None, output_dir=None, results_data=None, **kwargs):
        """Generate the EOL Versions sheet."""
        self.logger.info("Generating EOL Versions sheet")
        ws = super().generate(wb)
        
        # Add title
        self.add_title(
            ws, "Total Different Versions Identified as EOL", 
            font_size=14, merge_range='A1:F1'
        )
        
        # Process data from dataframe if available
        if df is not None:
            # Filter for EOL components
            eol_df = self.filter_eol_components(df)
            
            if not eol_df.empty:
                # Extract versions from EOL components
                versions_data = self.extract_versions(eol_df)
                
                # Write versions summary
                self.write_versions_summary(ws, versions_data)
                
                # Write detailed versions list
                self.write_versions_details(ws, versions_data)
                
                # Create Excel charts if we have version data
                if versions_data['versions_data'] is not None and not versions_data['versions_data'].empty:
                    self.create_version_charts(ws, versions_data)
            else:
                ws['A3'] = "No EOL components found in the vulnerability data."
        else:
            ws['A3'] = "No vulnerability data available."
        
        return ws
    
    def filter_eol_components(self, df):
        """Filter dataframe for EOL components."""
        eol_pattern = r'(?i)(EOL|SEoL|End\s+of\s+Life|Unsupported|Out\s+of\s+Date)'
        eol_df = df[df['Name'].str.contains(eol_pattern, regex=True, na=False)]
        return eol_df
    
    def extract_versions(self, eol_df):
        """Extract version information from EOL components."""
        version_details = []
        
        for _, row in eol_df.iterrows():
            name = str(row['Name']) if pd.notna(row.get('Name')) else ""
            plugin_output = str(row.get('Plugin Output', "")) if pd.notna(row.get('Plugin Output')) else ""
            host = str(row.get('Host', ''))
            
            # Extract version info from Plugin Output (SEOL format) 
            software_type, version = self.extract_from_plugin_output(plugin_output)
            
            # If not found, try name
            if not version:
                software_type, version = self.extract_from_name(name)
            
            # If version found, add to results
            if version:
                version_details.append({
                    'Software': software_type,
                    'Version': version,
                    'Host': host,
                    'Source': 'Plugin Output' if plugin_output else 'Name',
                    'Original Name': name
                })
        
        # Process results
        version_df = pd.DataFrame(version_details) if version_details else pd.DataFrame()
        
        if not version_df.empty:
            # Group by Software and Version, count hosts
            grouped = version_df.groupby(['Software', 'Version']).agg({
                'Host': 'nunique',
                'Original Name': 'first',
                'Source': 'first'
            }).reset_index()
            
            # Rename Host to Host Count
            grouped = grouped.rename(columns={'Host': 'Host Count'})
            
            # Sort by host count descending
            grouped = grouped.sort_values('Host Count', ascending=False)
            
            # Return statistics
            return {
                'unique_software_count': len(grouped['Software'].unique()),
                'total_versions_count': len(grouped),
                'versions_data': grouped
            }
        else:
            return {
                'unique_software_count': 0,
                'total_versions_count': 0,
                'versions_data': pd.DataFrame()
            }
    
    def extract_from_plugin_output(self, plugin_output):
        """Extract version info from plugin output (SEOL format)."""
        # Default return values
        software_type = ""
        version = ""
        
        # If empty, return defaults
        if not plugin_output or plugin_output == "nan":
            return software_type, version
        
        # Split into lines
        lines = plugin_output.split('\n')
        
        # Look for SEOL format: "Path" and "Installed version"
        path_line = None
        version_line = None
        
        for line in lines:
            line = line.strip()
            if re.search(r'^\s*Path\s*:', line, re.IGNORECASE):
                path_line = line
            elif re.search(r'^\s*Installed\s+version\s*:', line, re.IGNORECASE):
                version_line = line
        
        # If found both path and version lines, extract info
        if path_line and version_line:
            # Extract version
            version_match = re.search(r'Installed\s+version\s*:\s*(\S+)', version_line, re.IGNORECASE)
            if version_match:
                version = version_match.group(1).strip()
                
                # Extract software type from path
                path_match = re.search(r'Path\s*:\s*(.+)', path_line, re.IGNORECASE)
                if path_match:
                    path = path_match.group(1).strip()
                    
                    # Determine software type from path
                    if 'Microsoft.AspNetCore.App' in path:
                        software_type = 'ASP.NET Core'
                    elif 'Microsoft.NETCore.App' in path:
                        software_type = '.NET Core'
                    elif 'Microsoft.WindowsDesktop.App' in path:
                        software_type = '.NET Desktop'
                    elif 'dotnet' in path:
                        software_type = '.NET'
        
        return software_type, version
    
    def extract_from_name(self, name):
        """Extract version info from component name."""
        # Default return values
        software_type = ""
        version = ""
        
        # If empty, return defaults
        if not name:
            return software_type, version
        
        # Identify software type
        if 'Windows' in name:
            software_type = 'Windows'
        elif 'Java' in name:
            software_type = 'Java'
        elif 'Apache' in name:
            software_type = 'Apache'
        elif '.NET' in name:
            software_type = '.NET'
        else:
            # Use first word as fallback
            words = name.split()
            if words:
                software_type = words[0]
        
        # Extract version number
        version_match = re.search(r'(\d+\.\d+\.\d+(\.\d+)?)', name)
        if version_match:
            version = version_match.group(1)
        
        return software_type, version
    
    def write_versions_summary(self, ws, versions_data):
        """Write versions summary statistics to worksheet."""
        # Add summary section
        ws['A3'] = "EOL Versions Summary"
        ws['A3'].font = ws['A3'].font.copy(bold=True)
        
        # Write statistics
        ws['A4'] = "Total Different Software Types with EOL Versions:"
        ws['B4'] = versions_data['unique_software_count']
        
        ws['A5'] = "Total Different EOL Versions Identified:"
        ws['B5'] = versions_data['total_versions_count']
        
        # Set column widths
        ws.column_dimensions['A'].width = 40
        ws.column_dimensions['B'].width = 15
    
    def write_versions_details(self, ws, versions_data):
        """Write detailed versions list to worksheet."""
        versions_df = versions_data['versions_data']
        
        if not versions_df.empty:
            # Add section title
            start_row = 8
            self.add_section_title(ws, "EOL Versions Details", cell=f"A{start_row}")
            
            # Write headers
            headers = ['Software Type', 'Version', 'Host Count', 'Source', 'Sample Name']
            self.write_headers(ws, headers, row=start_row+1)
            
            # Write data
            for row_idx, (_, row) in enumerate(versions_df.iterrows(), start_row+2):
                ws.cell(row=row_idx, column=1, value=row['Software'])
                ws.cell(row=row_idx, column=2, value=row['Version'])
                ws.cell(row=row_idx, column=3, value=row['Host Count'])
                ws.cell(row=row_idx, column=4, value=row['Source'])
                ws.cell(row=row_idx, column=5, value=row['Original Name'])
            
            # Set column widths
            ws.column_dimensions['A'].width = 25  # Software Type
            ws.column_dimensions['B'].width = 15  # Version
            ws.column_dimensions['C'].width = 15  # Host Count
            ws.column_dimensions['D'].width = 20  # Source
            ws.column_dimensions['E'].width = 60  # Sample Name
        else:
            ws['A8'] = "No version information extracted from EOL components."
    
    def create_version_charts(self, ws, versions_data):
        """Create Excel charts for version data."""
        versions_df = versions_data['versions_data']
        
        if not versions_df.empty:
            # Create bar chart for software distribution
            self.create_software_chart(ws, versions_df)
    
    def create_software_chart(self, ws, versions_df):
        """Create bar chart showing software distribution."""
        # Count versions per software type
        software_counts = versions_df.groupby('Software').size().reset_index(name='Count')
        software_counts = software_counts.sort_values('Count', ascending=False).head(10)
        
        # Write data for chart
        chart_data_row = 30
        ws.cell(row=chart_data_row, column=7, value="Software")
        ws.cell(row=chart_data_row, column=8, value="Count")
        
        for i, (_, row) in enumerate(software_counts.iterrows(), chart_data_row+1):
            ws.cell(row=i, column=7, value=row['Software'])
            ws.cell(row=i, column=8, value=row['Count'])
        
        # Create chart
        chart = BarChart()
        chart.title = "EOL Versions by Software Type"
        chart.y_axis.title = "Count"
        
        # Set data ranges
        data = Reference(ws, min_col=8, max_col=8, min_row=chart_data_row, max_row=chart_data_row+len(software_counts))
        cats = Reference(ws, min_col=7, max_col=7, min_row=chart_data_row+1, max_row=chart_data_row+len(software_counts))
        
        # Add data to chart
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(cats)
        
        # Add data labels
        chart.dataLabels = DataLabelList()
        chart.dataLabels.showVal = True
        
        # Add chart to worksheet
        ws.add_chart(chart, "C3")