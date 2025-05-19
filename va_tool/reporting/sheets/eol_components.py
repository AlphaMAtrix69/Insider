"""EOL Components sheet generator with enhanced Excel visualizations."""

import pandas as pd
import os
import re
from datetime import datetime, timedelta
from openpyxl.chart import BarChart, Reference, PieChart, LineChart
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.series import Series
from openpyxl.chart.marker import Marker
from openpyxl.styles import PatternFill, Font, Alignment
from openpyxl.drawing.fill import PatternFillProperties, ColorChoice
from openpyxl.drawing.colors import ColorMapping

from va_tool.reporting.sheets.base import BaseSheetGenerator
from va_tool.utils import ensure_dir_exists


class EOLComponentsSheetGenerator(BaseSheetGenerator):
    """Generator for the EOL Components sheet."""
    
    def __init__(self):
        """Initialize the generator."""
        super().__init__(title="2.1 EOL Components")
    
    def generate(self, wb, df=None, output_dir=None, results_data=None, **kwargs):
        """
        Generate the EOL Components sheet.
        
        Args:
            wb: Excel workbook
            df: DataFrame with vulnerability data
            output_dir: Directory to save chart images
            results_data: Dictionary with analysis results
            **kwargs: Additional arguments
        
        Returns:
            The worksheet
        """
        self.logger.info("Generating EOL Components sheet")
        ws = super().generate(wb)
        
        # Add title
        self.add_title(
            ws, "Total Components in EOL", 
            font_size=14, merge_range='A1:F1'
        )
        
        if results_data and 'eol_duration_summary' in results_data:
            eol_data = results_data['eol_duration_summary']
            
            # Extract data from the results
            total_eol_components = eol_data.get('total_eol_components', 0)
            duration_summary = eol_data.get('duration_summary', [])
            eol_details = eol_data.get('eol_details', [])
            
            if total_eol_components > 0:
                # Write total EOL components
                ws['A3'] = "Total EOL Components:"
                ws['B3'] = total_eol_components
                ws['A3'].font = ws['A3'].font.copy(bold=True)
                
                # Highlight the total with a fill color
                ws['B3'].fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
                ws['B3'].font = Font(bold=True, size=12, color="9C0006")
                
                # Write duration summary table
                self.write_duration_summary(ws, duration_summary)
                
                # Get unique EOL components
                unique_eol_details = self.get_unique_components(eol_details)
                
                # Write detailed EOL components list
                self.write_eol_details(ws, unique_eol_details)
                
                # Create Excel charts for the duration summary
                self.create_enhanced_visualizations(ws, duration_summary, eol_details)
            else:
                ws['A3'] = "No EOL components found in the vulnerability data."
        elif df is not None:
            # If results_data not available, process the dataframe directly
            # Filter for EOL components
            eol_df = self.filter_eol_components(df)
            
            if not eol_df.empty:
                # Calculate EOL duration
                eol_with_duration = self.calculate_eol_duration(eol_df)
                
                # Summarize by duration buckets
                duration_summary = self.summarize_by_duration(eol_with_duration)
                
                # Write total EOL components
                ws['A3'] = "Total EOL Components:"
                ws['B3'] = len(eol_df)
                ws['A3'].font = ws['A3'].font.copy(bold=True)
                
                # Highlight the total with a fill color
                ws['B3'].fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
                ws['B3'].font = Font(bold=True, size=12, color="9C0006")
                
                # Write duration summary table
                self.write_duration_summary(ws, duration_summary.to_dict('records'))
                
                # Get unique components data
                unique_eol_df = self.get_unique_components_df(eol_with_duration)
                
                # Write detailed EOL components list
                self.write_eol_details_from_df(ws, unique_eol_df)
                
                # Create Excel charts for the duration summary
                self.create_enhanced_visualizations_from_df(ws, duration_summary, eol_with_duration)
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
    
    def calculate_eol_duration(self, eol_df):
        """Calculate how long components have been EOL."""
        # Create a copy to avoid modifying the original
        result_df = eol_df.copy()
        
        # Current date for calculation
        current_date = datetime.now().date()
        
        # If CVE Published Date is available, use it to calculate duration
        if 'CVE Published Date' in result_df.columns:
            result_df['EOL Duration Days'] = result_df['CVE Published Date'].apply(
                lambda x: (current_date - datetime.fromisoformat(x).date()).days 
                if pd.notna(x) and x else None
            )
        else:
            # Otherwise, use Days After Discovery if available
            if 'Days After Discovery' in result_df.columns:
                result_df['EOL Duration Days'] = result_df['Days After Discovery']
            else:
                result_df['EOL Duration Days'] = None
        
        return result_df
    
    def get_unique_components(self, eol_details):
        """Get unique EOL components from the details list."""
        if not eol_details:
            return []
            
        # Create a temporary DataFrame for easier processing
        temp_df = pd.DataFrame(eol_details)
        
        # Create a unique component identifier using Plugin ID and Name
        if 'Plugin ID' in temp_df.columns and 'Name' in temp_df.columns:
            temp_df['Component ID'] = temp_df['Plugin ID'].astype(str) + '-' + temp_df['Name'].astype(str)
            
            # Get unique components by Component ID
            unique_components = temp_df.drop_duplicates(subset=['Component ID'])
            
            # Count hosts for each component
            host_counts = temp_df.groupby('Component ID')['Host'].nunique().reset_index()
            host_counts.columns = ['Component ID', 'Host Count']
            
            # Merge host counts back to unique components
            unique_components = pd.merge(unique_components, host_counts, on='Component ID', how='left')
            
            # Sort by duration (if available) or risk level
            if 'EOL Duration Days' in unique_components.columns:
                unique_components = unique_components.sort_values(
                    by=['EOL Duration Days', 'Risk'], 
                    ascending=[False, True],
                    na_position='last'
                )
            elif 'Risk' in unique_components.columns:
                # Create a risk level ordering
                risk_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
                unique_components['Risk Order'] = unique_components['Risk'].map(
                    lambda x: risk_order.get(x, 4) if pd.notna(x) else 4
                )
                unique_components = unique_components.sort_values('Risk Order')
                
            # Convert back to list of dictionaries
            unique_list = unique_components.to_dict('records')
            
            # Clean up by removing temporary fields
            for item in unique_list:
                if 'Component ID' in item:
                    del item['Component ID']
                if 'Risk Order' in item:
                    del item['Risk Order']
            
            return unique_list
        else:
            # If we can't create a unique identifier, just return as is
            return eol_details
    
    def get_unique_components_df(self, df):
        """Get unique EOL components from DataFrame."""
        if df.empty:
            return df
            
        # Create a copy to avoid modifying the original
        result_df = df.copy()
        
        # Create a unique component identifier using Plugin ID and Name
        result_df['Component ID'] = result_df['Plugin ID'].astype(str) + '-' + result_df['Name'].astype(str)
        
        # Get unique components by Component ID
        unique_components = result_df.drop_duplicates(subset=['Component ID'])
        
        # Count hosts for each component
        host_counts = result_df.groupby('Component ID')['Host'].nunique().reset_index()
        host_counts.columns = ['Component ID', 'Host Count']
        
        # Merge host counts back to unique components
        unique_components = pd.merge(unique_components, host_counts, on='Component ID', how='left')
        
        # Sort by duration (if available) or risk level
        if 'EOL Duration Days' in unique_components.columns:
            unique_components = unique_components.sort_values(
                by=['EOL Duration Days', 'Risk'], 
                ascending=[False, True],
                na_position='last'
            )
        elif 'Risk' in unique_components.columns:
            # Create a risk level ordering
            risk_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
            unique_components['Risk Order'] = unique_components['Risk'].map(
                lambda x: risk_order.get(x, 4) if pd.notna(x) else 4
            )
            unique_components = unique_components.sort_values('Risk Order')
        
        # Drop temporary columns
        if 'Component ID' in unique_components.columns:
            unique_components = unique_components.drop('Component ID', axis=1)
        if 'Risk Order' in unique_components.columns:
            unique_components = unique_components.drop('Risk Order', axis=1)
            
        return unique_components
    
    def summarize_by_duration(self, eol_df):
        """Summarize EOL components by duration buckets."""
        # Create duration buckets
        def categorize_duration(days):
            if pd.isna(days):
                return "Unknown"
            elif days <= 30:
                return "< 30 days"
            elif days <= 90:
                return "30-90 days"
            elif days <= 180:
                return "90-180 days"
            elif days <= 365:
                return "180-365 days"
            else:
                return "> 365 days"
        
        eol_df['Duration Category'] = eol_df['EOL Duration Days'].apply(categorize_duration)
        
        # Count components by duration category
        duration_summary = eol_df['Duration Category'].value_counts().reset_index()
        duration_summary.columns = ['Duration', 'Component Count']
        
        # Set priority order for categories
        duration_order = ["< 30 days", "30-90 days", "90-180 days", "180-365 days", "> 365 days", "Unknown"]
        duration_summary['Order'] = duration_summary['Duration'].apply(lambda x: duration_order.index(x))
        duration_summary = duration_summary.sort_values('Order').drop('Order', axis=1)
        
        return duration_summary
    
    def write_duration_summary(self, ws, duration_summary):
        """Write duration summary table to worksheet."""
        # Write headers with styling
        ws['A5'] = "EOL Duration"
        ws['B5'] = "Component Count"
        
        # Apply header styling
        for cell in [ws['A5'], ws['B5']]:
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="5B9BD5", end_color="5B9BD5", fill_type="solid")
            cell.alignment = Alignment(horizontal="center", vertical="center")
        
        # Write data with alternate row coloring
        row_idx = 6
        total_count = 0
        
        for i, item in enumerate(duration_summary):
            # Alternate row colors
            fill_color = "E9F1FB" if i % 2 == 0 else "FFFFFF"
            
            # Write values
            ws.cell(row=row_idx, column=1, value=item.get('Duration', ''))
            count = item.get('Component Count', 0)
            ws.cell(row=row_idx, column=2, value=count)
            
            # Apply cell styling
            for col in [1, 2]:
                cell = ws.cell(row=row_idx, column=col)
                cell.fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
                if col == 2:  # Right-align count values
                    cell.alignment = Alignment(horizontal="right")
            
            total_count += count
            row_idx += 1
        
        # Calculate total with special styling
        total_row = row_idx
        ws.cell(row=total_row, column=1, value="Total")
        ws.cell(row=total_row, column=2, value=total_count)
        
        # Style the total row
        for col in [1, 2]:
            cell = ws.cell(row=total_row, column=col)
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="D9E1F2", end_color="D9E1F2", fill_type="solid")
            if col == 2:  # Right-align count values
                cell.alignment = Alignment(horizontal="right")
    
    def write_eol_details(self, ws, eol_details):
        """Write detailed EOL components list to worksheet."""
        # Add section title
        start_row = 15
        self.add_section_title(ws, "Unique EOL Components", cell=f"A{start_row}")
        
        # Write headers with styling
        headers = ['Plugin ID', 'Name', 'Host Count', 'EOL Duration (Days)', 'Risk', 'CVE']
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=start_row+1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="5B9BD5", end_color="5B9BD5", fill_type="solid")
            cell.alignment = Alignment(horizontal="center", vertical="center")
        
        # Write data with conditional formatting for risk level
        for i, item in enumerate(eol_details, 0):
            row_idx = start_row + 2 + i
            
            # Alternate row colors
            fill_color = "E9F1FB" if i % 2 == 0 else "FFFFFF"
            
            # Write and style each cell
            ws.cell(row=row_idx, column=1, value=item.get('Plugin ID', '')).fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
            ws.cell(row=row_idx, column=2, value=item.get('Name', '')).fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
            ws.cell(row=row_idx, column=3, value=item.get('Host Count', 1)).fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
            ws.cell(row=row_idx, column=4, value=item.get('EOL Duration Days', '')).fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
            
            # Apply risk-based formatting
            risk_cell = ws.cell(row=row_idx, column=5, value=item.get('Risk', ''))
            risk_cell.fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
            
            risk = item.get('Risk', '')
            if risk == 'Critical':
                risk_cell.font = Font(color="FF0000", bold=True)  # Red
            elif risk == 'High':
                risk_cell.font = Font(color="FF8000")  # Orange
            elif risk == 'Medium':
                risk_cell.font = Font(color="FFBF00")  # Amber
            
            ws.cell(row=row_idx, column=6, value=item.get('CVE', '')).fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
        
        # Set column widths
        ws.column_dimensions['A'].width = 15  # Plugin ID
        ws.column_dimensions['B'].width = 50  # Name
        ws.column_dimensions['C'].width = 15  # Host Count
        ws.column_dimensions['D'].width = 20  # EOL Duration
        ws.column_dimensions['E'].width = 15  # Risk
        ws.column_dimensions['F'].width = 20  # CVE
    
    def write_eol_details_from_df(self, ws, eol_df):
        """Write detailed EOL components list from DataFrame to worksheet."""
        # Add section title
        start_row = 15
        self.add_section_title(ws, "Unique EOL Components", cell=f"A{start_row}")
        
        # Write headers with styling
        headers = ['Plugin ID', 'Name', 'Host Count', 'EOL Duration (Days)', 'Risk', 'CVE']
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=start_row+1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="5B9BD5", end_color="5B9BD5", fill_type="solid")
            cell.alignment = Alignment(horizontal="center", vertical="center")
        
        # Sort by duration descending
        if 'EOL Duration Days' in eol_df.columns:
            eol_df = eol_df.sort_values('EOL Duration Days', ascending=False, na_position='last')
        
        # Write data with conditional formatting for risk level
        for i, (_, row) in enumerate(eol_df.iterrows(), 0):
            row_idx = start_row + 2 + i
            
            # Alternate row colors
            fill_color = "E9F1FB" if i % 2 == 0 else "FFFFFF"
            
            # Write and style each cell
            ws.cell(row=row_idx, column=1, value=str(row.get('Plugin ID', ''))).fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
            ws.cell(row=row_idx, column=2, value=str(row.get('Name', ''))).fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
            ws.cell(row=row_idx, column=3, value=row.get('Host Count', 1)).fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
            ws.cell(row=row_idx, column=4, value=row.get('EOL Duration Days', '')).fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
            
            # Apply risk-based formatting
            risk_cell = ws.cell(row=row_idx, column=5, value=str(row.get('Risk', '')))
            risk_cell.fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
            
            risk = row.get('Risk', '')
            if risk == 'Critical':
                risk_cell.font = Font(color="FF0000", bold=True)  # Red
            elif risk == 'High':
                risk_cell.font = Font(color="FF8000")  # Orange
            elif risk == 'Medium':
                risk_cell.font = Font(color="FFBF00")  # Amber
            
            ws.cell(row=row_idx, column=6, value=str(row.get('CVE', ''))).fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")
        
        # Set column widths
        ws.column_dimensions['A'].width = 15  # Plugin ID
        ws.column_dimensions['B'].width = 50  # Name
        ws.column_dimensions['C'].width = 15  # Host Count
        ws.column_dimensions['D'].width = 20  # EOL Duration
        ws.column_dimensions['E'].width = 15  # Risk
        ws.column_dimensions['F'].width = 20  # CVE
    
    def create_enhanced_visualizations(self, ws, duration_summary, eol_details):
        """Create multiple Excel charts for enhanced visualization."""
        # Create bar chart for duration summary
        self.create_duration_bar_chart(ws, duration_summary)
        
        # Create pie chart for duration distribution
        self.create_duration_pie_chart(ws, duration_summary)
        
        # Create risk distribution chart if risk data is available
        if eol_details and 'Risk' in eol_details[0]:
            self.create_risk_distribution_chart(ws, eol_details)
    
    def create_enhanced_visualizations_from_df(self, ws, duration_summary, eol_df):
        """Create multiple Excel charts for enhanced visualization from DataFrames."""
        # Create bar chart for duration summary
        self.create_duration_bar_chart_from_df(ws, duration_summary)
        
        # Create pie chart for duration distribution
        self.create_duration_pie_chart_from_df(ws, duration_summary)
        
        # Create risk distribution chart if risk data is available
        if 'Risk' in eol_df.columns:
            self.create_risk_distribution_chart_from_df(ws, eol_df)
    
    def create_duration_bar_chart(self, ws, duration_summary):
        """Create an enhanced bar chart for duration summary."""
        # Write chart title
        ws['D4'] = "EOL Components by Duration"
        ws['D4'].font = Font(bold=True, size=12)
        
        # Create bar chart
        chart = BarChart()
        chart.type = "col"
        chart.style = 42  # Use a more colorful Excel chart style
        chart.title = None  # We already added a title in the worksheet
        chart.y_axis.title = "Number of Components"
        chart.x_axis.title = "Duration Since EOL"
        
        # Calculate data range
        data_row_count = len(duration_summary) + 1  # +1 for header
        
        # Create references to the data
        data = Reference(ws, min_col=2, max_col=2, min_row=5, max_row=5+data_row_count-1)
        cats = Reference(ws, min_col=1, max_col=1, min_row=6, max_row=5+data_row_count-1)
        
        # Add data and categories
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(cats)
        
        # Enable data labels
        chart.dataLabels = DataLabelList()
        chart.dataLabels.showVal = True
        chart.dataLabels.showCatName = False
        
        # Set series colors - use a color gradient for duration categories
        s = chart.series[0]
        s.graphicalProperties.solidFill = "5B9BD5"  # Blue fill
        
        # Set chart size and position
        chart.width = 15
        chart.height = 10
        
        # Add chart to worksheet
        ws.add_chart(chart, "D5")
    
    def create_duration_bar_chart_from_df(self, ws, duration_df):
        """Create an enhanced bar chart for duration summary from DataFrame."""
        # Write chart title
        ws['D4'] = "EOL Components by Duration"
        ws['D4'].font = Font(bold=True, size=12)
        
        # Create bar chart
        chart = BarChart()
        chart.type = "col"
        chart.style = 42  # Use a more colorful Excel chart style
        chart.title = None  # We already added a title in the worksheet
        chart.y_axis.title = "Number of Components"
        chart.x_axis.title = "Duration Since EOL"
        
        # Calculate data range based on DataFrame size
        data_row_count = len(duration_df) + 1  # +1 for header
        
        # Create references to the data
        data = Reference(ws, min_col=2, max_col=2, min_row=5, max_row=5+data_row_count-1)
        cats = Reference(ws, min_col=1, max_col=1, min_row=6, max_row=5+data_row_count-1)
        
        # Add data and categories
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(cats)
        
        # Enable data labels
        chart.dataLabels = DataLabelList()
        chart.dataLabels.showVal = True
        chart.dataLabels.showCatName = False
        
        # Set series colors - use a color gradient for duration categories
        s = chart.series[0]
        s.graphicalProperties.solidFill = "5B9BD5"  # Blue fill
        
        # Set chart size and position
        chart.width = 15
        chart.height = 10
        
        # Add chart to worksheet
        ws.add_chart(chart, "D5")
    
    def create_duration_pie_chart(self, ws, duration_summary):
        """Create a pie chart showing distribution of components by duration."""
        # Prepare data for the chart - write to a different area of the sheet
        chart_data_row = 30
        
        # Write headers for source data
        ws.cell(row=chart_data_row, column=8, value="Duration")
        ws.cell(row=chart_data_row, column=9, value="Count")
        
        # Write source data for the chart
        for i, item in enumerate(duration_summary, 1):
            ws.cell(row=chart_data_row+i, column=8, value=item.get('Duration', ''))
            ws.cell(row=chart_data_row+i, column=9, value=item.get('Component Count', 0))
        
        # Create pie chart
        pie = PieChart()
        pie.title = "EOL Components Distribution"
        pie.style = 10
        
        # Define data range for the chart
        labels = Reference(ws, min_col=8, min_row=chart_data_row+1, max_row=chart_data_row+len(duration_summary))
        data = Reference(ws, min_col=9, min_row=chart_data_row, max_row=chart_data_row+len(duration_summary))
        
        # Add data to the chart
        pie.add_data(data, titles_from_data=True)
        pie.set_categories(labels)
        
        # Add data labels showing percentages
        pie.dataLabels = DataLabelList()
        pie.dataLabels.showPercent = True
        
        # Set chart size and position
        pie.width = 10
        pie.height = 10
        
        # Add chart to worksheet
        ws.add_chart(pie, "I5")
    
    def create_duration_pie_chart_from_df(self, ws, duration_df):
        """Create a pie chart showing distribution of components by duration from DataFrame."""
        # Prepare data for the chart - write to a different area of the sheet
        chart_data_row = 30
        
        # Write headers for source data
        ws.cell(row=chart_data_row, column=8, value="Duration")
        ws.cell(row=chart_data_row, column=9, value="Count")
        
        # Write source data for the chart
        for i, (_, row) in enumerate(duration_df.iterrows(), 1):
            ws.cell(row=chart_data_row+i, column=8, value=row['Duration'])
            ws.cell(row=chart_data_row+i, column=9, value=row['Component Count'])
        
        # Create pie chart
        pie = PieChart()
        pie.title = "EOL Components Distribution"
        pie.style = 10
        
        # Define data range for the chart
        labels = Reference(ws, min_col=8, min_row=chart_data_row+1, max_row=chart_data_row+len(duration_df))
        data = Reference(ws, min_col=9, min_row=chart_data_row, max_row=chart_data_row+len(duration_df))
        
        # Add data to the chart
        pie.add_data(data, titles_from_data=True)
        pie.set_categories(labels)
        
        # Add data labels showing percentages
        pie.dataLabels = DataLabelList()
        pie.dataLabels.showPercent = True
        
        # Set chart size and position
        pie.width = 10
        pie.height = 10
        
        # Add chart to worksheet
        ws.add_chart(pie, "I5")
    
    def create_risk_distribution_chart(self, ws, eol_details):
        """Create a chart showing risk distribution of EOL components."""
        # Prepare data - count by risk level
        risk_counts = {}
        for item in eol_details:
            risk = item.get('Risk', 'Unknown')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        # Write data to worksheet
        chart_data_row = 45
        ws.cell(row=chart_data_row, column=8, value="Risk Level")
        ws.cell(row=chart_data_row, column=9, value="Count")
        
        row_idx = chart_data_row + 1
        for risk, count in risk_counts.items():
            ws.cell(row=row_idx, column=8, value=risk)
            ws.cell(row=row_idx, column=9, value=count)
            row_idx += 1
        
        # Create bar chart
        chart = BarChart()
        chart.type = "col"
        chart.style = 42
        chart.title = "EOL Components by Risk Level"
        chart.y_axis.title = "Number of Components"
        
        # Define data range for the chart
        data = Reference(ws, min_col=9, min_row=chart_data_row, max_row=chart_data_row+len(risk_counts))
        cats = Reference(ws, min_col=8, min_row=chart_data_row+1, max_row=chart_data_row+len(risk_counts))
        
        # Add data to the chart
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(cats)
        
        # Add data labels
        chart.dataLabels = DataLabelList()
        chart.dataLabels.showVal = True
        
        # Set risk-specific colors for the bars
        for i, (risk, _) in enumerate(risk_counts.items()):
            if risk == "Critical":
                chart.series[0].graphicalProperties.solidFill = "FF0000"  # Red
            elif risk == "High":
                chart.series[0].graphicalProperties.solidFill = "FF8000"  # Orange
            elif risk == "Medium":
                chart.series[0].graphicalProperties.solidFill = "FFBF00"  # Amber
            elif risk == "Low":
                chart.series[0].graphicalProperties.solidFill = "00FF00"  # Green
        
        # Set chart size and position
        chart.width = 10
        chart.height = 10
        
        # Add chart to worksheet
        ws.add_chart(chart, "D17")
    
    def create_risk_distribution_chart_from_df(self, ws, eol_df):
        """Create a chart showing risk distribution of EOL components from DataFrame."""
        # Prepare data - count by risk level
        risk_counts = eol_df['Risk'].value_counts().reset_index()
        risk_counts.columns = ['Risk', 'Count']
        
        # Write data to worksheet
        chart_data_row = 45
        ws.cell(row=chart_data_row, column=8, value="Risk Level")
        ws.cell(row=chart_data_row, column=9, value="Count")
        
        for i, (_, row) in enumerate(risk_counts.iterrows(), 1):
            ws.cell(row=chart_data_row+i, column=8, value=row['Risk'])
            ws.cell(row=chart_data_row+i, column=9, value=row['Count'])
        
        # Create bar chart
        chart = BarChart()
        chart.type = "col"
        chart.style = 42
        chart.title = "EOL Components by Risk Level"
        chart.y_axis.title = "Number of Components"
        
        # Define data range for the chart
        data = Reference(ws, min_col=9, min_row=chart_data_row, max_row=chart_data_row+len(risk_counts))
        cats = Reference(ws, min_col=8, min_row=chart_data_row+1, max_row=chart_data_row+len(risk_counts))
        
        # Add data to the chart
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(cats)
        
        # Add data labels
        chart.dataLabels = DataLabelList()
        chart.dataLabels.showVal = True
        
        # Set chart size and position
        chart.width = 10
        chart.height = 10
        
        # Add chart to worksheet
        ws.add_chart(chart, "D17")