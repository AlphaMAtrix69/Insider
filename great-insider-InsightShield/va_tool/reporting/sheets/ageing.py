"""Ageing of Vulnerabilities sheet generator."""

from va_tool.reporting.sheets.base import BaseSheetGenerator


class AgeingSheetGenerator(BaseSheetGenerator):
    """Generator for the Ageing of Vulnerabilities sheet."""
    
    def __init__(self):
        """Initialize the generator."""
        super().__init__(title="1.2 Ageing of Vulnerability")
    
    def generate(self, wb, df=None, **kwargs):
        """
        Generate the Ageing of Vulnerabilities sheet.
        
        Args:
            wb: Excel workbook
            df: DataFrame with vulnerability data
            **kwargs: Additional arguments
        
        Returns:
            The worksheet
        """
        self.logger.info("Generating Ageing of Vulnerabilities sheet")
        ws = super().generate(wb)
        
        # Add title
        self.add_title(
            ws, "Ageing of Vulnerabilities", 
            font_size=14, merge_range='A1:H1'
        )
        
        # Add note about Tenable API integration
        ws['A3'] = "Note: Plugin Initial Release Date and Plugin Updated Date will be populated from Tenable API once integrated."
        ws['A3'].font = ws['A3'].font.copy(italic=True)
        ws.merge_cells('A3:H3')
        
        # Check if we have the data
        if df is not None:
            # Define the columns to display
            columns = [
                "Plugin ID", "CVE", "Host", "Name", "Risk", 
                "CVE Published Date", "Days After Discovery"
            ]
            
            # Add placeholders for Tenable API data
            extended_columns = columns + ["Plugin Initial Release Date", "Plugin Updated Date"]
            
            # Add headers
            self.write_headers(ws, extended_columns, row=5)
            
            # Check if required columns exist
            if all(col in df.columns for col in columns):
                # Create a copy with only the relevant columns
                subset_df = df[columns].copy()
                
                # Write data
                for row_idx, (_, row) in enumerate(subset_df.iterrows(), 6):
                    for col_idx, col in enumerate(columns, 1):
                        value = row.get(col, '')
                        ws.cell(row=row_idx, column=col_idx, value=value)
                    
                    # Add empty cells for Tenable API data (to be filled later)
                    ws.cell(row=row_idx, column=len(columns) + 1, value="N/A")
                    ws.cell(row=row_idx, column=len(columns) + 2, value="N/A")
            else:
                ws['A6'] = "Required columns not found in data."
        else:
            ws['A5'] = "No vulnerability data available."
        
        return ws