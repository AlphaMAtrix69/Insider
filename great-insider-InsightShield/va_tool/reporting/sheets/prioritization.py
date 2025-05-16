"""Prioritization Insights sheet generator."""

from va_tool.reporting.sheets.base import BaseSheetGenerator
from va_tool.utils import style_header_cell


class PrioritizationInsightsGenerator(BaseSheetGenerator):
    """Generator for the Prioritization Insights sheet."""
    
    def __init__(self):
        """Initialize the generator."""
        super().__init__(title="1. Prioritization Insights")
    
    def generate(self, wb, results_data, original_df=None, processed_df=None, **kwargs):
        """
        Generate the Prioritization Insights sheet.
        
        Args:
            wb: Excel workbook
            results_data: Dictionary with analysis results
            original_df: Original vulnerability DataFrame
            processed_df: Processed vulnerability DataFrame
            **kwargs: Additional arguments
        
        Returns:
            The worksheet
        """
        self.logger.info("Generating Prioritization Insights sheet")
        ws = super().generate(wb)
        
        # Add Raw Data section
        self.add_section_title(ws, "Nessus Raw Data count", cell="A1")
        self.add_raw_data_section(ws, original_df)
        
        # Add Revision Count section
        self.add_section_title(ws, "Revision Count", cell="H1")
        self.add_revision_count_section(ws, processed_df)
        
        # Add EPSS Risk Summary section
        self.add_section_title(ws, "EPSS Risk Summary", cell="H6")
        self.add_epss_summary(ws, processed_df)
        
        # Add VPR Risk Summary section
        self.add_section_title(ws, "VPR Risk Summary", cell="H10")
        self.add_vpr_summary(ws, processed_df)
        
        # Add KEV Risk Summary section
        self.add_section_title(ws, "KEV Risk Summary", cell="H14")
        self.add_kev_summary(ws, processed_df)
        
        # Add Metric table
        self.add_metric_table(ws, processed_df)
        
        # Add legend section
        self.add_legend_section(ws)
        
        return ws
    
    def add_raw_data_section(self, ws, original_df):
        """Add raw data count section."""
        # Add headers
        headers = ["", "Critical", "High", "Medium", "Low", "None"]
        for i, header in enumerate(headers, 1):
            cell = ws.cell(row=2, column=i, value=header)
            style_header_cell(cell)
        
        # Add rows for counts
        ws['A3'] = "[Count...]"
        ws['A4'] = "Total (Without None)"
        
        # Add raw count values if available
        if original_df is not None:
            raw_counts = original_df["Risk"].value_counts()
            for i, risk in enumerate(["Critical", "High", "Medium", "Low", "None"], 2):
                ws.cell(row=3, column=i, value=raw_counts.get(risk, 0))
            
            # Calculate total without None
            total_without_none = sum(raw_counts.get(risk, 0) for risk in ["Critical", "High", "Medium", "Low"])
            ws.cell(row=4, column=2, value=total_without_none)
    
    def add_revision_count_section(self, ws, processed_df):
        """Add revision count section."""
        # Add headers
        revision_headers = ["", "Critical", "High", "Medium", "Low", "Informational", "N/A"]
        for i, header in enumerate(revision_headers, 8):
            cell = ws.cell(row=2, column=i, value=header)
            style_header_cell(cell)
        
        # Add rows for counts
        ws['H3'] = "Risk Rating:"
        ws['H4'] = "Total Without NA+Info"
        
        # Add revision count values if available
        if processed_df is not None:
            revision_counts = processed_df["Risk"].value_counts()
            for i, risk in enumerate(["Critical", "High", "Medium", "Low", "Informational", "N/A"], 9):
                ws.cell(row=3, column=i, value=revision_counts.get(risk, 0))
            
            # Calculate total without Informational and N/A
            total_without_na = sum(revision_counts.get(risk, 0) for risk in ["Critical", "High", "Medium", "Low"])
            ws.cell(row=4, column=9, value=total_without_na)
    
    def add_epss_summary(self, ws, processed_df):
        """Add EPSS risk summary section."""
        ws['H7'] = "EPSS Score Available"
        
        if processed_df is not None and 'EPSS Category' in processed_df.columns:
            epss_counts = processed_df['EPSS Category'].value_counts()
            total_epss = sum(epss_counts.get(risk, 0) for risk in ["Critical", "High", "Medium", "Low"])
            ws['H8'] = f"Total EPSS Score Available ({total_epss})"
            
            # Add EPSS counts by category
            for i, risk in enumerate(["Critical", "High", "Medium", "Low"], 9):
                ws.cell(row=7, column=i, value=epss_counts.get(risk, 0))
        else:
            ws['H8'] = "Total EPSS Score Available (0)"
    
    def add_vpr_summary(self, ws, processed_df):
        """Add VPR risk summary section."""
        ws['H11'] = "VPR Score Available"
        
        if processed_df is not None and 'VPR Category' in processed_df.columns:
            vpr_counts = processed_df['VPR Category'].value_counts()
            total_vpr = sum(vpr_counts.get(risk, 0) for risk in ["Critical", "High", "Medium", "Low"])
            ws['H12'] = f"Total VPR Score Available ({total_vpr})"
            
            # Add VPR counts by category
            for i, risk in enumerate(["Critical", "High", "Medium", "Low"], 9):
                ws.cell(row=11, column=i, value=vpr_counts.get(risk, 0))
        else:
            ws['H12'] = "Total VPR Score Available (0)"
    
    def add_kev_summary(self, ws, processed_df):
        """Add KEV risk summary section."""
        ws['H15'] = "KEV Score Available"
        
        if processed_df is not None and 'KEV Listed' in processed_df.columns:
            kev_counts = processed_df['KEV Listed'].value_counts()
            ws.cell(row=15, column=9, value=kev_counts.get('Yes', 0))
            ws.cell(row=15, column=10, value=kev_counts.get('No', 0))
    
    def add_metric_table(self, ws, processed_df):
        """Add metric table."""
        # Add headers
        ws['H19'] = "Metric"
        style_header_cell(ws['H19'])
        
        ws['I19'] = "Critical Count"
        style_header_cell(ws['I19'])
        
        ws['J19'] = "High Count"
        style_header_cell(ws['J19'])
        
        ws['K19'] = "Medium Count"
        style_header_cell(ws['K19'])
        
        ws['L19'] = "Low Count"
        style_header_cell(ws['L19'])
        
        # Add metric rows
        metrics = ["CVSS", "EPSS", "VPR", "CISA KEV"]
        for i, metric in enumerate(metrics, 20):
            ws.cell(row=i, column=8, value=metric)
        
        # Fill in metric counts if processed_df is available
        if processed_df is not None:
            for i, metric in enumerate(['CVSS Category', 'EPSS Category', 'VPR Category', 'KEV Listed'], 0):
                row_idx = 20 + i
                
                if metric == 'KEV Listed':
                    # For KEV, we need Yes/No counts
                    kev_counts = processed_df[metric].value_counts()
                    ws.cell(row=row_idx, column=9, value=kev_counts.get('Yes', 0))
                    ws.cell(row=row_idx, column=10, value=0)  # Assuming 0 for other categories
                    ws.cell(row=row_idx, column=11, value=0)
                    ws.cell(row=row_idx, column=12, value=0)
                else:
                    # For scoring metrics, count by category
                    counts = processed_df[metric].value_counts()
                    ws.cell(row=row_idx, column=9, value=counts.get('Critical', 0))
                    ws.cell(row=row_idx, column=10, value=counts.get('High', 0))
                    ws.cell(row=row_idx, column=11, value=counts.get('Medium', 0))
                    ws.cell(row=row_idx, column=12, value=counts.get('Low', 0))
    
    def add_legend_section(self, ws):
        """Add legend section."""
        # Add headers
        ws['P1'] = "Rating"
        ws['P1'].font = ws['P1'].font.copy(bold=True)
        
        ws['Q1'] = "CVSS Score"
        ws['Q1'].font = ws['Q1'].font.copy(bold=True)
        
        ws['R1'] = "Priority Score"
        ws['R1'].font = ws['R1'].font.copy(bold=True)
        
        # Add CVSS rating data
        ratings = [
            ["None", "0", "0"],
            ["Low", "0.1 - 3.9", "1"],
            ["Medium", "4.0 - 6.9", "2"],
            ["High", "7.0 - 8.9", "3"],
            ["Critical", "9.0 - 10.0", "4"]
        ]
        
        for i, (rating, score, priority) in enumerate(ratings, 2):
            ws.cell(row=i, column=16, value=rating)
            ws.cell(row=i, column=17, value=score)
            ws.cell(row=i, column=18, value=int(priority))
        
        # Add EPSS Score legend
        ws['P8'] = "Rating and EPSS Score"
        ws['P8'].font = ws['P8'].font.copy(bold=True)
        
        epss_ratings = [
            ["None", "<0.01", "0"],
            ["Low", "0.01-0.39", "1"],
            ["Medium", "0.4-0.69", "2"],
            ["High", "0.7-0.89", "3"],
            ["Critical", "0.9-1", "4"]
        ]
        
        for i, (rating, score, priority) in enumerate(epss_ratings, 9):
            ws.cell(row=i, column=16, value=rating)
            ws.cell(row=i, column=17, value=score)
            ws.cell(row=i, column=18, value=int(priority))
        
        # Add KEV legend
        ws['P15'] = "KEV"
        ws['P15'].font = ws['P15'].font.copy(bold=True)
        
        kev_ratings = [
            ["Yes", "", "4"],
            ["No", "", "0"]
        ]
        
        for i, (rating, _, priority) in enumerate(kev_ratings, 16):
            ws.cell(row=i, column=16, value=rating)
            ws.cell(row=i, column=18, value=int(priority))
        
        # Add common priority formula
        ws['P20'] = "Common Priority Formula"
        ws['P20'].font = ws['P20'].font.copy(bold=True)
        
        ws['Q20'] = "Epss+VPR+KEV"
        
        ws['P21'] = "Highest"
        ws['Q21'] = "12"
        
        ws['P22'] = "Lowest"
        ws['Q22'] = "1"