"""Base sheet generator that other sheet generators can inherit from."""

from openpyxl.utils import get_column_letter
from openpyxl.styles import Font

from va_tool.utils import style_header_cell, set_column_widths, get_logger

logger = get_logger()


class BaseSheetGenerator:
    """Base class for Excel sheet generators."""
    
    def __init__(self, title=None):
        """
        Initialize the sheet generator.
        
        Args:
            title: Title for the sheet
        """
        self.title = title
        self.logger = get_logger()
    
    def generate(self, wb, df=None, **kwargs):
        """
        Generate the Excel sheet.
        
        Args:
            wb: Excel workbook
            df: DataFrame with data (optional)
            **kwargs: Additional arguments
        
        Returns:
            The worksheet
        """
        self.logger.info(f"Generating sheet: {self.title or 'Untitled'}")
        
        # Create the sheet
        ws = wb.create_sheet(title=self.title)
        
        # Set up the sheet
        self.setup_sheet(ws, **kwargs)
        
        # Generate content if DataFrame is provided
        if df is not None:
            self.generate_content(ws, df, **kwargs)
        
        return ws
    
    def setup_sheet(self, ws, **kwargs):
        """
        Set up the worksheet with basic formatting.
        
        Args:
            ws: The worksheet
            **kwargs: Additional arguments
        """
        # Set column widths (default: 20 columns, width 15)
        set_column_widths(ws, kwargs.get('num_columns', 20), kwargs.get('column_width', 15))
    
    def generate_content(self, ws, df, **kwargs):
        """
        Generate content for the worksheet.
        
        Args:
            ws: The worksheet
            df: DataFrame with data
            **kwargs: Additional arguments
        """
        # This method should be implemented by subclasses
        pass
    
    def add_title(self, ws, title, cell="A1", font_size=14, bold=True, merge_range=None):
        """
        Add a title to the worksheet.
        
        Args:
            ws: The worksheet
            title: Title text
            cell: Cell reference for the title
            font_size: Font size
            bold: Whether the title should be bold
            merge_range: Range to merge (e.g., "A1:H1")
        """
        ws[cell] = title
        ws[cell].font = Font(size=font_size, bold=bold)
        
        if merge_range:
            ws.merge_cells(merge_range)
    
    def add_section_title(self, ws, title, cell="A3", bold=True):
        """
        Add a section title to the worksheet.
        
        Args:
            ws: The worksheet
            title: Title text
            cell: Cell reference for the title
            bold: Whether the title should be bold
        """
        ws[cell] = title
        ws[cell].font = Font(bold=bold)
    
    def write_headers(self, ws, headers, row=3, start_col=1):
        """
        Write headers to the worksheet.
        
        Args:
            ws: The worksheet
            headers: List of header texts
            row: Row number
            start_col: Starting column number
        """
        for col_idx, header in enumerate(headers, start_col):
            cell = ws.cell(row=row, column=col_idx, value=header)
            style_header_cell(cell)
    
    def write_data_rows(self, ws, data, row_start=4, col_start=1):
        """
        Write data rows to the worksheet.
        
        Args:
            ws: The worksheet
            data: List of lists or DataFrame
            row_start: Starting row number
            col_start: Starting column number
        """
        # If data is a DataFrame, convert it to a list of lists
        if hasattr(data, 'values'):
            data = data.values.tolist()
        
        for row_idx, row_data in enumerate(data, row_start):
            for col_idx, value in enumerate(row_data, col_start):
                ws.cell(row=row_idx, column=col_idx, value=value)