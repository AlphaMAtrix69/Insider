# Enhanced Vulnerability Analysis Tool

A modular command-line tool for analyzing vulnerability scan data, enriching it with additional information from the National Vulnerability Database (NVD), and generating comprehensive reports.

## Features

- Loads vulnerability data from Excel files exported from security scanning tools
- Enriches vulnerability data with CVE information from the NVD API
- Categorizes vulnerabilities by type, severity, and exploitability
- Calculates risk scores based on multiple factors (CVSS, EPSS, VPR, KEV)
- Identifies critical vulnerabilities requiring immediate attention
- Generates standard and enhanced Excel reports with visualizations
- Exports analysis results in JSON format for integration with other systems
- Provides comprehensive insights for vulnerability prioritization

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/vulnerability-analysis-tool.git
   cd vulnerability-analysis-tool
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Basic usage:

```bash
python main.py --vuln-file /path/to/vulnerability_data.xlsx --kev-file /path/to/kev_data.csv
```

Options:

```
  --vuln-file VULN_FILE     Path to vulnerability Excel file
  --kev-file KEV_FILE       Path to KEV CSV file
  --output-dir OUTPUT_DIR   Directory to save output files (default: ./output)
  --clear-cache             Clear the CVE cache before processing
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                            Set the logging level (default: INFO)
  --log-file LOG_FILE       Path to log file (default: none, logs to console only)
  --version                 Show program's version number and exit
```

## Input Files

### Vulnerability Data File

The tool accepts vulnerability data in Excel format (.xlsx) with the following required columns:

- `Plugin ID`: Identifier for the vulnerability
- `CVE`: CVE identifier(s)
- `Host`: Host/IP address where the vulnerability was found
- `Name`: Vulnerability name
- `Risk`: Risk level (Critical, High, Medium, Low)

Additional recommended columns for enhanced analysis:

- `Description`: Vulnerability description
- `Solution`: Recommended remediation
- `Plugin Output`: Scanner output for the vulnerability
- `CVSS v3.0 Base Score`: CVSS score
- `EPSS Score`: EPSS score
- `VPR Score`: VPR score

### Known Exploited Vulnerabilities (KEV) File

A CSV file containing the CISA Known Exploited Vulnerabilities catalog. This should contain a `cveID` column.

## Output Files

The tool generates three types of output files:

1. **Standard Report**: Excel file with multiple sheets containing raw data and analysis
2. **Enhanced Report**: Excel file with visualizations and prioritization insights
3. **JSON Results**: JSON file with analysis results for integration with other systems

## Architecture

The tool follows a modular architecture:

```
vulnerability_analysis_tool/
├── main.py                  # Entry point
├── requirements.txt         # Dependencies
└── va_tool/                 # Main package
    ├── data/                # Data acquisition modules
    ├── processing/          # Analysis and processing modules 
    ├── reporting/           # Report generation modules
    │   └── sheets/          # Excel sheet generators
    └── utils/               # Utility functions and helpers
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- NIST National Vulnerability Database for CVE data
- CISA for Known Exploited Vulnerabilities catalog