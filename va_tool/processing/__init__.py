"""Make the processing directory a proper package."""

from va_tool.processing.categorization import (
    assign_severity, categorize_name, categorize_vulnerabilities
)
from va_tool.processing.scoring import (
    categorize_cvss_score, categorize_epss_score, categorize_vpr_score,
    calculate_exploitability_score, add_scoring_data
)
from va_tool.processing.analysis import (
    analyze_vulnerability_data, generate_risk_counts, generate_top_cves,
    generate_ip_vuln_counts, generate_patch_summary, generate_bucket_summary,
    generate_seol_summary, generate_scoring_summary, generate_vulnerability_insights,
    generate_common_critical
)
from va_tool.processing.core import process_vulnerability_data

__all__ = [
    # From categorization
    'assign_severity', 'categorize_name', 'categorize_vulnerabilities',
    
    # From scoring
    'categorize_cvss_score', 'categorize_epss_score', 'categorize_vpr_score',
    'calculate_exploitability_score', 'add_scoring_data',
    
    # From analysis
    'analyze_vulnerability_data', 'generate_risk_counts', 'generate_top_cves',
    'generate_ip_vuln_counts', 'generate_patch_summary', 'generate_bucket_summary',
    'generate_seol_summary', 'generate_scoring_summary', 'generate_vulnerability_insights',
    'generate_common_critical',
    
    # From core
    'process_vulnerability_data'
]