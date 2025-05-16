"""Analysis functionality for vulnerability data."""

import pandas as pd
import datetime
from va_tool.utils import get_logger, clean_for_json

logger = get_logger()


def analyze_vulnerability_data(df, kev_set, cve_cache):
    """
    Analyze vulnerability data and enrich with additional fields.
    
    Args:
        df: DataFrame with vulnerability data
        kev_set: Set of CVE IDs from KEV list
        cve_cache: Dictionary with CVE details from cache/API
    
    Returns:
        DataFrame with enriched data and dictionary with analysis results
    """
    logger.info("Starting vulnerability data analysis")
    
    # Create a copy to avoid modifying the original
    result_df = df.copy()
    today = datetime.date.today()
    
    # Add CVE publication date and days since publication
    result_df["CVE Published Date"] = result_df["CVE"].map(
        lambda x: cve_cache.get(x, {}).get("date_obj") if pd.notna(x) else None
    )
    
    result_df["Days After Discovery"] = result_df["CVE Published Date"].apply(
        lambda x: (today - datetime.date.fromisoformat(x)).days if pd.notna(x) and x else None
    )
    
    # Add KEV listing status
    result_df["KEV Listed"] = result_df["CVE"].apply(
        lambda x: "Yes" if pd.notna(x) and str(x) in kev_set else "No"
    )
    
    # Add patch status information
    result_df["Patch Status"] = result_df["CVE"].apply(
        lambda x: cve_cache.get(x, {}).get("patch_info", {}).get("status", "Unknown") 
        if pd.notna(x) else "Unknown"
    )
    
    # Split data for analysis
    # Remove informational findings for primary analysis
    filtered_df = result_df[~result_df["Risk"].isin(["None", "Informational"])]
    check_needed_df = filtered_df[filtered_df["Risk"] == "Check Needed"].copy()
    analyzed_df = filtered_df[filtered_df["Risk"] != "Check Needed"]
    
    # Generate analysis results
    results = {
        "risk_counts": generate_risk_counts(analyzed_df),
        "top_cves": generate_top_cves(analyzed_df),
        "ip_vuln_counts": generate_ip_vuln_counts(analyzed_df),
        "patch_summary": generate_patch_summary(analyzed_df),
        "bucket_summary": generate_bucket_summary(analyzed_df),
        "seol_summary": generate_seol_summary(analyzed_df),
        "scoring_summary": generate_scoring_summary(analyzed_df),
        "vulnerability_insights": generate_vulnerability_insights(analyzed_df),
        "common_critical": generate_common_critical(analyzed_df)
    }
    
    logger.info("Vulnerability analysis complete")
    return result_df, check_needed_df, analyzed_df, results


def generate_risk_counts(df):
    """Generate risk counts summary."""
    risk_counts = df["Risk"].value_counts().reset_index()
    risk_counts.columns = ["Risk Level", "Count"]
    return clean_for_json(risk_counts)


def generate_top_cves(df):
    """Generate top CVEs summary."""
    top_cves = df["CVE"].value_counts().nlargest(10).reset_index()
    top_cves.columns = ["CVE", "Count"]
    return clean_for_json(top_cves)


def generate_ip_vuln_counts(df):
    """Generate IP-based vulnerability counts."""
    # Create pivot table with vulnerability counts by host and risk
    ip_vuln_counts = df.pivot_table(
        index="Host", 
        columns="Risk", 
        aggfunc="size", 
        fill_value=0
    )
    
    # Ensure all risk levels are present
    for risk in ["Critical", "High", "Medium", "Low"]:
        if risk not in ip_vuln_counts.columns:
            ip_vuln_counts[risk] = 0
            
    # Add total and weighted counts
    ip_vuln_counts["Total Vulnerabilities"] = ip_vuln_counts.sum(axis=1)
    ip_vuln_counts["Criticality"] = (
        (ip_vuln_counts.get("Critical", 0) * 4) + 
        (ip_vuln_counts.get("High", 0) * 3) + 
        (ip_vuln_counts.get("Medium", 0) * 2) + 
        (ip_vuln_counts.get("Low", 0) * 1)
    )
    ip_vuln_counts.reset_index(inplace=True)
    
    return clean_for_json(ip_vuln_counts)


def generate_patch_summary(df):
    """Generate patch status summary."""
    grouped = df.groupby("Patch Status")
    patch_summary = pd.DataFrame({
        "Vulnerability Count": grouped["CVE"].count(),
        "Risk Distribution": grouped["Risk"].apply(lambda x: x.value_counts().to_dict())
    }).reset_index()
    
    return clean_for_json(patch_summary)


def generate_bucket_summary(df):
    """Generate bucket categorization summary."""
    # Explode the bucket column to handle multiple buckets per vulnerability
    df_exploded = df.copy()
    df_exploded["Bucket"] = df_exploded["Bucket"].str.split(", ")
    df_exploded = df_exploded.explode("Bucket")
    
    # Count vulnerabilities by bucket
    bucket_grouped = df_exploded.groupby("Bucket")
    bucket_counts = bucket_grouped.size().reset_index(name="Count")
    
    # Get risk distribution by bucket
    bucket_risk_distribution = pd.crosstab(df_exploded["Bucket"], df_exploded["Risk"])
    
    # Ensure all risk levels are present
    for risk in ["Critical", "High", "Medium", "Low"]:
        if risk not in bucket_risk_distribution.columns:
            bucket_risk_distribution[risk] = 0
    
    # Merge counts and distribution
    bucket_summary_df = pd.merge(bucket_counts, bucket_risk_distribution, on="Bucket")
    
    return clean_for_json(bucket_summary_df)


def generate_seol_summary(df):
    """Generate SEoL (Service End of Life) summary."""
    # Find SEoL items
    seolkit = df[df["Name"].str.contains("SEoL", case=False, na=False)]
    
    if not seolkit.empty:
        # Group by host
        grouped_seol = seolkit.groupby("Host")
        seol_ip_summary = pd.DataFrame({
            "SEoL Count": grouped_seol["Plugin ID"].count(),
            "Risk Distribution": grouped_seol.apply(lambda x: {"Critical": len(x)})
        }).reset_index()
        
        return clean_for_json(seol_ip_summary)
    
    return []


def generate_scoring_summary(df):
    """Generate scoring summary for CVSS, EPSS, VPR, and KEV."""
    # Check if required columns exist
    if not all(col in df.columns for col in ["CVSS Category", "EPSS Category", "VPR Category", "KEV Listed"]):
        return []
    
    # Create summary dataframe
    summary_df = pd.DataFrame({
        'Metric': ['CVSS', 'EPSS', 'VPR', 'CISA KEV'],
    })
    
    # Add count columns for each severity level
    for severity in ["Critical", "High", "Medium", "Low"]:
        counts = []
        
        # CVSS count
        cvss_count = len(df[df["CVSS Category"] == severity])
        counts.append(cvss_count)
        
        # EPSS count
        epss_count = len(df[df["EPSS Category"] == severity])
        counts.append(epss_count)
        
        # VPR count
        vpr_count = len(df[df["VPR Category"] == severity])
        counts.append(vpr_count)
        
        # KEV count (only for Critical)
        if severity == "Critical":
            kev_count = len(df[df["KEV Listed"] == "Yes"])
        else:
            kev_count = 0
        counts.append(kev_count)
        
        # Add to dataframe
        summary_df[f'{severity} Count'] = counts
    
    return clean_for_json(summary_df)


def generate_vulnerability_insights(df):
    """Generate insights about vulnerabilities."""
    # Extract relevant columns
    insight_df = df[["Name", "Solution", "Risk", "Host"]]
    
    # Group by vulnerability name
    insight_df_grouped = insight_df.groupby("Name").agg({
        "Solution": lambda x: list(x.dropna().unique()),
        "Risk": lambda x: x.dropna().unique()[0] if len(x.dropna().unique()) > 0 else "Not Assigned",
        "Host": lambda x: len(x.dropna().unique())
    }).reset_index()
    
    # Explode solutions for one row per solution
    insight_df_exploded = insight_df_grouped.explode("Solution").reset_index(drop=True)
    insight_df_exploded["Vulnerability Name"] = insight_df_exploded.groupby("Name")["Name"].transform(lambda x: x.ffill())
    
    # Add vulnerability counts
    total_vuln_counts = df["Name"].value_counts().reset_index()
    total_vuln_counts.columns = ["Name", "Total Count"]
    insight_df_exploded = insight_df_exploded.merge(total_vuln_counts, on="Name", how="left")
    insight_df_exploded["Vulnerability Count"] = insight_df_exploded["Total Count"]
    
    # Finalize dataset
    insight_df_exploded["IP Count"] = insight_df_exploded.groupby("Name")["Host"].transform('first')
    insight_df_exploded = insight_df_exploded[["Vulnerability Name", "Solution", "Risk", "Vulnerability Count", "IP Count"]]
    insight_df_exploded.columns = ["Vulnerability Name", "Solutions", "Severity", "Vulnerability Count", "IP Count"]
    
    return clean_for_json(insight_df_exploded)


def generate_common_critical(df):
    """Generate common critical vulnerabilities list."""
    # Check if required columns exist
    required_cols = ["CVSS Category", "EPSS Category", "VPR Category", "KEV Listed"]
    if not all(col in df.columns for col in required_cols):
        return []
    
    # Find vulnerabilities that are critical/high across multiple metrics
    common_critical = df[
        (df['CVSS Category'].isin(['Critical', 'High'])) &
        (df['EPSS Category'].isin(['Critical', 'High'])) &
        (df['VPR Category'].isin(['Critical', 'High'])) &
        (df['KEV Listed'] == 'Yes')
    ].copy()
    
    if not common_critical.empty:
        # Add priority score calculation
        common_critical['CVSS Value'] = common_critical['CVSS Category'].map({
            'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Not Assigned': 0
        })
        common_critical['EPSS Value'] = common_critical['EPSS Category'].map({
            'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Not Assigned': 0
        })
        common_critical['VPR Value'] = common_critical['VPR Category'].map({
            'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Not Assigned': 0
        })
        
        # Calculate combined priority
        common_critical['Combined Priority'] = (
            (common_critical['CVSS Value'] * 2) + 
            common_critical['EPSS Value'] + 
            common_critical['VPR Value']
        )
        
        # Select required columns
        required_columns = [
            'Plugin ID', 'CVE', 'Host', 'Name', 'Description', 'Plugin Output', 'Risk',
            'CVSS v3.0 Base Score', 'CVSS Category',
            'EPSS Score', 'EPSS Category',
            'VPR Score', 'VPR Category',
            'KEV Listed', 'Combined Priority'
        ]
        
        # Filter columns that exist in the dataframe
        available_columns = [col for col in required_columns if col in common_critical.columns]
        common_critical = common_critical[available_columns]
        
        # Sort by priority
        sort_columns = ['Combined Priority']
        if 'CVSS v3.0 Base Score' in common_critical.columns:
            sort_columns.append('CVSS v3.0 Base Score')
            
        common_critical = common_critical.sort_values(
            by=sort_columns,
            ascending=[False, False]
        )
        
        return clean_for_json(common_critical)
        
    return []