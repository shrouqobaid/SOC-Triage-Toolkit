import datetime
import os

def generate_markdown_report(results, output_path="SOC_Triage_Report.md"):
    # Initialize counters
    total_iocs = len(results)
    successful_scans = 0
    failed_scans = 0
    malicious_iocs = 0
    needs_review_iocs = 0
    suspicious_iocs = 0
    clean_iocs = 0

    # Severity counters
    critical_count = 0
    high_count = 0
    medium_count = 0
    informational_count = 0
    unknown_count = 0

    table_rows = ""
    # SOC Analyst Recommendations
    recommendations = {
        "Critical": "Immediate investigation and containment",
        "High": "Prioritize investigation",
        "Medium": "Review and validate IOC",
        "Informational": "No immediate action required",
        "Unknown": "Retry analysis"
    }
    for item in results:
        ioc = item.get("ioc", "N/A")
        status = item.get("status", "Unknown")
        if status == "Success":
            successful_scans += 1
            ioc_type = item.get("ioc_type", "ip_address" if "." in ioc and not ioc.isalpha() else "md5")
            malicious = item.get("malicious", 0)
            suspicious = item.get("suspicious", 0)
            harmless = item.get("harmless", 0)

            # Determine Threat Verdict and Severity
            if malicious >= 5:
                verdict = "🔴 Malicious"
                severity = "Critical"
                malicious_iocs += 1
                critical_count += 1

            elif 0 < malicious < 5:
                verdict = "🔎 Needs Review"
                severity = "High"
                needs_review_iocs += 1
                high_count += 1

            elif suspicious > 0:
                verdict = "🟠 Suspicious"
                severity = "Medium"
                suspicious_iocs += 1
                medium_count += 1

            else:
                verdict = "🟢 Clean"
                severity = "Informational"
                clean_iocs += 1
                informational_count += 1

            recommendation = recommendations.get(
                severity,
                "Manual review required"
            )

            # Display malicious detection count
            mal_cell = str(malicious)

            table_rows += f"| `{ioc}` | {ioc_type} | {status} | {verdict} | {severity} | {mal_cell} | {suspicious} | {harmless} | {recommendation} |\n"

        else:
            failed_scans += 1
            unknown_count += 1
            ioc_type = "Unknown"

            table_rows += f"| `{ioc}` | {ioc_type} | {status} | Not Evaluated | Unknown | - | - | - | {recommendations['Unknown']} |\n"

    # Executive Assessment
    if successful_scans == 0:
        executive_assessment = (
            "UNABLE TO ASSESS: All IOC scans failed. "
            "No threat assessment can be made. Retry analysis."
        )

    elif critical_count > 0:
        executive_assessment = (
            f"CRITICAL: {critical_count} critical IOC(s) detected. "
            "Immediate investigation and containment required."
        )

    elif high_count > 0:
        executive_assessment = (
            f"HIGH: {high_count} high-severity IOC(s) detected. "
            "Prioritize investigation."
        )

    elif medium_count > 0:
        executive_assessment = (
            f"MEDIUM: {medium_count} suspicious IOC(s) detected. "
            "Review and validate findings."
        )

    elif unknown_count > 0:
        executive_assessment = (
            f"REVIEW REQUIRED: {unknown_count} IOC(s) could not be evaluated. "
            "Retry analysis."
        )

    else:
        executive_assessment = (
            "NO THREATS DETECTED: No malicious or suspicious IOCs found."
        )

    # Current timestamp
    gen_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Markdown template
    report_content = f"""# Automated SOC Alert Triage Report
**Generated on:** `{gen_time}`<br>
**Tool:** SOC-Triage-Toolkit

---

## 📊 Executive Summary
This report contains the automated threat intelligence enrichment results for the submitted Indicators of Compromise (IOCs) via VirusTotal API.

### 🚨 Executive Assessment
**{executive_assessment}**

## 📈 Executive Summary Statistics

| Metric | Count |
| :--- | :---: |
| Total IOCs | {total_iocs} |
| Successful Scans | {successful_scans} |
| Failed Scans | {failed_scans} |
| Malicious IOCs 🚨 | {malicious_iocs} |
| Needs Review 🔎 | {needs_review_iocs} |
| Suspicious IOCs ⚠️ | {suspicious_iocs} |
| Clean IOCs ✅ | {clean_iocs} |

### 🎯 Severity Distribution

| Severity Level | Count |
| :--- | :---: |
| Critical 🔴 | {critical_count} |
| High 🟠 | {high_count} |
| Medium 🟡 | {medium_count} |
| Informational 🟢 | {informational_count} |
| Unknown ⚪ | {unknown_count} |

---

## IOC Investigation Results
| IOC Value | IOC Type | Status | Threat Verdict | Severity | Malicious 🚨 | Suspicious ⚠️ | Harmless ✅ | Analyst Recommendation |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
{table_rows}
---
> *Report automatically generated by Shrouq's SOC-Triage-Toolkit.*
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"[+] Triage report successfully generated: {output_path}")
