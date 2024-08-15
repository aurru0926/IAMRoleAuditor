import os
from datetime import datetime

#  Generate a text based report of audit findings.
def generate_report(audit_results):
    report = []
    summary = {
        'total_roles': len(set(result['RoleName'] for result in audit_results)),
        'roles_with_issues': 0,
        'total_findings': 0,
        'findings_by_severity': {'High': 0, 'Medium': 0, 'Low': 0}
    }

    report.append("AWS IAM Role Audit Report")
    report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")

    for result in audit_results:
        role_name = result['RoleName']
        policy_name = result['PolicyName']
        policy_type = result['PolicyType']
        findings = result['Findings']

        if findings:
            summary['roles_with_issues'] += 1
            summary['total_findings'] += len(findings)

            report.append(f"Role: {role_name}")
            report.append(f"  Policy: {policy_name} (Type: {policy_type})")

            for finding in findings:
                severity = finding['Severity']
                summary['findings_by_severity'][severity] += 1
                report.append(f"    Severity: {severity}")
                report.append(f"    Issue: {finding['Issue']}")
                report.append(f"    Description: {finding['Description']}")
                report.append(f"    Recommendation: {finding['Recommendation']}")
                report.append("")

    # Add summary at the beginning of the report.
    summary_lines = [
        "Summary:",
        f"Total Roles Audited: {summary['total_roles']}",
        f"Roles with Issues: {summary['roles_with_issues']}",
        f"Total Findings: {summary['total_findings']}",
        "Findings by Severity:"
    ]
    for severity, count in summary['findings_by_severity'].items():
        summary_lines.append(f"  {severity}: {count}")
    summary_lines.append("")

    report = summary_lines + report

    return "\n".join(report)

# Saves the report.
def save_report(report, filename):
    """
    Save the generated report to a text file.
    """
    try:
        with open(filename, 'w') as file:
            file.write(report)
        print(f"Audit report generated: {os.path.abspath(filename)}")
    except IOError as e:
        print(f"Error saving report to {filename}: {e}")
        raise