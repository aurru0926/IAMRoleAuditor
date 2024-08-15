from iam_auditor.iam_client import create_iam_client, list_roles
from iam_auditor.role_auditor import audit_role_policies
from iam_auditor.report_generator import generate_report, save_report

def main():
    try:
        print("Creating IAM client...")
        client = create_iam_client()

        print("Listing IAM roles...")
        roles = list_roles(client)
        print(f"Found {len(roles)} roles.")

        if not roles:
            print("No IAM roles found. Exiting program.")
            return

        print("Auditing roles...")
        audit_results = []
        for i, role in enumerate(roles, 1):
            print(f"Auditing role {i}/{len(roles)}: {role['RoleName']}")
            results = audit_role_policies(client, role)
            audit_results.extend(results)

        roles_with_issues = sum(1 for r in audit_results if r.get('Findings'))

        if roles_with_issues == 0:
            print("No audit findings. All roles appear to be properly configured.")
        else:
            print(f"Audit complete. Found issues in {roles_with_issues} roles.")

        print("Generating report...")
        report = generate_report(audit_results)

        print("Saving report...")
        save_report(report, 'audit_report.txt')

        print("Audit completed successfully. Please review 'audit_report.txt' for detailed findings.")
    except Exception as e:
        print(f"An error occurred during the audit process: {e}")
        raise

if __name__ == "__main__":
    main()