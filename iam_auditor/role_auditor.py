from iam_auditor.iam_client import get_role_policies, get_policy_document
from botocore.exceptions import ClientError

def audit_role_policies(client, role):
    try:
        attached_policies, inline_policies = get_role_policies(client, role['RoleName'])
    except ClientError as e:
        print(f"Error getting policies for role {role['RoleName']}: {e}")
        return []
    
    audit_results = []
    
    # Audit attached policies.
    for policy in attached_policies:
        try:
            policy_document = get_policy_document(client, policy['PolicyArn'])
            findings = analyze_policy(role['RoleName'], policy_document)
            if findings:
                audit_results.append({
                    'RoleName': role['RoleName'],
                    'PolicyName': policy['PolicyName'],
                    'PolicyArn': policy['PolicyArn'],
                    'PolicyType': 'Attached',
                    'Findings': findings
                })
        except ClientError as e:
            print(f"Error analyzing attached policy {policy['PolicyName']}: {e}")
    
    # Audit inline policies.
    for inline_policy_name in inline_policies:
        try:
            policy_document = client.get_role_policy(RoleName=role['RoleName'], PolicyName=inline_policy_name)['PolicyDocument']
            findings = analyze_policy(role['RoleName'], policy_document)
            if findings:
                audit_results.append({
                    'RoleName': role['RoleName'],
                    'PolicyName': inline_policy_name,
                    'PolicyType': 'Inline',
                    'Findings': findings
                })
        except ClientError as e:
            print(f"Error analyzing inline policy {inline_policy_name}: {e}")
    
    return audit_results

def analyze_policy(role_name, policy_document):
    statements = policy_document.get('Statement', [])
    findings = []
    
    for statement in statements:
        effect = statement.get('Effect')
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        
        if '*' in actions:
            findings.append(f"Wildcard action found in policy")
        if '*' in resources:
            findings.append(f"Wildcard resource found in policy")
        
        # Check for overly permissive actions.
        sensitive_actions = ['iam:*', 's3:*', 'ec2:*', 'rds:*', 'dynamodb:*']
        for action in actions:
            if any(action.startswith(sa.replace('*', '')) for sa in sensitive_actions):
                findings.append(f"Potentially overly permissive action: {action}")
        
        # Check for "Allow" effect with sensitive actions.
        if effect == 'Allow' and any(action in sensitive_actions for action in actions):
            findings.append(f"'Allow' effect used with sensitive action(s)")
    
    return findings