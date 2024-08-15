import boto3
from botocore.exceptions import ClientError

def create_iam_client():
    try:
        return boto3.client('iam')
    except Exception as e:
        print(f"Error creating IAM client: {e}")
        raise

def list_roles(client):
    roles = []
    try:
        paginator = client.get_paginator('list_roles')
        for page in paginator.paginate():
            roles.extend(page['Roles'])
        return roles
    except ClientError as e:
        print(f"Error listing IAM roles: {e}")
        raise

def get_role_policies(client, role_name):
    attached_policies = []
    inline_policies = []
    try:
        # Get attached policies.
        paginator = client.get_paginator('list_attached_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            attached_policies.extend(page['AttachedPolicies'])
        
        # Get inline policies.
        paginator = client.get_paginator('list_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            inline_policies.extend(page['PolicyNames'])
        
        return attached_policies, inline_policies
    except ClientError as e:
        print(f"Error getting policies for role {role_name}: {e}")
        raise

def get_policy_document(client, policy_arn):
    try:
        policy = client.get_policy(PolicyArn=policy_arn)
        version_id = policy['Policy']['DefaultVersionId']
        policy_version = client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        return policy_version['PolicyVersion']['Document']
    except ClientError as e:
        print(f"Error getting policy document for {policy_arn}: {e}")
        raise