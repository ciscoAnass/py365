import boto3
import json
import re
import sys
from typing import List, Dict, Any
from botocore.exceptions import ClientError

class IAMPolicyValidator:
    def __init__(self, profile_name: str = None):
        self.session = boto3.Session(profile_name=profile_name)
        self.iam_client = self.session.client('iam')
        self.findings = {
            'overly_permissive_policies': [],
            'user_direct_policy_attachments': [],
            'unused_policies': [],
            'wildcard_actions': [],
            'high_risk_policies': []
        }

    def validate_all_policies(self):
        self._validate_user_policies()
        self._validate_group_policies()
        self._validate_role_policies()
        self._analyze_policy_risk()
        return self.findings

    def _validate_user_policies(self):
        try:
            paginator = self.iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']
                    policies = self.iam_client.list_attached_user_policies(UserName=username)['AttachedPolicies']
                    
                    if policies:
                        self.findings['user_direct_policy_attachments'].append({
                            'username': username,
                            'policy_count': len(policies)
                        })
        except ClientError as e:
            print(f"Error validating user policies: {e}")

    def _validate_group_policies(self):
        try:
            paginator = self.iam_client.get_paginator('list_groups')
            for page in paginator.paginate():
                for group in page['Groups']:
                    groupname = group['GroupName']
                    policies = self.iam_client.list_attached_group_policies(GroupName=groupname)['AttachedPolicies']
                    
                    for policy in policies:
                        policy_details = self._get_policy_document(policy['PolicyArn'])
                        self._check_policy_risk(policy_details, groupname)
        except ClientError as e:
            print(f"Error validating group policies: {e}")

    def _validate_role_policies(self):
        try:
            paginator = self.iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    rolename = role['RoleName']
                    policies = self.iam_client.list_attached_role_policies(RoleName=rolename)['AttachedPolicies']
                    
                    for policy in policies:
                        policy_details = self._get_policy_document(policy['PolicyArn'])
                        self._check_policy_risk(policy_details, rolename)
        except ClientError as e:
            print(f"Error validating role policies: {e}")

    def _get_policy_document(self, policy_arn: str) -> Dict[str, Any]:
        try:
            policy_version = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=self.iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            )
            return json.loads(policy_version['PolicyVersion']['Document'])
        except ClientError:
            return {}

    def _check_policy_risk(self, policy: Dict[str, Any], entity_name: str):
        if not policy:
            return

        for statement in policy.get('Statement', []):
            actions = statement.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]

            # Check for wildcard actions
            wildcard_actions = [action for action in actions if '*:*' in action or action.endswith(':*')]
            if wildcard_actions:
                self.findings['wildcard_actions'].append({
                    'entity': entity_name,
                    'actions': wildcard_actions
                })

            # Check for overly permissive policies
            if statement.get('Effect') == 'Allow' and '*' in actions:
                self.findings['overly_permissive_policies'].append({
                    'entity': entity_name,
                    'policy': policy
                })

    def _analyze_policy_risk(self):
        # Additional complex risk analysis could be implemented here
        pass

    def generate_report(self):
        report = """
        AWS IAM Policy Risk Assessment Report
        =====================================
        
        Overly Permissive Policies: {}
        Direct User Policy Attachments: {}
        Wildcard Actions Detected: {}
        
        Detailed Findings:
        {}
        """.format(
            len(self.findings['overly_permissive_policies']),
            len(self.findings['user_direct_policy_attachments']),
            len(self.findings['wildcard_actions']),
            json.dumps(self.findings, indent=2)
        )
        return report

def main():
    validator = IAMPolicyValidator()
    validator.validate_all_policies()
    print(validator.generate_report())

if __name__ == '__main__':
    main()