import os
import sys
import json
import yaml
import re
import argparse
from typing import Dict, List, Any
from dataclasses import dataclass, field

@dataclass
class CloudFormationLinter:
    template_path: str
    template_data: Dict[str, Any] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)

    def load_template(self):
        try:
            with open(self.template_path, 'r') as file:
                if self.template_path.endswith('.json'):
                    self.template_data = json.load(file)
                elif self.template_path.endswith(('.yml', '.yaml')):
                    self.template_data = yaml.safe_load(file)
                else:
                    raise ValueError("Unsupported file format. Use JSON or YAML.")
        except Exception as e:
            print(f"Error loading template: {e}")
            sys.exit(1)

    def check_required_tags(self, required_tags=None):
        if required_tags is None:
            required_tags = ['Environment', 'Project', 'Owner', 'CostCenter']

        resources = self.template_data.get('Resources', {})
        for resource_name, resource_config in resources.items():
            tags = resource_config.get('Properties', {}).get('Tags', [])
            tag_keys = [tag.get('Key', '') for tag in tags]

            for req_tag in required_tags:
                if req_tag not in tag_keys:
                    self.findings.append(f"Missing required tag '{req_tag}' in resource {resource_name}")

    def detect_hardcoded_secrets(self):
        def recursive_secret_check(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if isinstance(value, str):
                        if re.search(r'(password|secret|key|token|credentials)', key.lower()):
                            self.findings.append(f"Potential hardcoded secret detected in key: {key}")
                    recursive_secret_check(value)
            elif isinstance(obj, list):
                for item in obj:
                    recursive_secret_check(item)

        recursive_secret_check(self.template_data)

    def validate_security_configurations(self):
        resources = self.template_data.get('Resources', {})
        
        for resource_name, resource_config in resources.items():
            resource_type = resource_config.get('Type', '')
            
            # EC2 Security Group checks
            if resource_type == 'AWS::EC2::SecurityGroup':
                properties = resource_config.get('Properties', {})
                ingress_rules = properties.get('SecurityGroupIngress', [])
                
                for rule in ingress_rules:
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 0)
                    
                    if from_port <= 22 or to_port <= 22:
                        self.findings.append(f"SSH port (22) exposed in SecurityGroup {resource_name}")
                    
                    if from_port <= 3389 or to_port <= 3389:
                        self.findings.append(f"RDP port (3389) exposed in SecurityGroup {resource_name}")

            # S3 Bucket security checks
            if resource_type == 'AWS::S3::Bucket':
                properties = resource_config.get('Properties', {})
                
                if not properties.get('PublicAccessBlockConfiguration'):
                    self.findings.append(f"S3 Bucket {resource_name} lacks public access block configuration")

    def generate_report(self):
        print("\n--- CloudFormation Linter Report ---")
        if not self.findings:
            print("✅ No issues found in the CloudFormation template.")
        else:
            print("🚨 Issues Detected:")
            for index, finding in enumerate(self.findings, 1):
                print(f"{index}. {finding}")

def main():
    parser = argparse.ArgumentParser(description='CloudFormation Template Linter')
    parser.add_argument('template_path', help='Path to CloudFormation template')
    args = parser.parse_args()

    linter = CloudFormationLinter(args.template_path)
    linter.load_template()
    linter.check_required_tags()
    linter.detect_hardcoded_secrets()
    linter.validate_security_configurations()
    linter.generate_report()

if __name__ == '__main__':
    main()