import json
import sys
import os
import html
import re
from typing import Dict, List, Any

class TerraformStateAnalyzer:
    def __init__(self, state_file_path: str):
        self.state_file_path = state_file_path
        self.state_data = self._load_state_file()
        self.resources = self._extract_resources()

    def _load_state_file(self) -> Dict[str, Any]:
        try:
            with open(self.state_file_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: State file {self.state_file_path} not found.")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in state file {self.state_file_path}")
            sys.exit(1)

    def _extract_resources(self) -> List[Dict[str, Any]]:
        resources = []
        for resource in self.state_data.get('resources', []):
            resources.append({
                'type': resource.get('type', 'Unknown'),
                'name': resource.get('name', 'Unnamed'),
                'provider': resource.get('provider', 'Unknown'),
                'instances': resource.get('instances', [])
            })
        return resources

    def generate_html_report(self) -> str:
        html_template = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Terraform State Analysis</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; }
                h1 { color: #333; border-bottom: 2px solid #ccc; }
                .resource { background: #f4f4f4; margin: 10px 0; padding: 15px; border-radius: 5px; }
                .resource-header { display: flex; justify-content: space-between; }
                .resource-type { font-weight: bold; color: #0066cc; }
                .resource-name { color: #666; }
                .resource-details { margin-top: 10px; }
                .dependency { color: #888; font-style: italic; }
            </style>
        </head>
        <body>
            <h1>Terraform State Analysis</h1>
            <div class="summary">
                <p>Total Resources: {total_resources}</p>
                <p>Resource Types: {resource_types}</p>
            </div>
            {resources_html}
        </body>
        </html>
        '''

        resources_html = []
        for resource in self.resources:
            resource_html = f'''
            <div class="resource">
                <div class="resource-header">
                    <span class="resource-type">{html.escape(resource['type'])}</span>
                    <span class="resource-name">{html.escape(resource['name'])}</span>
                </div>
                <div class="resource-details">
                    <p>Provider: {html.escape(resource['provider'])}</p>
                    <p>Instances: {len(resource['instances'])}</p>
                </div>
            </div>
            '''
            resources_html.append(resource_html)

        return html_template.format(
            total_resources=len(self.resources),
            resource_types=len(set(r['type'] for r in self.resources)),
            resources_html=''.join(resources_html)
        )

    def analyze_dependencies(self) -> List[Dict[str, Any]]:
        dependencies = []
        for resource in self.resources:
            for instance in resource['instances']:
                dependencies.append({
                    'resource_type': resource['type'],
                    'resource_name': resource['name'],
                    'dependencies': self._find_resource_dependencies(instance)
                })
        return dependencies

    def _find_resource_dependencies(self, instance: Dict[str, Any]) -> List[str]:
        dependencies = []
        def find_references(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if isinstance(value, str) and re.search(r'\${.*}', value):
                        dependencies.append(value)
                    elif isinstance(value, (dict, list)):
                        find_references(value)
            elif isinstance(obj, list):
                for item in obj:
                    find_references(item)

        find_references(instance.get('attributes', {}))
        return dependencies

    def export_report(self, output_format='html'):
        if output_format == 'html':
            report = self.generate_html_report()
            output_path = os.path.join(os.path.dirname(self.state_file_path), 'terraform_state_report.html')
            with open(output_path, 'w') as f:
                f.write(report)
            print(f"HTML report generated: {output_path}")
        elif output_format == 'json':
            report = {
                'resources': self.resources,
                'dependencies': self.analyze_dependencies()
            }
            output_path = os.path.join(os.path.dirname(self.state_file_path), 'terraform_state_report.json')
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"JSON report generated: {output_path}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python terraform_state_analyzer.py <path_to_terraform_state_file>")
        sys.exit(1)

    state_file_path = sys.argv[1]
    analyzer = TerraformStateAnalyzer(state_file_path)
    
    print("Analyzing Terraform State File...")
    analyzer.export_report('html')
    analyzer.export_report('json')

if __name__ == '__main__':
    main()