import sys
import json
import yaml
import argparse
import os
import re
from typing import Dict, Any, Optional

class JSONYAMLFormatter:
    def __init__(self):
        self.supported_formats = ['json', 'yaml', 'yml']

    def validate_file(self, file_path: str) -> Dict[str, Any]:
        """Validate and parse file contents based on file extension."""
        file_extension = os.path.splitext(file_path)[1][1:].lower()
        
        if file_extension not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_extension}")
        
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                
            if file_extension in ['json']:
                return self._validate_json(content)
            else:
                return self._validate_yaml(content)
        
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}")
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            raise ValueError(f"Invalid file syntax: {str(e)}")

    def _validate_json(self, content: str) -> Dict[str, Any]:
        """Validate JSON content."""
        try:
            parsed_json = json.loads(content)
            return parsed_json
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {str(e)}")

    def _validate_yaml(self, content: str) -> Dict[str, Any]:
        """Validate YAML content."""
        try:
            parsed_yaml = yaml.safe_load(content)
            return parsed_yaml
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {str(e)}")

    def format_file(self, file_path: str, output_format: Optional[str] = None, indent: int = 2) -> str:
        """Format file contents with optional output format conversion."""
        file_extension = os.path.splitext(file_path)[1][1:].lower()
        parsed_content = self.validate_file(file_path)
        
        if output_format is None:
            output_format = file_extension
        
        if output_format == 'json':
            return json.dumps(parsed_content, indent=indent)
        elif output_format in ['yaml', 'yml']:
            return yaml.safe_dump(parsed_content, default_flow_style=False, indent=indent)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

def main():
    parser = argparse.ArgumentParser(description='JSON/YAML Formatter and Validator')
    parser.add_argument('file', help='Input file path')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-f', '--format', choices=['json', 'yaml', 'yml'], 
                        help='Output format (default: same as input)')
    parser.add_argument('-i', '--indent', type=int, default=2, 
                        help='Indentation spaces (default: 2)')
    parser.add_argument('--validate', action='store_true', 
                        help='Only validate file syntax')
    
    args = parser.parse_args()
    
    formatter = JSONYAMLFormatter()
    
    try:
        if args.validate:
            result = formatter.validate_file(args.file)
            print("File is valid.")
            print(json.dumps(result, indent=2))
        else:
            formatted_content = formatter.format_file(
                args.file, 
                output_format=args.format, 
                indent=args.indent
            )
            
            if args.output:
                with open(args.output, 'w') as outfile:
                    outfile.write(formatted_content)
                print(f"Formatted file saved to {args.output}")
            else:
                print(formatted_content)
    
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()