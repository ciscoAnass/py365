import os
import json
import sys
import re
import math
import datetime
from collections import defaultdict
from typing import Dict, List, Tuple

def get_resource_counts(tf_state: Dict) -> Dict[str, int]:
    """
    Counts the number of resources of each type in the Terraform state.
    
    Args:
        tf_state (Dict): The parsed Terraform state JSON.
    
    Returns:
        Dict[str, int]: A dictionary mapping resource types to their counts.
    """
    resource_counts = defaultdict(int)
    for resource in tf_state["resources"]:
        resource_counts[resource["type"]] += 1
    return resource_counts

def get_resource_drift(tf_state: Dict) -> Dict[str, List[Dict]]:
    """
    Identifies resources that have drifted from their defined configuration.
    
    Args:
        tf_state (Dict): The parsed Terraform state JSON.
    
    Returns:
        Dict[str, List[Dict]]: A dictionary mapping resource types to a list of drifted resources.
    """
    drifted_resources = defaultdict(list)
    for resource in tf_state["resources"]:
        for attribute, value in resource["primary"]["attributes"].items():
            if attribute in resource["schema"]["attributes"]:
                schema_attr = resource["schema"]["attributes"][attribute]
                if schema_attr["type"] != "string" and schema_attr["type"] != "number":
                    continue
                if schema_attr["type"] == "string" and value != schema_attr["default"]:
                    drifted_resources[resource["type"]].append(resource)
                    break
                elif schema_attr["type"] == "number" and float(value) != schema_attr["default"]:
                    drifted_resources[resource["type"]].append(resource)
                    break
    return drifted_resources

def get_cost_anomalies(tf_state: Dict, cost_data: Dict) -> Dict[str, List[Dict]]:
    """
    Identifies resources with potential cost anomalies based on historical cost data.
    
    Args:
        tf_state (Dict): The parsed Terraform state JSON.
        cost_data (Dict): A dictionary mapping resource types to their average monthly costs.
    
    Returns:
        Dict[str, List[Dict]]: A dictionary mapping resource types to a list of resources with potential cost anomalies.
    """
    cost_anomalies = defaultdict(list)
    for resource in tf_state["resources"]:
        resource_type = resource["type"]
        if resource_type in cost_data:
            avg_cost = cost_data[resource_type]
            current_cost = get_resource_cost(resource)
            if current_cost > avg_cost * 2:
                cost_anomalies[resource_type].append(resource)
    return cost_anomalies

def get_resource_cost(resource: Dict) -> float:
    """
    Calculates the estimated monthly cost of a resource based on its attributes.
    
    Args:
        resource (Dict): The resource dictionary from the Terraform state.
    
    Returns:
        float: The estimated monthly cost of the resource.
    """
    # Implement your own cost calculation logic here
    # This is a placeholder implementation
    return 100.0

def generate_report(tf_state: Dict, cost_data: Dict) -> str:
    """
    Generates a comprehensive report based on the Terraform state and cost data.
    
    Args:
        tf_state (Dict): The parsed Terraform state JSON.
        cost_data (Dict): A dictionary mapping resource types to their average monthly costs.
    
    Returns:
        str: The generated report as a string.
    """
    report = ""
    
    # Resource counts
    resource_counts = get_resource_counts(tf_state)
    report += "Resource Counts:\n"
    for resource_type, count in resource_counts.items():
        report += f"  {resource_type}: {count}\n"
    report += "\n"
    
    # Drift detection
    drifted_resources = get_resource_drift(tf_state)
    report += "Drifted Resources:\n"
    for resource_type, resources in drifted_resources.items():
        report += f"  {resource_type}: {len(resources)}\n"
    report += "\n"
    
    # Cost anomalies
    cost_anomalies = get_cost_anomalies(tf_state, cost_data)
    report += "Cost Anomalies:\n"
    for resource_type, resources in cost_anomalies.items():
        report += f"  {resource_type}: {len(resources)}\n"
    report += "\n"
    
    return report

def main():
    if len(sys.argv) < 2:
        print("Usage: python terraform_state_analyzer.py <terraform.tfstate>")
        sys.exit(1)
    
    tf_state_file = sys.argv[1]
    
    if not os.path.isfile(tf_state_file):
        print(f"Error: {tf_state_file} does not exist.")
        sys.exit(1)
    
    with open(tf_state_file, "r") as f:
        tf_state = json.load(f)
    
    # Load cost data (replace with your own data source)
    cost_data = {
        "aws_instance": 100.0,
        "aws_s3_bucket": 10.0,
        "aws_lambda_function": 50.0,
        # Add more resource types and their average costs
    }
    
    report = generate_report(tf_state, cost_data)
    print(report)

if __name__ == "__main__":
    main()