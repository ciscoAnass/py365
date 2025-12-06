#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Title: azure-resource-group-janitor
# Description: A DevOps automation script for Azure that scans for 'orphaned'
#              resources and generates a report with recommendations for deletion
#              to save costs. This script is designed to be run in a read-only
#              capacity to generate a report, and does not perform any delete
#              operations itself.

# -----------------------------------------------------------------------------
# Pre-requisites:
# 1. Python 3.8+
# 2. Azure CLI installed and configured. Run 'az login' to authenticate.
# 3. Required Python 3rd party libraries. Install them using pip:
#    pip install azure-identity azure-mgmt-resource azure-mgmt-compute azure-mgmt-network azure-mgmt-web
# -----------------------------------------------------------------------------

import os
import sys
import logging
import argparse
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

# Necessary 3rd party library imports
try:
    from azure.identity import DefaultAzureCredential, CredentialUnavailableError
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.web import WebSiteManagementClient
    from azure.core.exceptions import HttpResponseError
except ImportError:
    print("Error: Required Azure SDK libraries are not installed.")
    print("Please run: pip install azure-identity azure-mgmt-resource azure-mgmt-compute azure-mgmt-network azure-mgmt-web")
    sys.exit(1)


# --- Configuration ---
# Default age in days for a snapshot to be considered "old"
DEFAULT_SNAPSHOT_AGE_THRESHOLD_DAYS = 90
# Tag to apply to resources to prevent them from being flagged by this script
DEFAULT_PROTECTION_TAG = "preserve"
# Default filename for the generated report
DEFAULT_REPORT_FILENAME = f"azure_janitor_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"


class AzureJanitor:
    """
    A class to scan an Azure subscription for orphaned resources and generate a report.
    """

    def __init__(self, subscription_id: str, protection_tag: str):
        """
        Initializes the AzureJanitor with necessary clients and settings.

        Args:
            subscription_id (str): The Azure Subscription ID to scan.
            protection_tag (str): The tag name used to mark resources for preservation.
        """
        if not subscription_id:
            raise ValueError("Subscription ID cannot be empty.")

        self.subscription_id = subscription_id
        self.protection_tag = protection_tag
        self.report_data: Dict[str, List[Dict[str, Any]]] = {
            "unattached_disks": [],
            "old_snapshots": [],
            "empty_resource_groups": [],
            "unattached_nics": [],
            "unassociated_public_ips": [],
            "empty_app_service_plans": [],
        }

        logging.info("Attempting to authenticate with Azure...")
        try:
            self.credential = DefaultAzureCredential()
            # Test credential by getting a token
            # self.credential.get_token("https://management.azure.com/.default")
        except CredentialUnavailableError as e:
            logging.error(f"Azure authentication failed. Please run 'az login'. Error: {e}")
            sys.exit(1)
        logging.info("Authentication successful.")

        self._initialize_clients()

    def _initialize_clients(self) -> None:
        """Initializes the various Azure Management clients needed for scanning."""
        logging.info("Initializing Azure Management Clients...")
        try:
            self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
            self.compute_client = ComputeManagementClient(self.credential, self.subscription_id)
            self.network_client = NetworkManagementClient(self.credential, self.subscription_id)
            self.web_client = WebSiteManagementClient(self.credential, self.subscription_id)
            logging.info("Azure Management Clients initialized successfully.")
        except Exception as e:
            logging.error(f"Failed to initialize Azure clients. Check credentials and subscription ID. Error: {e}")
            sys.exit(1)

    def _is_resource_protected(self, resource_tags: Optional[Dict[str, str]]) -> bool:
        """
        Checks if a resource has the protection tag.

        Args:
            resource_tags (Optional[Dict[str, str]]): A dictionary of tags for the resource.

        Returns:
            bool: True if the resource is protected, False otherwise.
        """
        if not resource_tags:
            return False
        return self.protection_tag in resource_tags

    def scan_unattached_disks(self) -> None:
        """Scans for unattached managed disks."""
        logging.info("Starting scan for unattached managed disks...")
        try:
            disks = self.compute_client.disks.list()
            for disk in disks:
                if self._is_resource_protected(disk.tags):
                    logging.info(f"Skipping protected disk: {disk.name}")
                    continue

                # A disk is unattached if its state is 'Unattached' and it's not managed by another resource (like a VM).
                if disk.disk_state == 'Unattached' and disk.managed_by is None:
                    logging.warning(f"Found unattached disk: {disk.name} in RG: {disk.id.split('/')[4]}")
                    disk_info = {
                        "name": disk.name,
                        "id": disk.id,
                        "resource_group": disk.id.split('/')[4],
                        "location": disk.location,
                        "size_gb": disk.disk_size_gb,
                        "sku": disk.sku.name if disk.sku else "N/A",
                        "reason": "Disk state is 'Unattached' and it is not managed by a VM.",
                    }
                    self.report_data["unattached_disks"].append(disk_info)
        except HttpResponseError as e:
            logging.error(f"An error occurred while scanning for disks: {e.message}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during disk scan: {e}")
        logging.info("Finished scan for unattached managed disks.")

    def scan_old_snapshots(self, age_threshold_days: int) -> None:
        """
        Scans for old disk snapshots based on a given age threshold.

        Args:
            age_threshold_days (int): The age in days to consider a snapshot as old.
        """
        logging.info(f"Starting scan for snapshots older than {age_threshold_days} days...")
        threshold_date = datetime.now(timezone.utc) - timedelta(days=age_threshold_days)
        try:
            snapshots = self.compute_client.snapshots.list()
            for snapshot in snapshots:
                if self._is_resource_protected(snapshot.tags):
                    logging.info(f"Skipping protected snapshot: {snapshot.name}")
                    continue

                if snapshot.time_created < threshold_date:
                    logging.warning(f"Found old snapshot: {snapshot.name} created on {snapshot.time_created.date()}")
                    snapshot_info = {
                        "name": snapshot.name,
                        "id": snapshot.id,
                        "resource_group": snapshot.id.split('/')[4],
                        "location": snapshot.location,
                        "created_time": snapshot.time_created.isoformat(),
                        "size_gb": snapshot.disk_size_gb,
                        "reason": f"Snapshot created on {snapshot.time_created.date()} is older than the {age_threshold_days}-day threshold.",
                    }
                    self.report_data["old_snapshots"].append(snapshot_info)
        except HttpResponseError as e:
            logging.error(f"An error occurred while scanning for snapshots: {e.message}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during snapshot scan: {e}")
        logging.info("Finished scan for old snapshots.")

    def scan_empty_resource_groups(self) -> None:
        """Scans for resource groups that contain no resources."""
        logging.info("Starting scan for empty resource groups...")
        try:
            resource_groups = self.resource_client.resource_groups.list()
            for rg in resource_groups:
                if self._is_resource_protected(rg.tags):
                    logging.info(f"Skipping protected resource group: {rg.name}")
                    continue

                resources = list(self.resource_client.resources.list_by_resource_group(rg.name))
                if not resources:
                    logging.warning(f"Found empty resource group: {rg.name}")
                    rg_info = {
                        "name": rg.name,
                        "id": rg.id,
                        "location": rg.location,
                        "reason": "The resource group contains no resources.",
                    }
                    self.report_data["empty_resource_groups"].append(rg_info)
        except HttpResponseError as e:
            logging.error(f"An error occurred while scanning for resource groups: {e.message}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during resource group scan: {e}")
        logging.info("Finished scan for empty resource groups.")

    def scan_unattached_nics(self) -> None:
        """Scans for Network Interface Cards (NICs) not attached to a VM."""
        logging.info("Starting scan for unattached Network Interfaces (NICs)...")
        try:
            nics = self.network_client.network_interfaces.list_all()
            for nic in nics:
                if self._is_resource_protected(nic.tags):
                    logging.info(f"Skipping protected NIC: {nic.name}")
                    continue

                # A NIC is unattached if its virtual_machine attribute is None
                if nic.virtual_machine is None:
                    logging.warning(f"Found unattached NIC: {nic.name} in RG: {nic.id.split('/')[4]}")
                    nic_info = {
                        "name": nic.name,
                        "id": nic.id,
                        "resource_group": nic.id.split('/')[4],
                        "location": nic.location,
                        "reason": "NIC is not associated with any virtual machine.",
                    }
                    self.report_data["unattached_nics"].append(nic_info)
        except HttpResponseError as e:
            logging.error(f"An error occurred while scanning for NICs: {e.message}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during NIC scan: {e}")
        logging.info("Finished scan for unattached NICs.")

    def scan_unassociated_public_ips(self) -> None:
        """Scans for Public IP addresses not associated with any resource."""
        logging.info("Starting scan for unassociated Public IPs...")
        try:
            public_ips = self.network_client.public_ip_addresses.list_all()
            for ip in public_ips:
                if self._is_resource_protected(ip.tags):
                    logging.info(f"Skipping protected Public IP: {ip.name}")
                    continue

                # A Public IP is unassociated if its ip_configuration is None
                if ip.ip_configuration is None:
                    logging.warning(f"Found unassociated Public IP: {ip.name} with IP: {ip.ip_address}")
                    ip_info = {
                        "name": ip.name,
                        "id": ip.id,
                        "resource_group": ip.id.split('/')[4],
                        "location": ip.location,
                        "ip_address": ip.ip_address,
                        "reason": "Public IP address is not associated with a NIC or Load Balancer.",
                    }
                    self.report_data["unassociated_public_ips"].append(ip_info)
        except HttpResponseError as e:
            logging.error(f"An error occurred while scanning for Public IPs: {e.message}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during Public IP scan: {e}")
        logging.info("Finished scan for unassociated Public IPs.")

    def scan_empty_app_service_plans(self) -> None:
        """Scans for App Service Plans that have no apps deployed to them."""
        logging.info("Starting scan for empty App Service Plans...")
        try:
            asps = self.web_client.app_service_plans.list()
            for asp in asps:
                if self._is_resource_protected(asp.tags):
                    logging.info(f"Skipping protected App Service Plan: {asp.name}")
                    continue

                # The number_of_sites property indicates how many apps are in the plan.
                if asp.number_of_sites == 0:
                    logging.warning(f"Found empty App Service Plan: {asp.name} in RG: {asp.resource_group}")
                    asp_info = {
                        "name": asp.name,
                        "id": asp.id,
                        "resource_group": asp.resource_group,
                        "location": asp.location,
                        "sku": asp.sku.name,
                        "reason": "App Service Plan has no applications deployed to it.",
                    }
                    self.report_data["empty_app_service_plans"].append(asp_info)
        except HttpResponseError as e:
            logging.error(f"An error occurred while scanning App Service Plans: {e.message}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during App Service Plan scan: {e}")
        logging.info("Finished scan for empty App Service Plans.")

    def run_all_scans(self, snapshot_age_days: int) -> None:
        """
        Runs all available scans to find various types of orphaned resources.

        Args:
            snapshot_age_days (int): The age threshold for old snapshots.
        """
        logging.info(f"--- Starting Azure Janitor scan for subscription: {self.subscription_id} ---")
        self.scan_unattached_disks()
        self.scan_old_snapshots(snapshot_age_days)
        self.scan_empty_resource_groups()
        self.scan_unattached_nics()
        self.scan_unassociated_public_ips()
        self.scan_empty_app_service_plans()
        logging.info("--- All scans completed ---")

    def generate_report(self, output_filename: str) -> None:
        """
        Generates a detailed text report of all findings and saves it to a file.

        Args:
            output_filename (str): The path to the file where the report will be saved.
        """
        logging.info(f"Generating report at: {output_filename}")
        total_issues = sum(len(v) for v in self.report_data.values())

        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(" Azure Janitor Orphaned Resources Report\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Subscription ID: {self.subscription_id}\n")
            f.write(f"Report Generated On: {datetime.now().isoformat()}\n")
            f.write(f"Total Issues Found: {total_issues}\n")
            f.write(f"Protection Tag: '{self.protection_tag}'\n")
            f.write("\n" + "-" * 80 + "\n")
            f.write(" Summary of Findings\n")
            f.write("-" * 80 + "\n")
            for key, value in self.report_data.items():
                f.write(f"- {key.replace('_', ' ').title()}: {len(value)} found\n")
            f.write("-" * 80 + "\n\n")

            for category, items in self.report_data.items():
                title = category.replace('_', ' ').title()
                f.write("=" * 80 + "\n")
                f.write(f" {title} ({len(items)} found)\n")
                f.write("=" * 80 + "\n\n")

                if not items:
                    f.write("No issues found in this category.\n\n")
                    continue

                for item in items:
                    for key, value in item.items():
                        f.write(f"{key.replace('_', ' ').title():<20}: {value}\n")
                    f.write("-" * 40 + "\n\n")
        
        logging.info("Report generation complete.")
        print(f"\nReport successfully generated: {output_filename}")
        print(f"Total potential cost-saving issues found: {total_issues}")


def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments for the script.

    Returns:
        argparse.Namespace: An object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Azure Janitor: A script to find orphaned resources in an Azure subscription.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-s", "--subscription-id",
        required=True,
        help="The Azure Subscription ID to scan."
    )
    parser.add_argument(
        "-a", "--snapshot-age-days",
        type=int,
        default=DEFAULT_SNAPSHOT_AGE_THRESHOLD_DAYS,
        help=f"The age in days to consider a snapshot 'old'. Default: {DEFAULT_SNAPSHOT_AGE_THRESHOLD_DAYS}."
    )
    parser.add_argument(
        "-t", "--protection-tag",
        type=str,
        default=DEFAULT_PROTECTION_TAG,
        help=f"The tag name to identify resources that should be ignored. Default: '{DEFAULT_PROTECTION_TAG}'."
    )
    parser.add_argument(
        "-o", "--output-file",
        type=str,
        default=DEFAULT_REPORT_FILENAME,
        help=f"The filename for the output report. Default: '{DEFAULT_REPORT_FILENAME}'."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging to the console."
    )
    return parser.parse_args()


def setup_logging(verbose: bool) -> None:
    """
    Configures the logging format and level.

    Args:
        verbose (bool): If True, sets the console logging level to INFO. Otherwise, WARNING.
    """
    log_level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        stream=sys.stdout
    )


def main() -> None:
    """
    Main function to execute the Azure Janitor script.
    """
    args = parse_arguments()
    setup_logging(args.verbose)

    print("--- Azure Resource Group Janitor ---")
    print("This script will scan for potential orphaned resources.")
    print("Ensure you are authenticated with Azure CLI ('az login').")
    print(f"Scanning Subscription ID: {args.subscription_id}")

    try:
        janitor = AzureJanitor(
            subscription_id=args.subscription_id,
            protection_tag=args.protection_tag
        )
        janitor.run_all_scans(snapshot_age_days=args.snapshot_age_days)
        janitor.generate_report(output_filename=args.output_file)
    except ValueError as e:
        logging.error(f"Configuration Error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred during script execution: {e}", exc_info=True)
        sys.exit(1)
    
    print("\nScript execution finished.")


if __name__ == "__main__":
    main()
