import argparse
import sys
import os
import collections

# It's necessary to specify the Google Cloud client libraries that will be used.
# These libraries are not part of the Python standard library.
# They can be installed via pip:
# pip install google-cloud-resourcemanager google-cloud-iam
from google.cloud import resourcemanager_v3
from google.cloud import iam_admin_v1
from google.api_core import exceptions
from google.auth import default as google_auth_default

PRIMITIVE_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/viewer",
}

ROLE_RECOMMENDATIONS = {
    "roles/owner": [
        "roles/compute.admin",
        "roles/storage.admin",
        "roles/cloudfunctions.admin",
        "roles/run.admin",
        "roles/container.admin",
        "roles/artifactregistry.admin",
        "roles/cloudbuild.builds.editor",
        "roles/datastore.owner",
        "roles/cloudsql.admin",
        "roles/iam.serviceAccountAdmin",
        "roles/logging.admin",
        "roles/monitoring.admin",
        "roles/networkmanagement.admin",
        "roles/cloudasset.viewer",
        "roles/secretmanager.admin",
        "roles/cloudkms.admin",
        "roles/firebase.admin",
        "roles/appengine.admin",
        "roles/dataflow.admin",
        "roles/bigquery.admin",
        "roles/pubsub.admin",
        "roles/eventarc.admin",
        "roles/cloudscheduler.admin",
        "roles/tasks.admin",
        "roles/workflows.admin",
        "roles/apigee.admin",
        "roles/artifactregistry.writer",
        "roles/billing.admin",
        "roles/compute.networkAdmin",
        "roles/dataproc.admin",
        "roles/datafusion.admin",
        "roles/dialogflow.admin",
        "roles/documentai.admin",
        "roles/healthcare.admin",
        "roles/iot.admin",
        "roles/k8s.admin",
        "roles/logging.configWriter",
        "roles/memcache.admin",
        "roles/metastore.admin",
        "roles/ml.admin",
        "roles/notebooks.admin",
        "roles/orchestration.admin",
        "roles/project.owner",
        "roles/resourcemanager.organizationAdmin",
        "roles/secretmanager.secretAccessor",
        "roles/serviceusage.serviceUsageAdmin",
        "roles/source.admin",
        "roles/spanner.admin",
        "roles/tpu.admin",
        "roles/trace.agent",
        "roles/vpcaccess.admin",
        "roles/websecurityscanner.admin",
        "roles/workflows.viewer",
        "roles/dataplex.admin",
        "roles/migrationcenter.admin",
        "roles/dataqna.admin",
        "roles/gkehub.admin",
        "roles/alloydb.admin",
        "roles/baremetalsolution.admin",
        "roles/batch.admin",
        "roles/clouddeploy.admin",
        "roles/datastream.admin",
        "roles/discoveryengine.admin",
        "roles/eventarc.eventReceiver",
        "roles/looker.admin",
        "roles/managedidentities.admin",
        "roles/media.admin",
        "roles/networkconnectivity.admin",
        "roles/networksecurity.admin",
        "roles/privateca.admin",
        "roles/recommender.admin",
        "roles/retail.admin",
        "roles/vision.admin",
        "roles/videointelligence.admin",
        "roles/language.admin",
        "roles/translation.admin",
        "roles/automl.admin",
        "roles/speech.admin",
        "roles/texttospeech.admin",
        "roles/datafusion.viewer",
        "roles/dataproc.viewer",
        "roles/cloudkms.viewer",
        "roles/secretmanager.viewer",
        "roles/cloudasset.owner",
        "roles/cloudasset.serviceAccountOwner",
    ],
    "roles/editor": [
        "roles/compute.instanceAdmin.v1",
        "roles/compute.networkUser",
        "roles/storage.objectAdmin",
        "roles/cloudfunctions.developer",
        "roles/run.developer",
        "roles/container.developer",
        "roles/artifactregistry.writer",
        "roles/bigquery.dataEditor",
        "roles/pubsub.editor",
        "roles/logging.logWriter",
        "roles/monitoring.metricWriter",
        "roles/cloudbuild.builds.editor",
        "roles/datastore.editor",
        "roles/cloudsql.editor",
        "roles/iam.serviceAccountUser",
        "roles/secretmanager.secretAccessor",
        "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "roles/appengine.appAdmin",
        "roles/dataflow.developer",
        "roles/eventarc.eventReceiver",
        "roles/artifactregistry.writer",
        "roles/bigquery.metadataEditor",
        "roles/cloudiot.deviceManager",
        "roles/cloudsql.client",
        "roles/compute.admin",
        "roles/container.admin",
        "roles/dataproc.editor",
        "roles/dialogflow.editor",
        "roles/documentai.editor",
        "roles/gkehub.editor",
        "roles/healthcare.editor",
        "roles/iam.roleEditor",
        "roles/k8s.editor",
        "roles/logging.viewer",
        "roles/memcache.editor",
        "roles/ml.developer",
        "roles/notebooks.editor",
        "roles/pubsub.viewer",
        "roles/spanner.editor",
        "roles/tpu.editor",
        "roles/trace.admin",
        "roles/workflows.editor",
        "roles/alloydb.editor",
        "roles/baremetalsolution.editor",
        "roles/batch.editor",
        "roles/clouddeploy.editor",
        "roles/datastream.editor",
        "roles/discoveryengine.editor",
        "roles/eventarc.admin",
        "roles/looker.editor",
        "roles/managedidentities.editor",
        "roles/media.editor",
        "roles/networkconnectivity.editor",
        "roles/networksecurity.editor",
        "roles/privateca.editor",
        "roles/recommender.editor",
        "roles/retail.editor",
        "roles/vision.editor",
        "roles/videointelligence.editor",
        "roles/language.editor",
        "roles/translation.editor",
        "roles/automl.editor",
        "roles/speech.editor",
        "roles/texttospeech.editor",
        "roles/artifactregistry.reader",
        "roles/serviceusage.serviceUsageViewer",
        "roles/source.reader",
        "roles/spanner.viewer",
    ],
    "roles/viewer": [
        "roles/compute.viewer",
        "roles/storage.objectViewer",
        "roles/cloudfunctions.viewer",
        "roles/run.viewer",
        "roles/container.viewer",
        "roles/artifactregistry.reader",
        "roles/bigquery.dataViewer",
        "roles/pubsub.viewer",
        "roles/logging.viewer",
        "roles/monitoring.viewer",
        "roles/cloudbuild.builds.viewer",
        "roles/datastore.viewer",
        "roles/cloudsql.viewer",
        "roles/iam.viewer",
        "roles/secretmanager.viewer",
        "roles/cloudkms.viewer",
        "roles/appengine.viewer",
        "roles/dataflow.viewer",
        "roles/eventarc.viewer",
        "roles/cloudasset.viewer",
        "roles/dataproc.viewer",
        "roles/dialogflow.viewer",
        "roles/documentai.viewer",
        "roles/gkehub.viewer",
        "roles/healthcare.viewer",
        "roles/k8s.viewer",
        "roles/logging.viewer",
        "roles/memcache.viewer",
        "roles/ml.viewer",
        "roles/notebooks.viewer",
        "roles/pubsub.viewer",
        "roles/spanner.viewer",
        "roles/tpu.viewer",
        "roles/trace.viewer",
        "roles/workflows.viewer",
        "roles/alloydb.viewer",
        "roles/baremetalsolution.viewer",
        "roles/batch.viewer",
        "roles/clouddeploy.viewer",
        "roles/datastream.viewer",
        "roles/discoveryengine.viewer",
        "roles/eventarc.viewer",
        "roles/looker.viewer",
        "roles/managedidentities.viewer",
        "roles/media.viewer",
        "roles/networkconnectivity.viewer",
        "roles/networksecurity.viewer",
        "roles/privateca.viewer",
        "roles/recommender.viewer",
        "roles/retail.viewer",
        "roles/vision.viewer",
        "roles/videointelligence.viewer",
        "roles/language.viewer",
        "roles/translation.viewer",
        "roles/automl.viewer",
        "roles/speech.viewer",
        "roles/texttospeech.viewer",
    ],
}

class IAMFinding:
    def __init__(self, service_account_email: str, primitive_role: str,
                 resource_type: str, resource_id: str, recommendations: list):
        self.service_account_email = service_account_email
        self.primitive_role = primitive_role
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.recommendations = recommendations

    def __str__(self):
        rec_str = ", ".join(self.recommendations) if self.recommendations else "N/A"
        return (f"  - Service Account: {self.service_account_email}\n"
                f"    Resource: {self.resource_type} '{self.resource_id}'\n"
                f"    Primitive Role: {self.primitive_role}\n"
                f"    Recommendation(s): {rec_str}\n")

    def to_dict(self):
        return {
            "service_account_email": self.service_account_email,
            "primitive_role": self.primitive_role,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "recommendations": self.recommendations,
        }

class GCPIamRoleAuditor:
    def __init__(self):
        self.resourcemanager_client = None
        self.iam_admin_client = None
        self._initialize_clients()
        self.findings = []
        self.processed_projects_count = 0
        self.total_projects_count = 0

    def _initialize_clients(self):
        try:
            credentials, project = google_auth_default()
            self.resourcemanager_client = resourcemanager_v3.ProjectsClient(credentials=credentials)
            self.iam_admin_client = iam_admin_v1.IAMClient(credentials=credentials)
            self._log_info("Successfully initialized GCP client libraries.")
        except Exception as e:
            self._log_error(f"Failed to initialize GCP client libraries: {e}")
            self._log_error("Please ensure you have authenticated to GCP (e.g., using 'gcloud auth application-default login').")
            sys.exit(1)

    def _log_info(self, message: str):
        print(f"[INFO] {message}", file=sys.stderr)

    def _log_warning(self, message: str):
        print(f"[WARNING] {message}", file=sys.stderr)

    def _log_error(self, message: str):
        print(f"[ERROR] {message}", file=sys.stderr)

    def _get_organization_iam_policy(self, organization_id: str):
        resource_name = f"organizations/{organization_id}"
        self._log_info(f"Attempting to retrieve IAM policy for organization: {organization_id}")
        try:
            policy = self.resourcemanager_client.get_iam_policy(resource=resource_name)
            self._log_info(f"Successfully retrieved IAM policy for organization: {organization_id}")
            return policy
        except exceptions.PermissionDenied:
            self._log_error(f"Permission denied to get IAM policy for organization '{organization_id}'. "
                            "Ensure the service account or user running this script has "
                            "'roles/resourcemanager.organizationViewer' and 'roles/iam.securityReviewer' "
                            "or equivalent permissions at the organization level.")
        except exceptions.NotFound:
            self._log_error(f"Organization '{organization_id}' not found. Please verify the ID.")
        except exceptions.GoogleAPIError as e:
            self._log_error(f"Google API error fetching organization policy for '{organization_id}': {e}")
        except Exception as e:
            self._log_error(f"An unexpected error occurred fetching organization policy for '{organization_id}': {e}")
        return None

    def _list_projects_in_organization(self, organization_id: str):
        projects = []
        try:
            project_iterator = self.resourcemanager_client.list_projects(
                parent=f"organizations/{organization_id}"
            )
            
            for project in project_iterator:
                if project.state == resourcemanager_v3.Project.State.ACTIVE:
                    projects.append(project.project_id)
            self._log_info(f"Found {len(projects)} active projects in organization {organization_id}.")
        except exceptions.PermissionDenied:
            self._log_error(f"Permission denied to list projects in organization '{organization_id}'. "
                            "Ensure the service account or user has 'resourcemanager.projects.list' "
                            "permission at the organization level.")
            return []
        except exceptions.NotFound:
            self._log_error(f"Organization '{organization_id}' not found during project listing.")
            return []
        except exceptions.GoogleAPIError as e:
            self._log_error(f"Google API error listing projects in organization '{organization_id}': {e}")
            return []
        except Exception as e:
            self._log_error(f"An unexpected error occurred listing projects in organization '{organization_id}': {e}")
            return []
        return projects

    def _get_project_iam_policy(self, project_id: str):
        resource_name = f"projects/{project_id}"
        try:
            policy = self.resourcemanager_client.get_iam_policy(resource=resource_name)
            return policy
        except exceptions.PermissionDenied:
            self._log_warning(f"Permission denied to get IAM policy for project '{project_id}'. "
                              "Skipping this project. Ensure 'resourcemanager.projects.getIamPolicy' "
                              "permission is granted.")
        except exceptions.NotFound:
            self._log_warning(f"Project '{project_id}' not found when attempting to retrieve policy. "
                              "It might have been deleted or there's a transient issue. Skipping.")
        except exceptions.GoogleAPIError as e:
            self._log_warning(f"Google API error fetching project policy for '{project_id}': {e}. Skipping.")
        except Exception as e:
            self._log_warning(f"An unexpected error occurred fetching project policy for '{project_id}': {e}. Skipping.")
        return None

    def _list_service_accounts_in_project(self, project_id: str):
        service_accounts = []
        project_name = f"projects/{project_id}"
        try:
            service_account_iterator = self.iam_admin_client.list_service_accounts(
                name=project_name
            )
            for sa in service_account_iterator:
                service_accounts.append(sa.email)
            self._log_info(f"Found {len(service_accounts)} service accounts in project {project_id}.")
        except exceptions.PermissionDenied:
            self._log_warning(f"Permission denied to list service accounts in project '{project_id}'. "
                              "Skipping this project for service account enumeration. Ensure "
                              "'iam.serviceAccounts.list' permission is granted.")
            return []
        except exceptions.NotFound:
            self._log_warning(f"Project '{project_id}' not found during service account listing. Skipping.")
            return []
        except exceptions.GoogleAPIError as e:
            self._log_warning(f"Google API error listing service accounts in project '{project_id}': {e}. Skipping.")
            return []
        except Exception as e:
            self._log_warning(f"An unexpected error occurred listing service accounts in project '{project_id}': {e}. Skipping.")
            return []
        return service_accounts

    def _is_service_account(self, member: str) -> bool:
        return member.startswith("serviceAccount:")

    def _get_service_account_email_from_member(self, member: str) -> str:
        if self._is_service_account(member):
            return member.split(":")[1]
        return ""

    def _recommend_granular_roles(self, primitive_role: str) -> list:
        return ROLE_RECOMMENDATIONS.get(primitive_role, [])

    def _analyze_policy_bindings(self, policy, resource_id: str, resource_type: str):
        if not policy or not hasattr(policy, 'bindings'):
            self._log_warning(f"Policy for {resource_type} '{resource_id}' is invalid or empty. Skipping analysis.")
            return

        for binding in policy.bindings:
            role = binding.role
            if role in PRIMITIVE_ROLES:
                for member in binding.members:
                    if self._is_service_account(member):
                        sa_email = self._get_service_account_email_from_member(member)
                        recommendations = self._recommend_granular_roles(role)
                        self.findings.append(IAMFinding(
                            service_account_email=sa_email,
                            primitive_role=role,
                            resource_type=resource_type,
                            resource_id=resource_id,
                            recommendations=recommendations
                        ))
                        self._log_info(f"FLAGGED: Service account '{sa_email}' has primitive role '{role}' "
                                       f"on {resource_type} '{resource_id}'.")

    def scan_organization(self, organization_id: str):
        self._log_info(f"Initiating scan for GCP Organization: {organization_id}")
        self.findings = []
        self.processed_projects_count = 0

        org_policy = self._get_organization_iam_policy(organization_id)
        if org_policy:
            self._log_info(f"Analyzing organization-level policy for '{organization_id}'.")
            self._analyze_policy_bindings(org_policy, organization_id, "organization")
        else:
            self._log_warning(f"Could not retrieve organization-level policy for '{organization_id}'. "
                              "Skipping organization-level policy analysis.")

        project_ids = self._list_projects_in_organization(organization_id)
        self.total_projects_count = len(project_ids)
        self._log_info(f"Starting project-level policy and service account scan for {self.total_projects_count} projects.")

        for project_id in project_ids:
            self.processed_projects_count += 1
            self._log_info(f"[{self.processed_projects_count}/{self.total_projects_count}] Processing project: {project_id}")

            project_policy = self._get_project_iam_policy(project_id)
            if project_policy:
                self._analyze_policy_bindings(project_policy, project_id, "project")
            else:
                self._log_warning(f"Skipping policy analysis for project '{project_id}' due to earlier errors.")

            service_accounts_in_project = self._list_service_accounts_in_project(project_id)
            if not service_accounts_in_project:
                self._log_info(f"No service accounts found or accessible in project '{project_id}'.")

        self._log_info(f"Scan complete for Organization: {organization_id}.")
        self._log_info(f"Found {len(self.findings)} potential issues.")
        return self.findings

    def generate_report(self, findings: list):
        if not findings:
            return "\n*** GCP IAM Role Audit Report ***\n\nNo primitive roles found assigned to service accounts.\n"

        report_lines = ["\n*** GCP IAM Role Audit Report ***\n"]
        report_lines.append(f"Total Primitive Roles Found for Service Accounts: {len(findings)}\n")
        report_lines.append("Details:\n")

        for i, finding in enumerate(findings):
            report_lines.append(f"Issue #{i + 1}:")
            report_lines.append(str(finding))
            report_lines.append("-" * 80)

        report_lines.append("\n*** End of Report ***\n")
        report_lines.append("Recommendations for primitive roles aim to replace broad access "
                            "with the principle of least privilege. "
                            "Review each recommendation carefully and choose roles that "
                            "precisely match the service account's required permissions.")
        return "\n".join(report_lines)

def _validate_organization_id(org_id: str) -> bool:
    if not org_id:
        print("[ERROR] Organization ID cannot be empty.", file=sys.stderr)
        return False
    if not org_id.isdigit():
        print("[ERROR] Organization ID must be a numeric string.", file=sys.stderr)
        return False
    return True

def main():
    parser = argparse.ArgumentParser(
        description="Scans a Google Cloud Platform organization for primitive "
                    "roles (Owner, Editor, Viewer) assigned to service accounts "
                    "and recommends more granular predefined roles."
    )
    parser.add_argument(
        "--organization-id",
        type=str,
        required=True,
        help="The numeric ID of the GCP organization to scan. "
             "Example: 123456789012"
    )

    args = parser.parse_args()

    organization_id = args.organization_id

    if not _validate_organization_id(organization_id):
        sys.exit(1)

    print(f"Starting GCP IAM Role Auditor for Organization ID: {organization_id}")
    print("Ensure your environment is authenticated to GCP (e.g., 'gcloud auth application-default login').")
    print("Required permissions: resourcemanager.organizations.get, resourcemanager.projects.list, "
          "resourcemanager.projects.getIamPolicy, iam.serviceAccounts.list, iam.securityReviewer.")
    print("-" * 100)

    auditor = GCPIamRoleAuditor()
    try:
        all_findings = auditor.scan_organization(organization_id)
        report = auditor.generate_report(all_findings)
        print("\n" + "=" * 100)
        print("Final Audit Report:")
        print("=" * 100)
        print(report)
        print("=" * 100)
    except KeyboardInterrupt:
        auditor._log_info("Scan interrupted by user. Generating partial report.")
        report = auditor.generate_report(auditor.findings)
        print("\n" + "=" * 100)
        print("Partial Audit Report (Interrupted):")
        print("=" * 100)
        print(report)
        print("=" * 100)
    except Exception as e:
        auditor._log_error(f"An unhandled error occurred during the scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()