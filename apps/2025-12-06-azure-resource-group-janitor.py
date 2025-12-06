import os
import datetime
import json
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient

def get_azure_credentials():
    tenant_id = os.environ.get('AZURE_TENANT_ID')
    client_id = os.environ.get('AZURE_CLIENT_ID')
    client_secret = os.environ.get('AZURE_CLIENT_SECRET')
    
    credentials = ServicePrincipalCredentials(
        client_id=client_id,
        secret=client_secret,
        tenant=tenant_id
    )
    
    return credentials

def get_resource_groups(credentials):
    resource_client = ResourceManagementClient(credentials, subscription_id)
    resource_groups = list(resource_client.resource_groups.list())
    return resource_groups

def get_unattached_disks(credentials):
    compute_client = ComputeManagementClient(credentials, subscription_id)
    unattached_disks = []
    
    for disk in compute_client.disks.list():
        if not disk.managed_by:
            unattached_disks.append(disk)
    
    return unattached_disks

def get_old_snapshots(credentials):
    compute_client = ComputeManagementClient(credentials, subscription_id)
    old_snapshots = []
    
    for snapshot in compute_client.snapshots.list():
        if (datetime.datetime.now() - snapshot.time_created).days > 30:
            old_snapshots.append(snapshot)
    
    return old_snapshots

def get_empty_resource_groups(credentials):
    resource_client = ResourceManagementClient(credentials, subscription_id)
    empty_resource_groups = []
    
    for rg in resource_client.resource_groups.list():
        if not list(resource_client.resources.list_by_resource_group(rg.name)):
            empty_resource_groups.append(rg)
    
    return empty_resource_groups

def generate_report(unattached_disks, old_snapshots, empty_resource_groups):
    report = {
        'unattached_disks': [],
        'old_snapshots': [],
        'empty_resource_groups': []
    }
    
    for disk in unattached_disks:
        report['unattached_disks'].append({
            'name': disk.name,
            'size': disk.disk_size_gb,
            'location': disk.location
        })
    
    for snapshot in old_snapshots:
        report['old_snapshots'].append({
            'name': snapshot.name,
            'size': snapshot.disk_size_gb,
            'location': snapshot.location,
            'age': (datetime.datetime.now() - snapshot.time_created).days
        })
    
    for rg in empty_resource_groups:
        report['empty_resource_groups'].append({
            'name': rg.name,
            'location': rg.location
        })
    
    return report

def delete_resources(credentials, report):
    resource_client = ResourceManagementClient(credentials, subscription_id)
    compute_client = ComputeManagementClient(credentials, subscription_id)
    
    for disk in report['unattached_disks']:
        compute_client.disks.delete(disk_name=disk['name'], resource_group_name=disk['location'])
    
    for snapshot in report['old_snapshots']:
        compute_client.snapshots.delete(snapshot_name=snapshot['name'], resource_group_name=snapshot['location'])
    
    for rg in report['empty_resource_groups']:
        resource_client.resource_groups.delete(rg_name=rg['name'])

def main():
    global subscription_id
    subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID')
    
    credentials = get_azure_credentials()
    
    unattached_disks = get_unattached_disks(credentials)
    old_snapshots = get_old_snapshots(credentials)
    empty_resource_groups = get_empty_resource_groups(credentials)
    
    report = generate_report(unattached_disks, old_snapshots, empty_resource_groups)
    
    print(json.dumps(report, indent=2))
    
    delete_resources(credentials, report)

if __name__ == '__main__':
    main()