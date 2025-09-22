import json
import os
import sys
import boto3
from botocore.exceptions import ClientError

class AnsibleDynamicInventory:
    def __init__(self):
        self.ec2_client = boto3.client('ec2')
        self.inventory = {
            '_meta': {
                'hostvars': {}
            },
            'all': {
                'hosts': [],
                'vars': {}
            },
            'aws': {
                'hosts': [],
                'vars': {}
            },
            'running': {
                'hosts': [],
                'vars': {}
            },
            'stopped': {
                'hosts': [],
                'vars': {}
            }
        }

    def fetch_ec2_instances(self):
        try:
            response = self.ec2_client.describe_instances(
                Filters=[
                    {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}
                ]
            )

            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    private_ip = instance.get('PrivateIpAddress', '')
                    public_ip = instance.get('PublicIpAddress', '')
                    state = instance['State']['Name']
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}

                    host_vars = {
                        'ansible_host': public_ip or private_ip,
                        'instance_id': instance_id,
                        'private_ip': private_ip,
                        'public_ip': public_ip,
                        'state': state,
                        'tags': tags
                    }

                    hostname = tags.get('Name', instance_id)
                    self.inventory['_meta']['hostvars'][hostname] = host_vars
                    self.inventory['all']['hosts'].append(hostname)
                    self.inventory['aws']['hosts'].append(hostname)
                    
                    if state == 'running':
                        self.inventory['running']['hosts'].append(hostname)
                    elif state == 'stopped':
                        self.inventory['stopped']['hosts'].append(hostname)

        except ClientError as e:
            print(f"Error fetching EC2 instances: {e}", file=sys.stderr)

    def get_inventory(self):
        self.fetch_ec2_instances()
        return json.dumps(self.inventory, indent=2)

    def get_host(self, hostname):
        host_vars = self.inventory['_meta']['hostvars'].get(hostname, {})
        return json.dumps(host_vars, indent=2)

def main():
    inventory = AnsibleDynamicInventory()

    if len(sys.argv) == 2:
        if sys.argv[1] == '--list':
            print(inventory.get_inventory())
        elif sys.argv[1] == '--host':
            print(inventory.get_host(sys.argv[2]))
        else:
            print("Invalid argument. Use --list or --host <hostname>", file=sys.stderr)
            sys.exit(1)
    else:
        print("Usage: python dynamic_inventory.py --list or --host <hostname>", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()