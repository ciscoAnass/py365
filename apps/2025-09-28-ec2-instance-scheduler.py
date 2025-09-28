import boto3
import json
import os
import logging
import datetime
import pytz
from botocore.exceptions import ClientError

class EC2InstanceScheduler:
    def __init__(self):
        self.ec2_client = boto3.client('ec2')
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)

    def get_instances_by_schedule_tag(self):
        try:
            filters = [
                {'Name': 'tag-key', 'Values': ['Schedule']},
                {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}
            ]
            response = self.ec2_client.describe_instances(Filters=filters)
            
            scheduled_instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    schedule_tag = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Schedule'), None)
                    if schedule_tag:
                        scheduled_instances.append({
                            'instance_id': instance['InstanceId'],
                            'schedule': schedule_tag,
                            'current_state': instance['State']['Name']
                        })
            
            return scheduled_instances
        except ClientError as e:
            self.logger.error(f"Error retrieving instances: {e}")
            return []

    def parse_schedule(self, schedule_str):
        try:
            schedule_parts = schedule_str.split(',')
            schedule_config = {}
            
            for part in schedule_parts:
                key, value = part.split('=')
                schedule_config[key.strip()] = value.strip()
            
            return schedule_config
        except Exception as e:
            self.logger.error(f"Error parsing schedule: {e}")
            return None

    def should_change_state(self, schedule_config):
        current_time = datetime.datetime.now(pytz.timezone(schedule_config.get('timezone', 'UTC')))
        
        start_time = datetime.datetime.strptime(schedule_config.get('start', '09:00'), '%H:%M').time()
        end_time = datetime.datetime.strptime(schedule_config.get('end', '17:00'), '%H:%M').time()
        
        days = schedule_config.get('days', 'Mon,Tue,Wed,Thu,Fri').split(',')
        current_day = current_time.strftime('%a')
        
        is_business_hours = (
            current_day in days and
            start_time <= current_time.time() <= end_time
        )
        
        return not is_business_hours

    def manage_instance_state(self, instance_id, current_state, schedule_config):
        try:
            if self.should_change_state(schedule_config):
                if current_state == 'running':
                    self.ec2_client.stop_instances(InstanceIds=[instance_id])
                    self.logger.info(f"Stopping instance {instance_id}")
                elif current_state == 'stopped':
                    self.ec2_client.start_instances(InstanceIds=[instance_id])
                    self.logger.info(f"Starting instance {instance_id}")
        except ClientError as e:
            self.logger.error(f"Error managing instance {instance_id}: {e}")

    def lambda_handler(self, event, context):
        scheduled_instances = self.get_instances_by_schedule_tag()
        
        for instance in scheduled_instances:
            schedule_config = self.parse_schedule(instance['schedule'])
            if schedule_config:
                self.manage_instance_state(
                    instance['instance_id'], 
                    instance['current_state'], 
                    schedule_config
                )

def lambda_handler(event, context):
    scheduler = EC2InstanceScheduler()
    return scheduler.lambda_handler(event, context)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    scheduler = EC2InstanceScheduler()
    scheduler.lambda_handler(None, None)