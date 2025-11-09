import os
import json
import time
import requests
from flask import Flask, request, jsonify
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

app = Flask(__name__)

# Configure Slack API credentials
SLACK_BOT_TOKEN = os.environ.get('SLACK_BOT_TOKEN')
SLACK_CHANNEL_ID = os.environ.get('SLACK_CHANNEL_ID')

# Configure Jenkins or GitLab API credentials
JENKINS_URL = os.environ.get('JENKINS_URL')
JENKINS_USERNAME = os.environ.get('JENKINS_USERNAME')
JENKINS_PASSWORD = os.environ.get('JENKINS_PASSWORD')

# Configure GitLab API credentials
GITLAB_URL = os.environ.get('GITLAB_URL')
GITLAB_TOKEN = os.environ.get('GITLAB_TOKEN')

# Function to get the latest build status from Jenkins
def get_jenkins_build_status(job_name):
    url = f"{JENKINS_URL}/job/{job_name}/lastBuild/api/json"
    response = requests.get(url, auth=(JENKINS_USERNAME, JENKINS_PASSWORD))
    if response.status_code == 200:
        build_data = json.loads(response.text)
        return build_data['result']
    else:
        return "UNKNOWN"

# Function to get the latest build status from GitLab
def get_gitlab_pipeline_status(project_id, pipeline_id):
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/pipelines/{pipeline_id}"
    headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        pipeline_data = json.loads(response.text)
        return pipeline_data['status']
    else:
        return "UNKNOWN"

# Function to send a message to a Slack channel
def send_slack_message(message, channel=SLACK_CHANNEL_ID):
    client = WebClient(token=SLACK_BOT_TOKEN)
    try:
        response = client.chat_postMessage(
            channel=channel,
            text=message
        )
        print(f"Message sent to Slack channel: {response['message']['text']}")
    except SlackApiError as e:
        print(f"Error sending message to Slack: {e}")

# Function to monitor a Jenkins job
def monitor_jenkins_job(job_name):
    previous_status = None
    while True:
        current_status = get_jenkins_build_status(job_name)
        if current_status != previous_status:
            if current_status == "SUCCESS":
                message = f"Jenkins job '{job_name}' has succeeded!"
            elif current_status == "FAILURE":
                message = f"Jenkins job '{job_name}' has failed!"
            else:
                message = f"Jenkins job '{job_name}' has an unknown status: {current_status}"
            send_slack_message(message)
            previous_status = current_status
        time.sleep(60)  # Check every minute

# Function to monitor a GitLab pipeline
def monitor_gitlab_pipeline(project_id, pipeline_id):
    previous_status = None
    while True:
        current_status = get_gitlab_pipeline_status(project_id, pipeline_id)
        if current_status != previous_status:
            if current_status == "success":
                message = f"GitLab pipeline {pipeline_id} in project {project_id} has succeeded!"
            elif current_status == "failed":
                message = f"GitLab pipeline {pipeline_id} in project {project_id} has failed!"
            else:
                message = f"GitLab pipeline {pipeline_id} in project {project_id} has an unknown status: {current_status}"
            send_slack_message(message)
            previous_status = current_status
        time.sleep(60)  # Check every minute

# Flask route to trigger Jenkins job monitoring
@app.route('/monitor_jenkins_job', methods=['POST'])
def monitor_jenkins_job_route():
    data = request.get_json()
    job_name = data.get('job_name')
    if job_name:
        monitor_jenkins_job(job_name)
        return jsonify({'message': f'Monitoring Jenkins job: {job_name}'}), 200
    else:
        return jsonify({'error': 'Job name is required'}), 400

# Flask route to trigger GitLab pipeline monitoring
@app.route('/monitor_gitlab_pipeline', methods=['POST'])
def monitor_gitlab_pipeline_route():
    data = request.get_json()
    project_id = data.get('project_id')
    pipeline_id = data.get('pipeline_id')
    if project_id and pipeline_id:
        monitor_gitlab_pipeline(project_id, pipeline_id)
        return jsonify({'message': f'Monitoring GitLab pipeline {pipeline_id} in project {project_id}'}), 200
    else:
        return jsonify({'error': 'Project ID and Pipeline ID are required'}), 400

# Main function to run the Flask app
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)