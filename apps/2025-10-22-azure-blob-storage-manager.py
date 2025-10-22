import os
import sys
import argparse
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

class AzureBlobStorageManager:
    def __init__(self, connection_string):
        self.blob_service_client = BlobServiceClient.from_connection_string(connection_string)

    def create_container(self, container_name):
        try:
            container_client = self.blob_service_client.create_container(container_name)
            print(f"Container '{container_name}' created successfully.")
        except ResourceExistsError:
            print(f"Container '{container_name}' already exists.")

    def delete_container(self, container_name):
        try:
            container_client = self.blob_service_client.get_container_client(container_name)
            container_client.delete_container()
            print(f"Container '{container_name}' deleted successfully.")
        except ResourceNotFoundError:
            print(f"Container '{container_name}' not found.")

    def list_containers(self):
        containers = self.blob_service_client.list_containers()
        print("Available Containers:")
        for container in containers:
            print(f"- {container.name}")

    def upload_blob(self, container_name, local_file_path, blob_name=None):
        try:
            container_client = self.blob_service_client.get_container_client(container_name)
            
            if not blob_name:
                blob_name = os.path.basename(local_file_path)
            
            blob_client = container_client.get_blob_client(blob_name)
            
            with open(local_file_path, "rb") as data:
                blob_client.upload_blob(data, overwrite=True)
            
            print(f"File '{local_file_path}' uploaded to container '{container_name}' as '{blob_name}'.")
        except FileNotFoundError:
            print(f"Local file '{local_file_path}' not found.")
        except ResourceNotFoundError:
            print(f"Container '{container_name}' not found.")

    def download_blob(self, container_name, blob_name, local_file_path=None):
        try:
            container_client = self.blob_service_client.get_container_client(container_name)
            blob_client = container_client.get_blob_client(blob_name)
            
            if not local_file_path:
                local_file_path = blob_name
            
            with open(local_file_path, "wb") as file:
                download_stream = blob_client.download_blob()
                file.write(download_stream.readall())
            
            print(f"Blob '{blob_name}' downloaded to '{local_file_path}'.")
        except ResourceNotFoundError:
            print(f"Blob '{blob_name}' not found in container '{container_name}'.")

    def list_blobs(self, container_name):
        try:
            container_client = self.blob_service_client.get_container_client(container_name)
            blobs = container_client.list_blobs()
            
            print(f"Blobs in container '{container_name}':")
            for blob in blobs:
                print(f"- {blob.name}")
        except ResourceNotFoundError:
            print(f"Container '{container_name}' not found.")

    def delete_blob(self, container_name, blob_name):
        try:
            container_client = self.blob_service_client.get_container_client(container_name)
            blob_client = container_client.get_blob_client(blob_name)
            
            blob_client.delete_blob()
            print(f"Blob '{blob_name}' deleted from container '{container_name}'.")
        except ResourceNotFoundError:
            print(f"Blob '{blob_name}' not found in container '{container_name}'.")

def main():
    parser = argparse.ArgumentParser(description="Azure Blob Storage Manager")
    parser.add_argument("--connection-string", required=True, help="Azure Storage Account Connection String")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Create Container
    create_container_parser = subparsers.add_parser("create-container", help="Create a new container")
    create_container_parser.add_argument("container_name", help="Name of the container")
    
    # Delete Container
    delete_container_parser = subparsers.add_parser("delete-container", help="Delete a container")
    delete_container_parser.add_argument("container_name", help="Name of the container")
    
    # List Containers
    subparsers.add_parser("list-containers", help="List all containers")
    
    # Upload Blob
    upload_blob_parser = subparsers.add_parser("upload", help="Upload a file to a container")
    upload_blob_parser.add_argument("container_name", help="Name of the container")
    upload_blob_parser.add_argument("local_file_path", help="Path to the local file")
    upload_blob_parser.add_argument("--blob-name", help="Optional blob name (default: filename)")
    
    # Download Blob
    download_blob_parser = subparsers.add_parser("download", help="Download a blob from a container")
    download_blob_parser.add_argument("container_name", help="Name of the container")
    download_blob_parser.add_argument("blob_name", help="Name of the blob")
    download_blob_parser.add_argument("--local-path", help="Optional local file path")
    
    # List Blobs
    list_blobs_parser = subparsers.add_parser("list-blobs", help="List blobs in a container")
    list_blobs_parser.add_argument("container_name", help="Name of the container")
    
    # Delete Blob
    delete_blob_parser = subparsers.add_parser("delete-blob", help="Delete a blob from a container")
    delete_blob_parser.add_argument("container_name", help="Name of the container")
    delete_blob_parser.add_argument("blob_name", help="Name of the blob")
    
    args = parser.parse_args()
    
    try:
        manager = AzureBlobStorageManager(args.connection_string)
        
        if args.command == "create-container":
            manager.create_container(args.container_name)
        elif args.command == "delete-container":
            manager.delete_container(args.container_name)
        elif args.command == "list-containers":
            manager.list_containers()
        elif args.command == "upload":
            manager.upload_blob(args.container_name, args.local_file_path, args.blob_name)
        elif args.command == "download":
            manager.download_blob(args.container_name, args.blob_name, args.local_path)
        elif args.command == "list-blobs":
            manager.list_blobs(args.container_name)
        elif args.command == "delete-blob":
            manager.delete_blob(args.container_name, args.blob_name)
        else:
            parser.print_help()
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()