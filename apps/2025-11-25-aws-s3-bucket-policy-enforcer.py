import boto3
import json
import os
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(filename='s3_bucket_policy_enforcer.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Define the security policy
SECURITY_POLICY = {
    "AllowPublicReadAccess": False,
    "AllowPublicWriteAccess": False,
    "RequireServerSideEncryption": True
}

def get_all_s3_buckets(session):
    """
    Retrieves a list of all S3 buckets in the current AWS account.
    
    Args:
        session (boto3.Session): The AWS session to use for the API calls.
    
    Returns:
        list: A list of S3 bucket names.
    """
    s3 = session.resource('s3')
    buckets = [bucket.name for bucket in s3.buckets.all()]
    return buckets

def get_bucket_policy(session, bucket_name):
    """
    Retrieves the policy for the specified S3 bucket.
    
    Args:
        session (boto3.Session): The AWS session to use for the API calls.
        bucket_name (str): The name of the S3 bucket.
    
    Returns:
        dict: The bucket policy as a dictionary, or None if no policy is set.
    """
    s3 = session.resource('s3')
    bucket = s3.Bucket(bucket_name)
    try:
        policy = json.loads(bucket.Policy().policy)
        return policy
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return None
        else:
            raise e

def check_public_access(session, bucket_name):
    """
    Checks if the specified S3 bucket has public read or write access.
    
    Args:
        session (boto3.Session): The AWS session to use for the API calls.
        bucket_name (str): The name of the S3 bucket.
    
    Returns:
        dict: A dictionary with the following keys:
            - "AllowPublicReadAccess": True if the bucket has public read access, False otherwise.
            - "AllowPublicWriteAccess": True if the bucket has public write access, False otherwise.
    """
    s3 = session.resource('s3')
    bucket = s3.Bucket(bucket_name)
    public_access_block = bucket.PublicAccessBlockConfiguration()
    
    allow_public_read_access = not public_access_block.block_public_reads
    allow_public_write_access = not public_access_block.block_public_writes
    
    return {
        "AllowPublicReadAccess": allow_public_read_access,
        "AllowPublicWriteAccess": allow_public_write_access
    }

def check_server_side_encryption(session, bucket_name):
    """
    Checks if the specified S3 bucket has server-side encryption enabled.
    
    Args:
        session (boto3.Session): The AWS session to use for the API calls.
        bucket_name (str): The name of the S3 bucket.
    
    Returns:
        bool: True if the bucket has server-side encryption enabled, False otherwise.
    """
    s3 = session.resource('s3')
    bucket = s3.Bucket(bucket_name)
    encryption_configuration = bucket.encryption()
    
    if encryption_configuration and 'ServerSideEncryptionConfiguration' in encryption_configuration:
        return True
    else:
        return False

def enforce_security_policy(session, bucket_name, security_policy):
    """
    Enforces the security policy on the specified S3 bucket.
    
    Args:
        session (boto3.Session): The AWS session to use for the API calls.
        bucket_name (str): The name of the S3 bucket.
        security_policy (dict): The security policy to enforce.
    
    Returns:
        bool: True if the security policy was successfully enforced, False otherwise.
    """
    s3 = session.resource('s3')
    bucket = s3.Bucket(bucket_name)
    
    # Check public access
    public_access = check_public_access(session, bucket_name)
    if public_access["AllowPublicReadAccess"] and not security_policy["AllowPublicReadAccess"]:
        logging.info(f"Bucket '{bucket_name}' has public read access, which violates the security policy. Attempting to block public read access.")
        try:
            bucket.PublicAccessBlockConfiguration().update(
                BlockPublicAcls=True,
                BlockPublicPolicy=True,
                IgnorePublicAcls=True,
                RestrictPublicBuckets=True
            )
            logging.info(f"Public read access successfully blocked for bucket '{bucket_name}'.")
        except botocore.exceptions.ClientError as e:
            logging.error(f"Failed to block public read access for bucket '{bucket_name}': {e}")
            return False
    
    if public_access["AllowPublicWriteAccess"] and not security_policy["AllowPublicWriteAccess"]:
        logging.info(f"Bucket '{bucket_name}' has public write access, which violates the security policy. Attempting to block public write access.")
        try:
            bucket.PublicAccessBlockConfiguration().update(
                BlockPublicAcls=True,
                BlockPublicPolicy=True,
                IgnorePublicAcls=True,
                RestrictPublicBuckets=True
            )
            logging.info(f"Public write access successfully blocked for bucket '{bucket_name}'.")
        except botocore.exceptions.ClientError as e:
            logging.error(f"Failed to block public write access for bucket '{bucket_name}': {e}")
            return False
    
    # Check server-side encryption
    has_encryption = check_server_side_encryption(session, bucket_name)
    if not has_encryption and security_policy["RequireServerSideEncryption"]:
        logging.info(f"Bucket '{bucket_name}' does not have server-side encryption enabled, which violates the security policy. Attempting to enable server-side encryption.")
        try:
            bucket.encryption().update(
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }
                    ]
                }
            )
            logging.info(f"Server-side encryption successfully enabled for bucket '{bucket_name}'.")
        except botocore.exceptions.ClientError as e:
            logging.error(f"Failed to enable server-side encryption for bucket '{bucket_name}': {e}")
            return False
    
    return True

def audit_s3_buckets(session, security_policy):
    """
    Audits all S3 buckets in the current AWS account and enforces the security policy.
    
    Args:
        session (boto3.Session): The AWS session to use for the API calls.
        security_policy (dict): The security policy to enforce.
    
    Returns:
        None
    """
    buckets = get_all_s3_buckets(session)
    for bucket_name in buckets:
        logging.info(f"Auditing bucket: {bucket_name}")
        
        # Check public access
        public_access = check_public_access(session, bucket_name)
        if public_access["AllowPublicReadAccess"] and not security_policy["AllowPublicReadAccess"]:
            logging.warning(f"Bucket '{bucket_name}' has public read access, which violates the security policy.")
        if public_access["AllowPublicWriteAccess"] and not security_policy["AllowPublicWriteAccess"]:
            logging.warning(f"Bucket '{bucket_name}' has public write access, which violates the security policy.")
        
        # Check server-side encryption
        has_encryption = check_server_side_encryption(session, bucket_name)
        if not has_encryption and security_policy["RequireServerSideEncryption"]:
            logging.warning(f"Bucket '{bucket_name}' does not have server-side encryption enabled, which violates the security policy.")
        
        # Enforce security policy
        if (public_access["AllowPublicReadAccess"] and not security_policy["AllowPublicReadAccess"]) or \
           (public_access["AllowPublicWriteAccess"] and not security_policy["AllowPublicWriteAccess"]) or \
           (not has_encryption and security_policy["RequireServerSideEncryption"]):
            if enforce_security_policy(session, bucket_name, security_policy):
                logging.info(f"Security policy successfully enforced for bucket '{bucket_name}'.")
            else:
                logging.error(f"Failed to enforce security policy for bucket '{bucket_name}'.")

def main():
    """
    The main entry point of the script.
    """
    # Set up the AWS session
    session = boto3.Session(profile_name='your-aws-profile-name')
    
    # Audit and enforce the security policy
    audit_s3_buckets(session, SECURITY_POLICY)

if __name__ == "__main__":
    main()