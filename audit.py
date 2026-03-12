import boto3
import json
import logging
import os
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_s3_security_posture(bucket_name="test-bucket"):
    """
    Connects to LocalStack S3 and retrieves the ACL for the given bucket.
    Saves the evidence to cloud_evidence.json.
    """
    logger.info(f"Connecting to LocalStack to extract security posture for {bucket_name}")
    try:
        s3 = boto3.client(
            's3',
            endpoint_url='http://localhost:4566',
            aws_access_key_id='test',
            aws_secret_access_key='test',
            region_name='us-east-1'
        )
        
        response = s3.get_bucket_acl(Bucket=bucket_name)
        
        public_access_block = None
        try:
            pab_response = s3.get_public_access_block(Bucket=bucket_name)
            public_access_block = pab_response.get('PublicAccessBlockConfiguration', {})
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                public_access_block = "Not configured"
            else:
                logger.warning(f"Failed to get Public Access Block")
        
        policy = None
        try:
            policy_response = s3.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response.get('Policy', '{}'))
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                policy = "Not configured"
            else:
                logger.warning(f"Failed to get Bucket Policy")

        evidence = {
            "bucket_name": bucket_name,
            "region": "us-east-1",
            "grants": response.get('Grants', []),
            "owner": response.get('Owner', {}),
            "public_access_block": public_access_block,
            "bucket_policy": policy
        }
        
        with open('cloud_evidence.json', 'w') as f:
            json.dump(evidence, f, indent=4)
        
        logger.info("Successfully extracted security posture to cloud_evidence.json")
        return evidence
        
    except ClientError as e:
        logger.error(f"Error communicating with LocalStack S3: {e}")
        return fetch_mock_evidence(bucket_name)
    except Exception as e:
        logger.error(f"Unexpected error, LocalStack might be down: {e}")
        return fetch_mock_evidence(bucket_name)

def calculate_blast_radius(resource_name):
    """
    Simulates a business dependency graph to determine the impact of a resource failure or compromise.
    """
    logger.info(f"Calculating Blast Radius for {resource_name}")
    
    # Mock Dependency Graph defining what downstream services rely on this bucket
    dependency_graph = {
        "test-bucket-public": ["Production Web App Frontend", "Customer PII Database", "Global Content Delivery Network"],
        "test-bucket-unencrypted": ["Internal Financial Reporting Tool", "Data Science Model Training Pipeline"],
        "test-bucket-no-mfa": ["Historical Archival System"],
        "test-bucket-secure": ["Development Sandbox Environment"],
        "test-bucket-complex-breach": ["Global Payment Gateway API (Critical)", "User Authentication Service"]
    }
    
    affected_services = dependency_graph.get(resource_name, ["Unknown Dependencies"])
    
    impact_score = "Low"
    if len(affected_services) > 2 or any("Production" in s or "Customer" in s for s in affected_services):
        impact_score = "High"
    elif len(affected_services) > 1 or any("Internal" in s for s in affected_services):
        impact_score = "Medium"
        
    return {
        "impact_score": impact_score,
        "affected_downstream_services": affected_services
    }

def fetch_mock_evidence(bucket_name):
    logger.info(f"LocalStack unavailable. Falling back to mock extracted evidence for {bucket_name}.")
    
    blast_radius = calculate_blast_radius(bucket_name)
    
    if bucket_name == "test-bucket-public":
        mock_evidence = {
            "bucket_name": bucket_name,
            "region": "us-east-1",
            "grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                    },
                    "Permission": "READ"
                }
            ],
            "owner": {"DisplayName": "sandbox-admin", "ID": "abc...123"},
            "server_side_encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}},
            "versioning": {"Status": "Enabled", "MFADelete": "Enabled"},
            "blast_radius": blast_radius
        }
    elif bucket_name == "test-bucket-unencrypted":
        mock_evidence = {
            "bucket_name": bucket_name,
            "region": "us-east-1",
            "grants": [],
            "owner": {"DisplayName": "sandbox-admin", "ID": "abc...123"},
            "server_side_encryption": None,
            "versioning": {"Status": "Enabled", "MFADelete": "Enabled"},
            "blast_radius": blast_radius
        }
    elif bucket_name == "test-bucket-no-mfa":
        mock_evidence = {
            "bucket_name": bucket_name,
            "region": "us-east-1",
            "grants": [],
            "owner": {"DisplayName": "sandbox-admin", "ID": "abc...123"},
            "server_side_encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}},
            "versioning": {"Status": "Enabled", "MFADelete": "Disabled"},
            "blast_radius": blast_radius
        }
    elif bucket_name == "test-bucket-complex-breach":
        # A completely new, complex configuration the rule-based system hasn't seen
        # but the LLM should be able to parse.
        mock_evidence = {
             "bucket_name": bucket_name,
             "region": "us-west-2",
             "grants": [
                 {
                     "Grantee": {
                         "Type": "CanonicalUser",
                         "ID": "suspicious-external-account-id-999"
                     },
                     "Permission": "FULL_CONTROL"
                 }
             ],
             "bucket_policy": {
                 "Statement": [
                     {
                         "Effect": "Allow",
                         "Principal": "*",
                         "Action": "s3:GetObject",
                         "Resource": f"arn:aws:s3:::{bucket_name}/*",
                         "Condition": {
                             "IpAddress": {"aws:SourceIp": "0.0.0.0/0"}
                         }
                     }
                 ]
             },
             "public_access_block": "Not configured",
             "server_side_encryption": None,
             "versioning": {"Status": "Suspended"},
             "blast_radius": blast_radius
        }
    else:
        # Default empty/secure configuration
        mock_evidence = {
            "bucket_name": bucket_name,
            "region": "us-east-1",
            "grants": [],
            "owner": {"DisplayName": "sandbox-admin", "ID": "abc...123"},
            "server_side_encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}},
            "versioning": {"Status": "Enabled", "MFADelete": "Enabled"},
            "blast_radius": blast_radius
        }
        
    with open('cloud_evidence.json', 'w') as f:
        json.dump(mock_evidence, f, indent=4)
    return mock_evidence

if __name__ == "__main__":
    extract_s3_security_posture()
