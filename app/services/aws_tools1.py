import json
from typing import List, Literal, Optional
from pydantic import BaseModel, Field
from app.utils.logging_decorator import logger
import boto3
from langchain.tools import tool
import os
from dotenv import load_dotenv
from botocore.exceptions import ClientError
##EC2 TOOL WITH boto3 client As ec2. 
from langchain.tools import tool
import boto3

from langchain.tools import tool
import boto3
import os

load_dotenv()
# pydantic classes

#### rds pydantic classes 
from pydantic import BaseModel, Field


# --------------------------------------------------------------------------------
# 🔹 RDS Pydantic Schemas
# --------------------------------------------------------------------------------

class CreateRDSInstanceInput(BaseModel):
    """Input schema for creating an RDS instance."""
    db_instance_identifier: str = Field(..., description="Unique identifier for the RDS instance, e.g., 'mydatabase'.")
    db_instance_class: str = Field("db.t3.micro", description="RDS instance size/class. Default: db.t3.micro")
    engine: str = Field("mysql", description="Database engine. Options: mysql, postgres, oracle-se2, sqlserver-ex")
    master_username: str = Field(..., description="Master username for the RDS instance.")
    master_user_password: str = Field(..., description="Master user password for the RDS instance.")
    allocated_storage: int = Field(20, description="Storage size in GB. Default: 20")
    publicly_accessible: bool = Field(True, description="Whether the instance is publicly accessible. Default: True")
    multi_az: bool = Field(False, description="Enable Multi-AZ deployment for high availability. Default: False")
    storage_type: str = Field("gp3", description="Storage type. Default: gp3")
    AWS_ACCESS_KEY_ID: str = Field(..., description="AWS Access Key ID for authentication.")
    SECRET_KEY_ACCESS: str = Field(..., description="AWS Secret Access Key for authentication.")



class DeleteRDSInstanceInput(BaseModel):
    """Input schema for deleting an RDS instance."""
    db_instance_identifier: str = Field(..., description="Unique identifier of the RDS instance to delete, e.g., 'mydatabase'.")
    skip_final_snapshot: bool = Field(True, description="If True, no final snapshot will be created. Default: True")
    AWS_ACCESS_KEY_ID: str = Field(..., description="AWS Access Key ID for authentication.")
    SECRET_KEY_ACCESS: str = Field(..., description="AWS Secret Access Key for authentication.")


# --------------------------------------------------------------------------------
# 🔹 EC2 Pydantic Schemas
# --------------------------------------------------------------------------------

from pydantic import BaseModel, Field

class CreateEC2InstanceInput(BaseModel):
    """Input schema for creating an EC2 instance."""
    
    friendly_name: str = Field(..., description="Friendly name of the AMI, e.g., 'Windows_Server 2019'.")
    instance_type: str = Field(..., description="EC2 instance type, e.g., 't3.micro'.")
    min_count: int = Field(..., description="Minimum number of instances to launch.")
    max_count: int = Field(..., description="Maximum number of instances to launch.")
    key_name: str = Field(None, description="Optional KeyPair name for SSH/RDP access.")
    ec2_name: str = Field(None, description="Optional tag name for the EC2 instance.")
    os_type: str = Field("linux", description="OS type, 'linux' or 'windows'. Defaults to 'linux'.")
    volume_size: int = Field(20, description="Root volume size in GB. Defaults to 20.")
    volume_type: str = Field("gp3", description="Volume type, e.g., gp3, gp2. Defaults to 'gp3'.")
    volume_encrypted: bool = Field(True, description="Whether the root volume is encrypted. Defaults to True.")
    associate_public_ip: bool = Field(True, description="Whether to assign a public IP. Defaults to True.")
    subnet_id: str = Field(None, description="Optional subnet ID for network interface.")
    security_group_name: str = Field("AutoSG", description="Security Group name. Defaults to 'AutoSG'.")
    AWS_ACCESS_KEY_ID: str = Field(..., description="AWS Access Key ID for the user.")
    SECRET_KEY_ACCESS: str = Field(..., description="AWS Secret Access Key for the user.")


from pydantic import BaseModel, Field

class DeleteEC2InstanceInput(BaseModel):
    """
    Input schema for deleting an EC2 instance by its Name tag.
    """
    instance_name: str = Field(..., description="The Name tag of the EC2 instance to terminate.")
    AWS_ACCESS_KEY_ID: str = Field(..., description="AWS access key ID for authentication.")
    SECRET_KEY_ACCESS: str = Field(..., description="AWS secret access key for authentication.")

class ListS3BucketsInput(BaseModel):
    """Input schema for listing S3 buckets."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
#==================================================================================================
#resource ecplorer
#=====================================================================================================
class ListResourcesInRegionInput(BaseModel):
    """Input schema for listing AWS resources in a region via Resource Explorer."""
    region: str = Field(..., description="AWS region to query, e.g., 'ap-south-1'.")
    AWS_ACCESS_KEY_ID: str = Field(..., description="AWS access key ID for authentication.")
    SECRET_KEY_ACCESS: str = Field(..., description="AWS secret access key for authentication.")




class GetBucketRegionInput(BaseModel):
    """Input schema for getting the region of a specific S3 bucket."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
    bucket_name: str = Field(..., description="Name of the S3 bucket.")


class GetBucketRegionOutput(BaseModel):
    """Output schema for the bucket's region."""
    bucket_name: str = Field(..., description="The name of the S3 bucket.")
    region: str = Field(..., description="The region where the S3 bucket is located.")


class SetBucketPolicyInput(BaseModel):
    """Input schema for setting S3 bucket policy or ACL."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
    bucket_name: str = Field(..., description="Name of the S3 bucket.")
    policy_type: str = Field(..., description="Type of policy to apply: 'private', 'public-read', or 'custom'.")
    custom_policy: Optional[dict] = Field(None, description="Custom JSON policy if policy_type is 'custom'.")

class SetBucketPolicyOutput(BaseModel):
    """Output schema confirming the policy update."""
    status: str = Field(..., description="Result of the policy update operation.")

class EnableS3VersioningInput(BaseModel):
    """Input schema for enabling or suspending versioning on an S3 bucket."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
    bucket_name: str = Field(..., description="Name of the S3 bucket.")
    status: Literal["Enabled", "Suspended"] = Field(..., description="Versioning status: 'Enabled' or 'Suspended'.")


class EnableS3VersioningOutput(BaseModel):
    """Output schema for confirming versioning status."""
    bucket_name: str = Field(..., description="Name of the S3 bucket.")
    versioning_status: str = Field(..., description="Current versioning status of the bucket.")

# ----------------------------
class SetS3BucketEncryptionInput(BaseModel):
    """Input schema for setting S3 bucket encryption."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
    bucket_name: str = Field(..., description="Name of the S3 bucket.")
    encryption_type: Literal["AES256", "aws:kms"] = Field(..., description="Encryption type: AES256 for SSE-S3 or aws:kms for SSE-KMS.")
    kms_key_id: str | None = Field(None, description="Optional KMS Key ID (required if encryption_type is aws:kms).")


class SetS3BucketEncryptionOutput(BaseModel):
    """Output schema for setting bucket encryption."""
    status: str = Field(..., description="Result of the encryption operation.")
    encryption_type: str = Field(..., description="The applied encryption type.")

class ConfigureS3ObjectLockInput(BaseModel):
    """Input schema for configuring S3 Object Lock on a bucket."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
    bucket_name: str = Field(..., description="Name of the S3 bucket.")
    object_lock_enabled: bool = Field(..., description="Enable Object Lock (True/False).")
    lock_mode: Literal["GOVERNANCE", "COMPLIANCE"] = Field(..., description="Object Lock mode: GOVERNANCE or COMPLIANCE.")
    retention_days: int = Field(..., description="Retention period in days.")

class ConfigureS3ObjectLockOutput(BaseModel):
    """Output schema for Object Lock configuration."""
    message: str = Field(..., description="Result of Object Lock configuration.")

class ConfigureLifecycleRuleInput(BaseModel):
    """Input schema for configuring lifecycle rules on an S3 bucket."""
    aws_access_key_id: str = Field(..., description="AWS access key ID.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key.")
    bucket_name: str = Field(..., description="S3 bucket name.")
    rule_id: str = Field(..., description="Unique ID for the lifecycle rule.")
    transition_days: int = Field(..., description="Number of days after which transition occurs.")
    storage_class: Literal["GLACIER", "DEEP_ARCHIVE"] = Field(..., description="Storage class to transition to.")

class ConfigureBucketLoggingInput(BaseModel):
    """Input schema for enabling or disabling logging on an S3 bucket."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
    bucket_name: str = Field(..., description="The name of the S3 bucket to configure logging for.")
    target_bucket: str = Field(..., description="The bucket where access logs will be stored.")
    target_prefix: str = Field("", description="Optional prefix for log object keys.")
    enable: bool = Field(..., description="Set True to enable logging, False to disable.")

class ConfigureBucketLoggingOutput(BaseModel):
    """Output schema indicating logging status."""
    status: str = Field(..., description="Result message about logging configuration.")
    bucket_name: str = Field(..., description="Name of the S3 bucket.")
    logging_enabled: bool = Field(..., description="True if logging enabled, False otherwise.")

class ConfigureBucketReplicationInput(BaseModel):
    """Input schema for enabling replication on an S3 bucket."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
    source_bucket: str = Field(..., description="The source S3 bucket for replication.")
    destination_bucket_arn: str = Field(..., description="ARN of the destination S3 bucket.")
    role_arn: str = Field(..., description="IAM Role ARN that grants S3 permissions for replication.")
    replication_id: str = Field(..., description="Unique ID for replication rule.")
    status: str = Field("Enabled", description="Replication status. Options: Enabled, Disabled.")
    prefix: str = Field("", description="Object key prefix for replication. Empty means all objects.")

class ConfigureBucketReplicationOutput(BaseModel):
    """Output schema for replication configuration result."""
    status: str = Field(..., description="Result message about replication configuration.")
    source_bucket: str = Field(..., description="Source S3 bucket name.")
    replication_enabled: bool = Field(..., description="True if replication rule is enabled.")
class ConfigureBucketEventNotificationInput(BaseModel):
    """Input schema for configuring S3 bucket event notifications."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
    bucket_name: str = Field(..., description="The S3 bucket to configure notifications for.")
    lambda_function_arn: str = Field(..., description="ARN of the Lambda function to invoke on events.")
    events: List[str] = Field(..., description="List of events to trigger notifications. Example: ['s3:ObjectCreated:*', 's3:ObjectRemoved:*'].")

class ConfigureBucketEventNotificationOutput(BaseModel):
    """Output schema for event notification configuration."""
    status: str = Field(..., description="Result message about the event notification setup.")
    bucket_name: str = Field(..., description="Bucket name where event notifications were configured.")
    events: List[str] = Field(..., description="Events configured for notifications.")

class CreateBucketInput(BaseModel):
    """Input schema for creating an S3 bucket."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
    bucket_name: str = Field(..., description="Unique name for the new S3 bucket.")
    region: str = Field(..., description="AWS region for the S3 bucket, e.g., ap-south-1.")


class CreateBucketOutput(BaseModel):
    """Output schema for creating an S3 bucket."""
    status: str = Field(..., description="Result message.")
    bucket_name: str = Field(..., description="Name of the created bucket.")
    region: str = Field(..., description="Region where the bucket was created.")

class DeleteBucketInput(BaseModel):
    """Input schema for deleting an S3 bucket."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
    bucket_name: str = Field(..., description="The name of the bucket to delete.")


class DeleteBucketOutput(BaseModel):
    """Output schema for deleting an S3 bucket."""
    status: str = Field(..., description="Result message.")
    bucket_name: str = Field(..., description="Name of the deleted bucket.")

# create IAM User
class CreateIAMUserInput(BaseModel):
    """Input for creating an IAM user."""
    aws_access_key_id: str = Field(..., description="AWS access key ID.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key.")
    user_name: str = Field(..., description="Name of the IAM user to create.")


class CreateIAMUserOutput(BaseModel):
    """Output for creating an IAM user."""
    status: str = Field(..., description="Result message.")
    user_arn: str = Field(..., description="ARN of the created IAM user.")

# Delete User
class DeleteIAMUserInput(BaseModel):
    aws_access_key_id: str
    aws_secret_access_key: str
    user_name: str


class DeleteIAMUserOutput(BaseModel):
    status: str


#IAM Attach Policy
class AttachPolicyInput(BaseModel):
    """Input for attaching a policy to an IAM user."""
    aws_access_key_id: str
    aws_secret_access_key: str
    user_name: str
    policy_arn: str = Field(..., description="ARN of the policy to attach (e.g., arn:aws:iam::aws:policy/AmazonS3FullAccess).")

class AttachPolicyOutput(BaseModel):
    """Output after attaching a policy."""
    status: str
    user_name: str
    policy_arn: str

# Detach Policy
class DetachPolicyInput(BaseModel):
    aws_access_key_id: str
    aws_secret_access_key: str
    user_name: str
    policy_arn: str


class DetachPolicyOutput(BaseModel):
    status: str



# Create Access Key
class CreateAccessKeyInput(BaseModel):
    """Input for creating a new access key for an IAM user."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")
    user_name: str = Field(..., description="The name of the IAM user to create keys for.")


class CreateAccessKeyOutput(BaseModel):
    """Output containing the newly created access key pair."""
    new_access_key_id: str = Field(..., description="The newly created access key ID.")
    new_secret_access_key: str = Field(..., description="The new secret access key. This is the only time it will be shown.")
    status: str = Field(..., description="The result of the operation.")

# Create Custom Policy
class CreatePolicyInput(BaseModel):
    aws_access_key_id: str
    aws_secret_access_key: str
    policy_name: str
    policy_document: str = Field(..., description="JSON string of the policy document.")


class CreatePolicyOutput(BaseModel):
    policy_arn: str
    status: str


# Rotate Access keys
class RotateAccessKeyInput(BaseModel):
    aws_access_key_id: str
    aws_secret_access_key: str
    user_name: str


class RotateAccessKeyOutput(BaseModel):
    old_key_status: str
    new_access_key_id: str
    new_secret_access_key: str
    status: str

# Attach role to EC2 Instance
class AttachInstanceProfileInput(BaseModel):
    """Input for attaching an IAM instance profile to an EC2 instance."""
    aws_access_key_id: str
    aws_secret_access_key: str
    region_name: str
    instance_id: str
    instance_profile_name: str = Field(..., description="The name of the IAM instance profile to attach.")


class AttachInstanceProfileOutput(BaseModel):
    """Output after attaching the instance profile."""
    status: str
# get function
def get_all_aws_tools():
    return [
        list_s3_buckets,
        get_bucket_region,
        set_s3_bucket_policy,
        enable_s3_versioning,
        set_s3_bucket_encryption,
        configure_lifecycle_rule,
        configure_bucket_logging,
        configure_bucket_replication,
        configure_bucket_event_notification,
        create_s3_bucket,
        delete_s3_bucket,
        create_iam_user,
        attach_policy_to_user,
        create_custom_policy,
        detach_policy_from_user,
        create_access_key_for_user,
        rotate_access_key,
        delete_iam_user,
        attach_instance_profile_to_ec2,
        create_rds_instance,
        delete_rds_instance,
        create_ec2_instance,

    ]

# Tools
@tool(args_schema=ListS3BucketsInput, return_direct=True)

def list_s3_buckets(aws_access_key_id: str, aws_secret_access_key: str):
    """List all S3 buckets in the AWS account."""
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    response = s3_client.list_buckets()
    return [bucket['Name'] for bucket in response['Buckets']]


@tool(args_schema=GetBucketRegionInput, return_direct=True)

def get_bucket_region(aws_access_key_id: str, aws_secret_access_key: str, bucket_name: str) -> GetBucketRegionOutput:
    """Get the region of a specific S3 bucket."""
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )
    response = s3_client.get_bucket_location(Bucket=bucket_name)
    region = response.get('LocationConstraint', 'us-east-1')  # Default to us-east-1 if None
    return GetBucketRegionOutput(bucket_name=bucket_name, region=region)

@tool(args_schema=SetBucketPolicyInput, return_direct=True)

def set_s3_bucket_policy(aws_access_key_id: str, aws_secret_access_key: str, bucket_name: str, policy_type: str, custom_policy: Optional[dict] = None):
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    try:
        if policy_type == "private":
            s3_client.put_bucket_acl(Bucket=bucket_name, ACL="private")
            return {"status": f"Bucket '{bucket_name}' set to private."}

        elif policy_type == "public-read":
            s3_client.put_bucket_acl(Bucket=bucket_name, ACL="public-read")
            return {"status": f"Bucket '{bucket_name}' set to public-read."}

        elif policy_type == "custom":
            if not custom_policy:
                return {"status": "Custom policy not provided for policy_type='custom'."}

            s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(custom_policy))
            return {"status": f"Custom policy applied to bucket '{bucket_name}'."}

        else:
            return {"status": "Invalid policy_type. Choose from: private, public-read, custom."}

    except Exception as e:
        logger.error(f"Error setting bucket policy: {str(e)}")
        return {"status": f"Failed to update policy: {str(e)}"}

    
    
@tool(args_schema=EnableS3VersioningInput, return_direct=True)

def enable_s3_versioning(aws_access_key_id: str, aws_secret_access_key: str, bucket_name: str, status: str) -> EnableS3VersioningOutput:
    """
    Enable or suspend versioning on an S3 bucket.
    
    Args:
        aws_access_key_id: AWS access key ID
        aws_secret_access_key: AWS secret access key
        bucket_name: S3 bucket name
        status: 'Enabled' or 'Suspended'
    Returns:
        EnableS3VersioningOutput
    """
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    # Apply versioning configuration
    s3_client.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': status}
    )

    return EnableS3VersioningOutput(bucket_name=bucket_name, versioning_status=status)

@tool(args_schema=SetS3BucketEncryptionInput, return_direct=True)

def set_s3_bucket_encryption(aws_access_key_id: str, aws_secret_access_key: str, bucket_name: str, encryption_type: str, kms_key_id: str | None = None) -> dict:
    """
    Enable server-side encryption on an S3 bucket.
    Supports AES-256 (SSE-S3) and AWS KMS (SSE-KMS).
    """
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    encryption_config = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": encryption_type
                }
            }
        ]
    }

    if encryption_type == "aws:kms" and kms_key_id:
        encryption_config["Rules"][0]["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"] = kms_key_id

    s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration=encryption_config
    )

    return {
        "status": "Bucket encryption applied successfully",
        "encryption_type": encryption_type
    }


@tool(args_schema=ConfigureS3ObjectLockInput, return_direct=True)

def configure_s3_object_lock(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    bucket_name: str,
    object_lock_enabled: bool,
    lock_mode: str,
    retention_days: int
) -> ConfigureS3ObjectLockOutput:
    """Configure Object Lock for a specific S3 bucket."""
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    if object_lock_enabled:
        # Enable Object Lock configuration (requires bucket versioning to be enabled)
        try:
            response = s3_client.put_object_lock_configuration(
                Bucket=bucket_name,
                ObjectLockConfiguration={
                    'ObjectLockEnabled': 'Enabled',
                    'Rule': {
                        'DefaultRetention': {
                            'Mode': lock_mode,
                            'Days': retention_days
                        }
                    }
                }
            )
            return ConfigureS3ObjectLockOutput(message=f"Object Lock enabled on {bucket_name} with mode {lock_mode} for {retention_days} days.")
        except Exception as e:
            return ConfigureS3ObjectLockOutput(message=f"Failed to configure Object Lock: {str(e)}")
    else:
        return ConfigureS3ObjectLockOutput(message=f"Object Lock not enabled on {bucket_name}.")
    
@tool(args_schema=ConfigureLifecycleRuleInput, return_direct=True)

def configure_lifecycle_rule(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    bucket_name: str,
    rule_id: str,
    transition_days: int,
    storage_class: str
):
    """Configure lifecycle rules for an S3 bucket to transition data to cheaper storage classes."""
    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
        lifecycle_config = {
            "Rules": [
                {
                    "ID": rule_id,
                    "Filter": {"Prefix": ""},
                    "Status": "Enabled",
                    "Transitions": [
                        {
                            "Days": transition_days,
                            "StorageClass": storage_class
                        }
                    ]
                }
            ]
        }
        s3.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_config
        )
        return {"status": f"Lifecycle rule {rule_id} added to {bucket_name}"}
    except Exception as e:
        return {"status": f"Error: {str(e)}"}
    
@tool(args_schema=ConfigureBucketLoggingInput, return_direct=True)

def configure_bucket_logging(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    bucket_name: str,
    target_bucket: str,
    target_prefix: str,
    enable: bool
) -> ConfigureBucketLoggingOutput:
    """Enable or disable logging for an S3 bucket."""
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    try:
        if enable:
            logging_config = {
                "LoggingEnabled": {
                    "TargetBucket": target_bucket,
                    "TargetPrefix": target_prefix
                }
            }
        else:
            logging_config = {}

        s3_client.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus=logging_config
        )

        return ConfigureBucketLoggingOutput(
            status=f"Logging {'enabled' if enable else 'disabled'} successfully",
            bucket_name=bucket_name,
            logging_enabled=enable
        )
    except Exception as e:
        logger.error(f"Error configuring logging for bucket {bucket_name}: {e}")
        return ConfigureBucketLoggingOutput(
            status=f"Error: {str(e)}",
            bucket_name=bucket_name,
            logging_enabled=False
        )
    
@tool(args_schema=ConfigureBucketReplicationInput, return_direct=True)

def configure_bucket_replication(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    source_bucket: str,
    destination_bucket_arn: str,
    role_arn: str,
    replication_id: str,
    status: str,
    prefix: str
) -> ConfigureBucketReplicationOutput:
    """Enable replication for an S3 bucket."""
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    try:
        replication_config = {
            "Role": role_arn,
            "Rules": [
                {
                    "ID": replication_id,
                    "Status": status,
                    "Prefix": prefix,
                    "Destination": {"Bucket": destination_bucket_arn}
                }
            ]
        }

        s3_client.put_bucket_replication(
            Bucket=source_bucket,
            ReplicationConfiguration=replication_config
        )

        return ConfigureBucketReplicationOutput(
            status=f"Replication {'enabled' if status == 'Enabled' else 'disabled'} successfully",
            source_bucket=source_bucket,
            replication_enabled=(status == "Enabled")
        )
    except Exception as e:
        logger.error(f"Error configuring replication for bucket {source_bucket}: {e}")
        return ConfigureBucketReplicationOutput(
            status=f"Error: {str(e)}",
            source_bucket=source_bucket,
            replication_enabled=False
        )
    
@tool(args_schema=ConfigureBucketEventNotificationInput, return_direct=True)

def configure_bucket_event_notification(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    bucket_name: str,
    lambda_function_arn: str,
    events: List[str]
) -> ConfigureBucketEventNotificationOutput:
    """Configure S3 bucket to send event notifications to a Lambda function."""
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    try:
        notification_config = {
            "LambdaFunctionConfigurations": [
                {
                    "LambdaFunctionArn": lambda_function_arn,
                    "Events": events
                }
            ]
        }

        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration=notification_config
        )

        return ConfigureBucketEventNotificationOutput(
            status="Event notification configured successfully",
            bucket_name=bucket_name,
            events=events
        )
    except Exception as e:
        logger.error(f"Error configuring event notification for bucket {bucket_name}: {e}")
        return ConfigureBucketEventNotificationOutput(
            status=f"Error: {str(e)}",
            bucket_name=bucket_name,
            events=[]
        )
    
@tool(args_schema=CreateBucketInput, return_direct=True)

def create_s3_bucket(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    bucket_name: str,
    region: str
) -> CreateBucketOutput:
    """Create a new S3 bucket in a specific AWS region."""
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )

    try:
        create_args = {"Bucket": bucket_name}
        if region != "us-east-1":
            create_args["CreateBucketConfiguration"] = {"LocationConstraint": region}

        s3_client.create_bucket(**create_args)

        return CreateBucketOutput(
            status="Bucket created successfully.",
            bucket_name=bucket_name,
            region=region
        )
    except Exception as e:
        logger.error(f"Error creating bucket {bucket_name}: {e}")
        return CreateBucketOutput(
            status=f"Error: {str(e)}",
            bucket_name=bucket_name,
            region=region
        )

@tool(args_schema=DeleteBucketInput, return_direct=True)

def delete_s3_bucket(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    bucket_name: str
) -> DeleteBucketOutput:
    """Delete an S3 bucket."""
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        return DeleteBucketOutput(
            status="Bucket deleted successfully.",
            bucket_name=bucket_name
        )
    except Exception as e:
        logger.error(f"Error deleting bucket {bucket_name}: {e}")
        return DeleteBucketOutput(
            status=f"Error: {str(e)}",
            bucket_name=bucket_name
        )
    
@tool(args_schema=CreateIAMUserInput, return_direct=True)

def create_iam_user(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    user_name: str
) -> CreateIAMUserOutput:
    """Create an IAM user."""
    client = boto3.client(
        'iam',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    try:
        response = client.create_user(UserName=user_name)
        return CreateIAMUserOutput(
            status="User created successfully.",
            user_arn=response['User']['Arn']
        )
    except Exception as e:
        logger.error(f"Error creating IAM user {user_name}: {e}")
        return CreateIAMUserOutput(
            status=f"Error: {str(e)}",
            user_arn=""
        )
    
@tool(args_schema=DeleteIAMUserInput, return_direct=True)

def delete_iam_user(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    user_name: str
) -> DeleteIAMUserOutput:
    """Delete IAM User"""
    client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    try:
        client.delete_user(UserName=user_name)
        return DeleteIAMUserOutput(status="User deleted successfully.")
    except Exception as e:
        logger.error(f"Error deleting IAM user: {e}")
        return DeleteIAMUserOutput(status=f"Error: {str(e)}")
    
@tool(args_schema=AttachPolicyInput, return_direct=True)

def attach_policy_to_user(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    user_name: str,
    policy_arn: str
) -> AttachPolicyOutput:
    """Attach an IAM policy to a user."""
    client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    try:
        client.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
        return AttachPolicyOutput(status="Policy attached successfully.", user_name=user_name, policy_arn=policy_arn)
    except Exception as e:
        logger.error(f"Error attaching policy: {e}")
        return AttachPolicyOutput(status=f"Error: {str(e)}", user_name=user_name, policy_arn=policy_arn)
    
@tool(args_schema=DetachPolicyInput, return_direct=True)

def detach_policy_from_user(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    user_name: str,
    policy_arn: str
) -> DetachPolicyOutput:
    """Detach an IAM policy from a user."""
    client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    try:
        client.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
        return DetachPolicyOutput(status="Policy detached successfully.")
    except Exception as e:
        logger.error(f"Error detaching policy: {e}")
        return DetachPolicyOutput(status=f"Error: {str(e)}")

@tool(args_schema=CreateAccessKeyInput)

def create_access_key_for_user(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    user_name: str
) -> CreateAccessKeyOutput:
    """Creates a new access key and secret key for a specified IAM user."""
    try:
        # 1. Initialize the IAM client using the provided admin credentials.
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

        # 2. Call the create_access_key API for the target user.
        response = iam_client.create_access_key(UserName=user_name)
        access_key_data = response['AccessKey']

        # 3. Return the new credentials and a success message.
        return CreateAccessKeyOutput(
            new_access_key_id=access_key_data['AccessKeyId'],
            new_secret_access_key=access_key_data['SecretAccessKey'],
            status="Success. IMPORTANT: Securely save the new secret key now, as it cannot be retrieved later."
        )

    except ClientError as e:
        # Handle known AWS errors, like user not found or key limit exceeded.
        error_message = f"Error: {e.response['Error']['Message']}"
        # logger.error(error_message)
        return CreateAccessKeyOutput(
            new_access_key_id="",
            new_secret_access_key="",
            status=error_message
        )
        
    except Exception as e:
        # Handle other unexpected errors.
        error_message = f"An unexpected error occurred: {str(e)}"
        # logger.error(error_message)
        return CreateAccessKeyOutput(
            new_access_key_id="",
            new_secret_access_key="",
            status=error_message
        )
@tool(args_schema=CreatePolicyInput) # Removed return_direct=True for easier inspection

def create_custom_policy(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    policy_name: str,
    policy_document: str
) -> CreatePolicyOutput:
    """Creates a new custom IAM policy."""
    client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    try:
        response = client.create_policy(PolicyName=policy_name, PolicyDocument=policy_document)
        return CreatePolicyOutput(policy_arn=response['Policy']['Arn'], status="Policy created successfully.")
    except Exception as e:
        logger.error(f"Error creating custom policy: {e}")
        return CreatePolicyOutput(policy_arn="", status=f"Error: {str(e)}")

@tool(args_schema=RotateAccessKeyInput, return_direct=True)

def rotate_access_key(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    user_name: str
) -> RotateAccessKeyOutput:
    """Rotate the aaccess key"""
    client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    try:
        # List existing keys
        keys = client.list_access_keys(UserName=user_name)['AccessKeyMetadata']
        old_key_id = keys[0]['AccessKeyId'] if keys else None

        # Create new key
        new_key = client.create_access_key(UserName=user_name)['AccessKey']

        # Deactivate old key if exists
        if old_key_id:
            client.update_access_key(UserName=user_name, AccessKeyId=old_key_id, Status='Inactive')

        return RotateAccessKeyOutput(
            old_key_status="Deactivated" if old_key_id else "No old key",
            new_access_key_id=new_key['AccessKeyId'],
            new_secret_access_key=new_key['SecretAccessKey'],
            status="Rotation successful"
        )
    except Exception as e:
        logger.error(f"Error rotating access key: {e}")
        return RotateAccessKeyOutput(old_key_status="", new_access_key_id="", new_secret_access_key="", status=f"Error: {str(e)}")
    


@tool(args_schema=AttachInstanceProfileInput) # Removed return_direct for easier inspection

def attach_instance_profile_to_ec2(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    region_name: str,
    instance_id: str,
    instance_profile_name: str
) -> AttachInstanceProfileOutput:
    """Attaches an IAM instance profile to a running EC2 instance."""
    client = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
    )
    try:
        # The API requires the Instance Profile's Name, not the Role's Name.
        client.associate_iam_instance_profile(
            IamInstanceProfile={'Name': instance_profile_name},
            InstanceId=instance_id
        )
        return AttachInstanceProfileOutput(status="Instance profile attached successfully.")
    except Exception as e:
        logger.error(f"Error attaching instance profile to EC2: {e}")
        return AttachInstanceProfileOutput(status=f"Error: {str(e)}")

# Tayyab
#===============================================================================
# Tools
#================================================================================
# --------------------------------------------------------------------------------
# 🔹 EC2 TOOLS
# --------------------------------------------------------------------------------


def get_ami_id(friendly_name: str,ec2) -> str:
    """
    Returns the latest AMI ID for a given friendly AMI name.

    Example friendly_name: "Windows_Server 2016"
    """
    # Split friendly_name into search terms for AWS name filter
    search_terms = friendly_name.replace(" ", "*")
    filters = [
        {"Name": "name", "Values": [f"*{search_terms}*"]},
        {"Name": "state", "Values": ["available"]},
        {"Name": "owner-alias", "Values": ["amazon"]}  # Official Amazon AMIs
    ]

    images = ec2.describe_images(Filters=filters)["Images"]

    if not images:
        raise ValueError(f"No AMI found for '{friendly_name}'")

    # Pick the most recent AMI by creation date
    latest_image = max(images, key=lambda x: x["CreationDate"])
    return latest_image["ImageId"]
def create_default_security_group(os_type: str,ec2, group_name="AutoSG") -> str:
    """Create minimal Security Group if none exists for SSH/RDP/HTTP."""
    sg_list = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [group_name]}])["SecurityGroups"]
    if sg_list:
        return sg_list[0]["GroupId"]

    # Create SG
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName=group_name, Description="Auto SG", VpcId=vpc_id)
    sg_id = sg["GroupId"]

    # Add inbound rules
    if os_type.lower() == "windows":
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpProtocol="tcp", FromPort=3389, ToPort=3389, CidrIp="0.0.0.0/0")
    else:
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpProtocol="tcp", FromPort=22, ToPort=22, CidrIp="0.0.0.0/0")
    # HTTP/HTTPS
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpProtocol="tcp", FromPort=80, ToPort=80, CidrIp="0.0.0.0/0")
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpProtocol="tcp", FromPort=443, ToPort=443, CidrIp="0.0.0.0/0")

    return sg_id

def get_device_name(os_type: str, volume_index: int) -> str:
    """
    Returns the appropriate device name for the root volume based on OS type.
    """
    if os_type.lower() == "windows":
        # Windows typically uses /dev/sda1 or /dev/xvda
        # Using /dev/sda1 as a common default
        return "/dev/sda1"
    else:
        # Linux typically uses /dev/sda1, /dev/xvda, or /dev/nvme0n1
        # Using /dev/xvda as a common default for older AMIs, or /dev/sda1
        # A more robust solution might involve describing the AMI's block device mappings
        return f"/dev/sd{chr(ord('a') + volume_index - 1)}" # /dev/sda, /dev/sdb, etc.


@tool("create_ec2_instance", return_direct=True)

def create_ec2_instance(
    friendly_name: str = None,   # Example: "Windows_Server 2016"
    instance_type: str = None,
    min_count: int = None,
    max_count: int = None,
    key_name: str = None,
    ec2_name: str = None,
    os_type: str = "linux",
    volume_size: int = 20,
    volume_type: str = "gp3",
    volume_encrypted: bool = True,
    associate_public_ip: bool = True,
    subnet_id: str = None,
    security_group_name: str = "AutoSG",
    AWS_ACCESS_KEY_ID: str = None,
    SECRET_KEY_ACCESS: str = None,
) -> str:
    """
    Launches an EC2 instance.
    Only essentials: friendly_name (or image_id internally), instance_type, min_count, max_count.
    Other parameters are optional.
    """
    if not SECRET_KEY_ACCESS or not AWS_ACCESS_KEY_ID:
        return "❌ 'AWS_ACCESS_KEY_ID' and 'SECRET_KEY_ACCESS' are required."

    ec2 = boto3.client(
    "ec2",
    aws_access_key_id= AWS_ACCESS_KEY_ID,
    aws_secret_access_key= SECRET_KEY_ACCESS,
    region_name="ap-south-1"
)


    # Convert friendly name to AMI ID
    if not friendly_name:
        return "❌ 'friendly_name' is essential (e.g., 'Windows_Server 2016')."
    try:
        image_id = get_ami_id(friendly_name, ec2) # Pass ec2 client
    except Exception as e:
        return f"❌ {str(e)}"

    # Check other essentials
    if not instance_type:
        return "❌ 'instance_type' is essential."
    if not min_count:
        return "❌ 'min_count' is essential."
    if not max_count:
        return "❌ 'max_count' is essential."

    # KeyPair handling
    key_status = "No KeyPair specified; instance will have no SSH/RDP access."
    if key_name:
        existing_keys = [k["KeyName"] for k in ec2.describe_key_pairs()["KeyPairs"]]
        if key_name not in existing_keys:
            key_response = ec2.create_key_pair(KeyName=key_name) # ec2 is available here
            private_key = key_response["KeyMaterial"]
            pem_file = f"{key_name}.pem"
            with open(pem_file, "w") as f:
                f.write(private_key)
            os.chmod(pem_file, 0o400)
            key_status = f"KeyPair '{key_name}' created and saved as '{pem_file}'."
        else:
            key_status = f"KeyPair '{key_name}' already exists. Using existing key."

    # Security Group
    sg_id = create_default_security_group(os_type, ec2, security_group_name) # Pass ec2 client

    # Block device mapping
    device_name = get_device_name(os_type, 1)
    block_device_mappings = [
        {
            "DeviceName": device_name,
            "Ebs": {
                "VolumeSize": volume_size,
                "VolumeType": volume_type,
                "Encrypted": volume_encrypted
            }
        }
    ]

    # Network Interface
    network_interface = {}
    if associate_public_ip:
        network_interface = {
            "AssociatePublicIpAddress": True,
            "DeviceIndex": 0,
            "Groups": [sg_id],
        }
        if subnet_id:
            network_interface["SubnetId"] = subnet_id

    # Launch EC2
    try:
        response = ec2.run_instances(
            ImageId=image_id,
            InstanceType=instance_type,
            KeyName=key_name if key_name else None,
            MinCount=min_count,
            MaxCount=max_count,
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ec2_name if ec2_name else "AutoInstance"}]
            }],
            BlockDeviceMappings=block_device_mappings,
            NetworkInterfaces=[network_interface] if network_interface else None
        )
        instance_id = response["Instances"][0]["InstanceId"]

        return f"✅ EC2 instance '{ec2_name if ec2_name else instance_id}' created successfully with ID: {instance_id}\n{key_status}\nSecurity Group ID: {sg_id}"

    except Exception as e:
        return f"❌ Error creating EC2 instance: {str(e)}"

##Deleting The Ec2 Instance 

from langchain.tools import tool
import boto3

def get_instance_id_by_name(ec2, instance_name: str) -> str:
    """
    Fetch the EC2 instance ID given its Name tag.
    """
    response = ec2.describe_instances(
        Filters=[{"Name": "tag:Name", "Values": [instance_name]}]
    )
    reservations = response.get("Reservations", [])
    if not reservations:
        raise ValueError(f"No EC2 instance found with name '{instance_name}'")
    instance = reservations[0]["Instances"][0]
    return instance["InstanceId"]

@tool("delete_ec2_instance", return_direct=True)
def delete_ec2_instance(
    instance_name: str,
    AWS_ACCESS_KEY_ID: str = None,
    SECRET_KEY_ACCESS: str = None
) -> str:
    """
    Terminates an EC2 instance by Name tag.
    """
    if not SECRET_KEY_ACCESS or not AWS_ACCESS_KEY_ID:
        return "❌ 'AWS_ACCESS_KEY_ID' and 'SECRET_KEY_ACCESS' are required."

    # Create EC2 client inside the function with user-provided credentials
    ec2 = boto3.client(
        "ec2",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=SECRET_KEY_ACCESS,
        region_name="ap-south-1"
    )

    try:
        instance_id = get_instance_id_by_name(ec2, instance_name)
        
        # Terminate instance
        ec2.terminate_instances(InstanceIds=[instance_id])
        
        return f"✅ EC2 instance '{instance_name}' with ID '{instance_id}' is being terminated."
    
    except ValueError as ve:
        return f"❌ {str(ve)}"
    except Exception as e:
        return f"❌ Error terminating EC2 instance: {str(e)}"


# --------------------------------------------------------------------------------
# 🔹 RDS TOOLS
# --------------------------------------------------------------------------------
from langchain.tools import tool
import boto3

@tool("create_rds_instance", return_direct=True)
def create_rds_instance(
    db_instance_identifier: str = None,  # Unique name for the RDS instance
    db_instance_class: str = "db.t3.micro",  # Instance size
    engine: str = "mysql",  # Database engine: mysql, postgres, oracle-se2, sqlserver-ex
    master_username: str = None,
    master_user_password: str = None,
    allocated_storage: int = 20,  # in GB
    publicly_accessible: bool = True,
    multi_az: bool = False,
    storage_type: str = "gp3",
    AWS_ACCESS_KEY_ID: str = None,
    SECRET_KEY_ACCESS: str = None,
) -> str:
    """
    Launch an RDS instance with specified configuration.
    Only essentials: db_instance_identifier, engine, master_username, master_user_password.
    """
    if not SECRET_KEY_ACCESS or not AWS_ACCESS_KEY_ID:
        return "❌ 'AWS_ACCESS_KEY_ID' and 'SECRET_KEY_ACCESS' are required."
    rds = boto3.client(
    "rds",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=SECRET_KEY_ACCESS,
    region_name="ap-south-1"
)

    if not db_instance_identifier:
        return "❌ 'db_instance_identifier' is required."
    if not master_username:
        return "❌ 'master_username' is required."
    if not master_user_password:
        return "❌ 'master_user_password' is required."

    try:
        response = rds.create_db_instance(
            DBInstanceIdentifier=db_instance_identifier,
            DBInstanceClass=db_instance_class,
            Engine=engine,
            MasterUsername=master_username,
            MasterUserPassword=master_user_password,
            AllocatedStorage=allocated_storage,
            PubliclyAccessible=publicly_accessible,
            MultiAZ=multi_az,
            StorageType=storage_type
        )

        return f"✅ RDS instance '{db_instance_identifier}' is being created. Status: {response['DBInstance']['DBInstanceStatus']}"

    except Exception as e:
        return f"❌ Error creating RDS instance: {str(e)}"


@tool("delete_rds_instance", return_direct=True)
def delete_rds_instance(
    db_instance_identifier: str,
    skip_final_snapshot: bool = True,
    AWS_ACCESS_KEY_ID: str = None,
    SECRET_KEY_ACCESS: str = None,
) -> str:
    """
    Deletes an RDS instance by DB identifier (name).
    - db_instance_identifier: Required. Example: "mydbinstance".
    - skip_final_snapshot: If True, no snapshot is taken before deletion.
      If False, AWS requires a FinalDBSnapshotIdentifier.
    """
    if not SECRET_KEY_ACCESS or not AWS_ACCESS_KEY_ID:
        return "❌ 'AWS_ACCESS_KEY_ID' and 'SECRET_KEY_ACCESS' are required."
      
    rds = boto3.client(
    "rds",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=SECRET_KEY_ACCESS,
    region_name="ap-south-1"
)
    try:
        if skip_final_snapshot:
            response = rds.delete_db_instance(
                DBInstanceIdentifier=db_instance_identifier,
                SkipFinalSnapshot=True
            )
        else:
            snapshot_id = f"{db_instance_identifier}-final-snapshot"
            response = rds.delete_db_instance(
                DBInstanceIdentifier=db_instance_identifier,
                SkipFinalSnapshot=False,
                FinalDBSnapshotIdentifier=snapshot_id
            )
        status = response["DBInstance"]["DBInstanceStatus"]
        return f"🗑️ Deletion initiated for RDS instance '{db_instance_identifier}'. Current status: {status}"
    except Exception as e:
        return f"❌ Error deleting RDS instance: {str(e)}"

#===================================================================
#REsource Explorer
#===================================================================

from langchain.tools import tool
import boto3

@tool("list_resources_in_region", return_direct=True)
def list_resources_in_region(
    region: str = None,  # Required: AWS region to query, e.g., "ap-south-1"
    AWS_ACCESS_KEY_ID: str = None,
    SECRET_KEY_ACCESS: str = None,
) -> str:
    """
    Lists all active AWS resources in the specified region using Resource Explorer.
    Only essential input: region.
    Returns a newline-separated string of resource ARNs.
    """
    if not SECRET_KEY_ACCESS or not AWS_ACCESS_KEY_ID:
        return "❌ 'AWS_ACCESS_KEY_ID' and 'SECRET_KEY_ACCESS' are required."
    if not region:
        return "❌ 'region' is required. Example: 'ap-south-1'"

    try:
        # Initialize Resource Explorer client for the specified region
        re_client = boto3.client(
            "resource-explorer-2",
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=SECRET_KEY_ACCESS,
            region_name=region
        )

        resources = []
        paginator = re_client.get_paginator("search")

        # Query all resources in the region
        for page in paginator.paginate(QueryString="service:*", MaxResults=100):
            for resource in page.get("Resources", []):
                resources.append(resource["Arn"])

        if not resources:
            return f"✅ No active resources found in region '{region}'."

        return "\n".join(resources)

    except Exception as e:
        return f"❌ Error fetching resources in region '{region}': {str(e)}"
