import json
from typing import List, Literal, Optional
from pydantic import BaseModel, Field
from app.utils.logging_decorator import logging_decorator, logger
import boto3
from langchain.tools import tool
import os
from dotenv import load_dotenv

load_dotenv()
# pydantic classes
class ListS3BucketsInput(BaseModel):
    """Input schema for listing S3 buckets."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")


class ListS3BucketsOutput(BaseModel):
    """Output schema containing the list of S3 buckets."""
    buckets: List[str] = Field(..., description="Names of all S3 buckets in the AWS account.")

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
        delete_s3_bucket
    ]

# Tools
@tool(args_schema=ListS3BucketsInput, return_direct=True)
@logging_decorator()
def list_s3_buckets():
    s3_client = boto3.client(
        "s3",
        aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
,
        aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")

    )
    """List all S3 buckets in the AWS account."""
    response = s3_client.list_buckets()
    return [bucket['Name'] for bucket in response['Buckets']]


@tool(args_schema=GetBucketRegionInput, return_direct=True)
@logging_decorator()
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

# @tool(args_schema=SetBucketPolicyInput, return_direct=True)
# @logging_decorator()
# def set_s3_bucket_policy(aws_access_key_id: str, aws_secret_access_key: str, bucket_name: str, policy_type: str, custom_policy: Optional[dict] = None):
#     """
#     Set the bucket policy or ACL for an S3 bucket.
#     Supports: 'private', 'public-read', and 'custom' policies.
#     """
#     s3_client = boto3.client(
#         "s3",
#         aws_access_key_id=aws_access_key_id,
#         aws_secret_access_key=aws_secret_access_key
#     )

    

#     try:
#         if policy_type == "private":
#             s3_client.put_bucket_acl(Bucket=bucket_name, ACL="private")
#             return {"status": f"Bucket '{bucket_name}' set to private."}

#         elif policy_type == "public-read":
#             s3_client.put_bucket_acl(Bucket=bucket_name, ACL="public-read")
#             return {"status": f"Bucket '{bucket_name}' set to public-read."}

#         elif policy_type == "custom":
#             if not custom_policy:
#                 return {"status": "Custom policy not provided for policy_type='custom'."}

#             s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(custom_policy))
#             return {"status": f"Custom policy applied to bucket '{bucket_name}'."}

#         else:
#             return {"status": "Invalid policy_type. Choose from: private, public-read, custom."}

#     except Exception as e:
#         logger.error(f"Error setting bucket policy: {str(e)}")
#         return {"status": f"Failed to update policy: {str(e)}"}
    
    
@tool(args_schema=EnableS3VersioningInput, return_direct=True)
@logging_decorator()
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
@logging_decorator()
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
@logging_decorator()
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
@logging_decorator()
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
@logging_decorator()
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
@logging_decorator()
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
@logging_decorator()
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
@logging_decorator()
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
@logging_decorator()
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