from typing import List
from pydantic import BaseModel, Field
from app.utils.logging_decorator import logging_decorator, logger
import boto3
from langchain.tools import tool

# pydantic classes
class ListS3BucketsInput(BaseModel):
    """Input schema for listing S3 buckets."""
    aws_access_key_id: str = Field(..., description="AWS access key ID for authentication.")
    aws_secret_access_key: str = Field(..., description="AWS secret access key for authentication.")


class ListS3BucketsOutput(BaseModel):
    """Output schema containing the list of S3 buckets."""
    buckets: List[str] = Field(..., description="Names of all S3 buckets in the AWS account.")

# get function
def get_all_aws_tools():
    return [list_s3_buckets]

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