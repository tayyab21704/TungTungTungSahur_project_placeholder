def map_tool_to_args(tool_name):
    """
    Maps a tool name to its arguments.

    Args:
        tool_name (str): The name of the tool.

    Returns:
        dict or None: A dictionary of arguments for the tool, or None if the tool is not found.
    """
    return tool_args_map.get(tool_name)

tool_args_map = {
  "list_s3_buckets": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string", 
        "required": True,
        "description": "AWS secret access key for authentication"
      },
    }
  },
  "get_bucket_region": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      },
      "bucket_name": {
        "type": "string",
        "required": True,
        "description": "Name of the S3 bucket"
      }
    }
  },
  "set_s3_bucket_policy": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      },
      "bucket_name": {
        "type": "string",
        "required": True,
        "description": "Name of the S3 bucket"
      },
      "policy_type": {
        "type": "string",
        "required": True,
        "description": "Type of policy to apply: 'private', 'public-read', or 'custom'"
      },
      "custom_policy": {
        "type": "dict",
        "required": False,
        "description": "Custom JSON policy if policy_type is 'custom'"
      }
    }
  },
  "enable_s3_versioning": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      },
      "bucket_name": {
        "type": "string",
        "required": True,
        "description": "Name of the S3 bucket"
      },
      "status": {
        "type": "string",
        "required": True,
        "description": "Versioning status: 'Enabled' or 'Suspended'"
      }
    }
  },
  "set_s3_bucket_encryption": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      },
      "bucket_name": {
        "type": "string",
        "required": True,
        "description": "Name of the S3 bucket"
      },
      "encryption_type": {
        "type": "string",
        "required": True,
        "description": "Encryption type: AES256 for SSE-S3 or aws:kms for SSE-KMS"
      },
      "kms_key_id": {
        "type": "string",
        "required": False,
        "description": "Optional KMS Key ID (required if encryption_type is aws:kms)"
      }
    }
  },
  "configure_s3_object_lock": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      },
      "bucket_name": {
        "type": "string",
        "required": True,
        "description": "Name of the S3 bucket"
      },
      "object_lock_enabled": {
        "type": "boolean",
        "required": True,
        "description": "Enable Object Lock (True/False)"
      },
      "lock_mode": {
        "type": "string",
        "required": True,
        "description": "Object Lock mode: GOVERNANCE or COMPLIANCE"
      },
      "retention_days": {
        "type": "integer",
        "required": True,
        "description": "Retention period in days"
      }
    }
  },
  "configure_lifecycle_rule": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key"
      },
      "bucket_name": {
        "type": "string",
        "required": True,
        "description": "S3 bucket name"
      },
      "rule_id": {
        "type": "string",
        "required": True,
        "description": "Unique ID for the lifecycle rule"
      },
      "transition_days": {
        "type": "integer",
        "required": True,
        "description": "Number of days after which transition occurs"
      },
      "storage_class": {
        "type": "string",
        "required": True,
        "description": "Storage class to transition to: GLACIER or DEEP_ARCHIVE"
      }
    }
  },
  "configure_bucket_logging": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      },
      "bucket_name": {
        "type": "string",
        "required": True,
        "description": "The name of the S3 bucket to configure logging for"
      },
      "target_bucket": {
        "type": "string",
        "required": True,
        "description": "The bucket where access logs will be stored"
      },
      "target_prefix": {
        "type": "string",
        "required": False,
        "description": "Optional prefix for log object keys"
      },
      "enable": {
        "type": "boolean",
        "required": True,
        "description": "Set True to enable logging, False to disable"
      }
    }
  },
  "configure_bucket_replication": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      },
      "source_bucket": {
        "type": "string",
        "required": True,
        "description": "The source S3 bucket for replication"
      },
      "destination_bucket_arn": {
        "type": "string",
        "required": True,
        "description": "ARN of the destination S3 bucket"
      },
      "role_arn": {
        "type": "string",
        "required": True,
        "description": "IAM Role ARN that grants S3 permissions for replication"
      },
      "replication_id": {
        "type": "string",
        "required": True,
        "description": "Unique ID for replication rule"
      },
      "status": {
        "type": "string",
        "required": False,
        "description": "Replication status. Options: Enabled, Disabled"
      },
      "prefix": {
        "type": "string",
        "required": False,
        "description": "Object key prefix for replication. Empty means all objects"
      }
    }
  },
  "configure_bucket_event_notification": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      },
      "bucket_name": {
        "type": "string",
        "required": True,
        "description": "The S3 bucket to configure notifications for"
      },
      "lambda_function_arn": {
        "type": "string",
        "required": True,
        "description": "ARN of the Lambda function to invoke on events"
      },
      "events": {
        "type": "list",
        "required": True,
        "description": "List of events to trigger notifications. Example: ['s3:ObjectCreated:*', 's3:ObjectRemoved:*']"
      }
    }
  },
  "create_s3_bucket": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      },
      "bucket_name": {
        "type": "string",
        "required": True,
        "description": "Unique name for the new S3 bucket"
      },
      "region": {
        "type": "string",
        "required": True,
        "description": "AWS region for the S3 bucket, e.g., ap-south-1"
      }
    }
  },
  "delete_s3_bucket": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      },
      "bucket_name": {
        "type": "string",
        "required": True,
        "description": "The name of the bucket to delete"
      }
    }
  },
  "create_iam_user": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key"
      },
      "user_name": {
        "type": "string",
        "required": True,
        "description": "Name of the IAM user to create"
      }
    }
  },
  "delete_iam_user": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key"
      },
      "user_name": {
        "type": "string",
        "required": True,
        "description": "Name of the IAM user to delete"
      }
    }
  },
  "attach_policy_to_user": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key"
      },
      "user_name": {
        "type": "string",
        "required": True,
        "description": "Name of the IAM user"
      },
      "policy_arn": {
        "type": "string",
        "required": True,
        "description": "ARN of the policy to attach (e.g., arn:aws:iam::aws:policy/AmazonS3FullAccess)"
      }
    }
  },
  "detach_policy_from_user": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key"
      },
      "user_name": {
        "type": "string",
        "required": True,
        "description": "Name of the IAM user"
      },
      "policy_arn": {
        "type": "string",
        "required": True,
        "description": "ARN of the policy to detach"
      }
    }
  },
  "create_access_key_for_user": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      },
      "user_name": {
        "type": "string",
        "required": True,
        "description": "The name of the IAM user to create keys for"
      }
    }
  },
  "create_custom_policy": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key"
      },
      "policy_name": {
        "type": "string",
        "required": True,
        "description": "Name of the policy to create"
      },
      "policy_document": {
        "type": "string",
        "required": True,
        "description": "JSON string of the policy document"
      }
    }
  },
  "rotate_access_key": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key"
      },
      "user_name": {
        "type": "string",
        "required": True,
        "description": "Name of the IAM user"
      }
    }
  },
  "attach_instance_profile_to_ec2": {
    "arguments": {
      "aws_access_key_id": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID"
      },
      "aws_secret_access_key": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key"
      },
      "region_name": {
        "type": "string",
        "required": True,
        "description": "AWS region name"
      },
      "instance_id": {
        "type": "string",
        "required": True,
        "description": "EC2 instance ID"
      },
      "instance_profile_name": {
        "type": "string",
        "required": True,
        "description": "The name of the IAM instance profile to attach"
      }
    }
  },
  "create_ec2_instance": {
    "arguments": {
      "friendly_name": {
        "type": "string",
        "required": True,
        "description": "Friendly name of the AMI, e.g., 'Windows_Server 2019'"
      },
      "instance_type": {
        "type": "string",
        "required": True,
        "description": "EC2 instance type, e.g., 't3.micro'"
      },
      "min_count": {
        "type": "integer",
        "required": True,
        "description": "Minimum number of instances to launch"
      },
      "max_count": {
        "type": "integer",
        "required": True,
        "description": "Maximum number of instances to launch"
      },
      "key_name": {
        "type": "string",
        "required": False,
        "description": "Optional KeyPair name for SSH/RDP access"
      },
      "ec2_name": {
        "type": "string",
        "required": False,
        "description": "Optional tag name for the EC2 instance"
      },
      "os_type": {
        "type": "string",
        "required": False,
        "description": "OS type, 'linux' or 'windows'. Defaults to 'linux'"
      },
      "volume_size": {
        "type": "integer",
        "required": False,
        "description": "Root volume size in GB. Defaults to 20"
      },
      "volume_type": {
        "type": "string",
        "required": False,
        "description": "Volume type, e.g., gp3, gp2. Defaults to 'gp3'"
      },
      "volume_encrypted": {
        "type": "boolean",
        "required": False,
        "description": "Whether the root volume is encrypted. Defaults to True"
      },
      "associate_public_ip": {
        "type": "boolean",
        "required": False,
        "description": "Whether to assign a public IP. Defaults to True"
      },
      "subnet_id": {
        "type": "string",
        "required": False,
        "description": "Optional subnet ID for network interface"
      },
      "security_group_name": {
        "type": "string",
        "required": False,
        "description": "Security Group name. Defaults to 'AutoSG'"
      },
      "AWS_ACCESS_KEY_ID": {
        "type": "string",
        "required": True,
        "description": "AWS Access Key ID for the user"
      },
      "SECRET_KEY_ACCESS": {
        "type": "string",
        "required": True,
        "description": "AWS Secret Access Key for the user"
      }
    }
  },
  "delete_ec2_instance": {
    "arguments": {
      "instance_name": {
        "type": "string",
        "required": True,
        "description": "The Name tag of the EC2 instance to terminate"
      },
      "AWS_ACCESS_KEY_ID": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "SECRET_KEY_ACCESS": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      }
    }
  },
  "create_rds_instance": {
    "arguments": {
      "db_instance_identifier": {
        "type": "string",
        "required": True,
        "description": "Unique identifier for the RDS instance, e.g., 'mydatabase'"
      },
      "db_instance_class": {
        "type": "string",
        "required": False,
        "description": "RDS instance size/class. Default: db.t3.micro"
      },
      "engine": {
        "type": "string",
        "required": False,
        "description": "Database engine. Options: mysql, postgres, oracle-se2, sqlserver-ex"
      },
      "master_username": {
        "type": "string",
        "required": True,
        "description": "Master username for the RDS instance"
      },
      "master_user_password": {
        "type": "string",
        "required": True,
        "description": "Master user password for the RDS instance"
      },
      "allocated_storage": {
        "type": "integer",
        "required": False,
        "description": "Storage size in GB. Default: 20"
      },
      "publicly_accessible": {
        "type": "boolean",
        "required": False,
        "description": "Whether the instance is publicly accessible. Default: True"
      },
      "multi_az": {
        "type": "boolean",
        "required": False,
        "description": "Enable Multi-AZ deployment for high availability. Default: False"
      },
      "storage_type": {
        "type": "string",
        "required": False,
        "description": "Storage type. Default: gp3"
      },
      "AWS_ACCESS_KEY_ID": {
        "type": "string",
        "required": True,
        "description": "AWS Access Key ID for authentication"
      },
      "SECRET_KEY_ACCESS": {
        "type": "string",
        "required": True,
        "description": "AWS Secret Access Key for authentication"
      }
    }
  },
  "delete_rds_instance": {
    "arguments": {
      "db_instance_identifier": {
        "type": "string",
        "required": True,
        "description": "Unique identifier of the RDS instance to delete, e.g., 'mydatabase'"
      },
      "skip_final_snapshot": {
        "type": "boolean",
        "required": False,
        "description": "If True, no final snapshot will be created. Default: True"
      },
      "AWS_ACCESS_KEY_ID": {
        "type": "string",
        "required": True,
        "description": "AWS Access Key ID for authentication"
      },
      "SECRET_KEY_ACCESS": {
        "type": "string",
        "required": True,
        "description": "AWS Secret Access Key for authentication"
      }
    }
  },
  "list_resources_in_region": {
    "arguments": {
      "region": {
        "type": "string",
        "required": True,
        "description": "AWS region to query, e.g., 'ap-south-1'"
      },
      "AWS_ACCESS_KEY_ID": {
        "type": "string",
        "required": True,
        "description": "AWS access key ID for authentication"
      },
      "SECRET_KEY_ACCESS": {
        "type": "string",
        "required": True,
        "description": "AWS secret access key for authentication"
      }
    }
  }
}