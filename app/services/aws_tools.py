from typing import List
from pydantic import BaseModel, Field
from app.utils.logging_decorator import logging_decorator, logger
import boto3
from langchain.tools import tool
from typing import Optional


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


#==================================================================================================
#resource ecplorer
#=====================================================================================================
class ListResourcesInRegionInput(BaseModel):
    """Input schema for listing AWS resources in a region via Resource Explorer."""
    region: str = Field(..., description="AWS region to query, e.g., 'ap-south-1'.")
    AWS_ACCESS_KEY_ID: str = Field(..., description="AWS access key ID for authentication.")
    SECRET_KEY_ACCESS: str = Field(..., description="AWS secret access key for authentication.")




# get function
def get_all_aws_tools():
    return

#===============================================================================
# Tools
#================================================================================
# --------------------------------------------------------------------------------
# 🔹 EC2 TOOLS
# --------------------------------------------------------------------------------


##EC2 TOOL WITH boto3 client As ec2. 
from langchain.tools import tool
import boto3

from langchain.tools import tool
import boto3
import os


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
