from kubiya_sdk.tools.registry import tool_registry
from kubiya_sdk.tools.models import FileSpec, Arg
from pathlib import Path
from .base import AWSJITTool
from ..scripts.config_loader import get_access_configs, get_s3_configs

# Get access handler code
HANDLER_PATH = Path(__file__).parent.parent / 'scripts' / 'access_handler.py'
with open(HANDLER_PATH) as f:
    HANDLER_CODE = f.read()

# Initialize tools dictionary at module level
tools = {}
s3_tools = {}

def create_jit_tool(config, action):
    """Create a JIT tool from configuration."""
    args = []
    
    if action == "revoke":
        args.append(
            Arg(name="user_email", description="The email of the user to revoke access for", type="str")
        )
    elif action == "grant":
        args.append(
            Arg(name="duration", 
                description=f"Duration for the access token to be valid (maximum {config['session_duration']}) - needs to be in ISO8601 format eg: 'PT1H'", 
                type="str", 
                # This is the recommended duration for the access token (controlled on scripts/config) - does not guarantee the duration
                default=config['session_duration'])
        )

    # Define file specifications for all necessary files
    file_specs = [
        FileSpec(destination="/opt/scripts/access_handler.py", content=HANDLER_CODE),
        FileSpec(destination="/opt/scripts/utils/aws_utils.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'aws_utils.py').read()),
        FileSpec(destination="/opt/scripts/utils/notifications.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'notifications.py').read()),
        FileSpec(destination="/opt/scripts/utils/slack_client.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'slack_client.py').read()),
        FileSpec(destination="/opt/scripts/utils/slack_messages.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'slack_messages.py').read()),
        FileSpec(destination="/opt/scripts/utils/webhook_handler.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'webhook_handler.py').read()),
    ]

    mermaid_diagram = f"""
    sequenceDiagram
        participant U as 👤 User
        participant T as 🛠️ Tool
        participant I as 🔍 IAM Identity Center
        participant S as 🔐 SSO Admin
        participant N as 📧 Notifications

        U->>+T: {"Request Access" if action == "grant" else "Request Revocation"}
        T->>+I: 🔎 Find User by Email
        I-->>-T: 📄 User Details
        T->>+S: 🔑 Get Permission Set: {config['permission_set']}
        S-->>-T: 🆔 Permission Set ARN
        T->>+S: { "🔧 Create Assignment" if action == "grant" else "❌ Delete Assignment" }
        Note over T,S: Account: {config['account_id']}
        S-->>-T: { "✅ Assignment Created" if action == "grant" else "🔓 Assignment Deleted" }
        T->>+N: Send Notification
        N-->>-T: Notification Sent
        T-->>-U: { "Access Granted 🎉" if action == "grant" else "Access Revoked 🔒" }
    """

    action_prefix = "jit_session_" + ("grant_" if action == "grant" else "revoke_")
    tool_name = f"{action_prefix}{config['name'].lower().replace(' ', '_')}"

    return AWSJITTool(
        name=tool_name,
        description=f"{config['description']} ({action.capitalize()}) - {'Grants' if action == 'grant' else 'Revokes'} access to AWS account {config['account_id']} using {config['permission_set']} permission set",
        args=args,
        content=f"""#!/bin/bash
set -e
echo ">> Processing request... ⏳"

# Install dependencies only if not found
python -c "import boto3, requests, jinja2, jsonschema, argparse" 2>/dev/null || pip install -q boto3 requests jinja2 jsonschema argparse > /dev/null 2>&1

export AWS_ACCOUNT_ID="{config['account_id']}"
export PERMISSION_SET_NAME="{config['permission_set']}"
export MAX_DURATION="{config['session_duration']}"

# Create __init__ files to cover the python project
touch /opt/scripts/__init__.py
touch /opt/scripts/utils/__init__.py

# Run access handler
echo ">> Just a moment... ⏳"
python /opt/scripts/access_handler.py {action} {"--user-email $KUBIYA_USER_EMAIL" if action == "grant" else "--user-email {{.user_email}}"} {"--duration {{.duration}}" if action == "grant" else "--duration PT1H"}
""",
        with_files=file_specs,
        mermaid=mermaid_diagram
    )

def create_s3_jit_tool(config, action):
    """Create a JIT tool for S3 bucket access from configuration."""
    args = []
    
    if action == "revoke":
        args.extend([
            Arg(name="user_email", description="The email of the user to revoke access for", type="str"),
            Arg(name="bucket_name", description="Name of the S3 bucket", type="str")
        ])
    elif action == "grant":
        args.extend([
            Arg(name="duration", 
                description=f"Duration for the access (maximum {config['session_duration']}) - ISO8601 format (e.g., 'PT1H')", 
                type="str", 
                default=config['session_duration']),
            Arg(name="bucket_name", description="Name of the S3 bucket", type="str")
        ])

    # Define file specifications for all necessary files
    file_specs = [
        FileSpec(destination="/opt/scripts/access_handler.py", content=HANDLER_CODE),
        FileSpec(destination="/opt/scripts/utils/aws_utils.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'aws_utils.py').read()),
        FileSpec(destination="/opt/scripts/utils/notifications.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'notifications.py').read()),
        FileSpec(destination="/opt/scripts/utils/slack_client.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'slack_client.py').read()),
        FileSpec(destination="/opt/scripts/utils/slack_messages.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'slack_messages.py').read()),
        FileSpec(destination="/opt/scripts/utils/webhook_handler.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'webhook_handler.py').read()),
    ]

    tool_name = f"s3_{action}_{config['name'].lower().replace(' ', '_')}"

    return AWSJITTool(
        name=tool_name,
        description=f"{config['description']} ({action.capitalize()}) - {'Grants' if action == 'grant' else 'Revokes'} access to S3 bucket: {{.bucket_name}}",
        args=args,
        content=f"""#!/bin/bash
set -e
echo ">> Processing request... ⏳"

# Install dependencies
pip install -q boto3 requests jinja2 jsonschema argparse

export POLICY_TEMPLATE="{config['policy_template']}"
export MAX_DURATION="{config['session_duration']}"

touch /opt/scripts/__init__.py
touch /opt/scripts/utils/__init__.py

# Run access handler
python /opt/scripts/access_handler.py {action} --user-email "{{.user_email}}" --bucket-name "{{.bucket_name}}" {"--duration {{.duration}}" if action == "grant" else ""}
""",
        with_files=file_specs,
        # ... rest of the code ...
    )

# Load configurations and create tools
try:
    ACCESS_CONFIGS = get_access_configs()
    S3_ACCESS_CONFIGS = get_s3_configs()

    # Create and register tools
    for action in ["grant", "revoke"]:
        for access_type, config in ACCESS_CONFIGS.items():
            tool = create_jit_tool(config, action)
            tools[tool.name] = tool
            tool_registry.register("aws_jit", tool)

        for access_type, config in S3_ACCESS_CONFIGS.items():
            tool = create_s3_jit_tool(config, action)
            s3_tools[tool.name] = tool
            tool_registry.register("aws_jit", tool)

except Exception as e:
    print(f"Error loading configurations: {e}")
    raise

# Export all tools
__all__ = ['tools', 's3_tools'] 
