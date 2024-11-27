from kubiya_sdk.tools.registry import tool_registry
from kubiya_sdk.tools.models import FileSpec, Arg
from pathlib import Path
from .base import AWSJITTool

# Get access handler code
HANDLER_PATH = Path(__file__).parent.parent / 'scripts' / 'access_handler.py'
with open(HANDLER_PATH) as f:
    HANDLER_CODE = f.read()

# Configuration for different access types
ACCESS_CONFIGS = {
    "Solution Engineer Access to Staging": {
        "name": "jit_se_access",
        "description": "Grants SE (Solutions Engineer) access to march17test2 AWS account (162755939319)",
        "account_id": "162755939319",
        "permission_set": "CustomViewOnlyAccess",
        "session_duration": "PT1H"
    },
}

def create_jit_tool(config, action):
    """Create a JIT tool from configuration."""
    args = []
    
    if action == "revoke":
        args.append(
            Arg(name="User Email", description="The email of the user to revoke access for", type="str")
        )
    elif action == "grant":
        args.append(
            Arg(name="Duration (TTL)", description="Duration for the access token to be valid (defaults to 1 hour) - needs to be in ISO8601 format eg: 'PT1H'", type="str", default="PT1H")
        )

    # Define file specifications for all necessary files
    file_specs = [
        FileSpec(destination="/opt/scripts/access_handler.py", content=HANDLER_CODE),
        FileSpec(destination="/opt/scripts/__init__.py", content=open(Path(__file__).parent.parent / 'scripts' / '__init__.py').read()),
        FileSpec(destination="/opt/scripts/utils/__init__.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / '__init__.py').read()),
        FileSpec(destination="/opt/scripts/utils/aws_utils.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'aws_utils.py').read()),
        FileSpec(destination="/opt/scripts/utils/notifications.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'notifications.py').read()),
        FileSpec(destination="/opt/scripts/utils/slack_client.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'slack_client.py').read()),
        FileSpec(destination="/opt/scripts/utils/slack_messages.py", content=open(Path(__file__).parent.parent / 'scripts' / 'utils' / 'slack_messages.py').read()),
    ]

    return AWSJITTool(
        name=f"{config['name']}_{action}",
        description=f"{config['description']} ({action.capitalize()})",
        args=args,
        content=f"""#!/bin/bash
set -e

export AWS_ACCOUNT_ID="{config['account_id']}"
export PERMISSION_SET_NAME="{config['permission_set']}"

# Install dependencies
pip install -q boto3 requests > /dev/null
# Run access handler
echo ">> Processing request... ⏳"
python /opt/scripts/access_handler.py {action} --user-email $1
""",
        with_files=file_specs,
        mermaid=f"""
    sequenceDiagram
        participant U as 👤 User
        participant T as 🛠️ Tool
        participant I as 🔍 IAM
        participant S as 🔐 SSO

        U->>+T: Request {config['permission_set']} {action.capitalize()}
        T->>+I: 🔎 Find/Create User
        I-->>-T: 📄 User Details
        T->>+S: 🔑 Get Permission Set
        S-->>-T: 🆔 Permission Set ARN
        T->>+S: { "🔧 Assign Permissions" if action == "grant" else "❌ Revoke Permissions" }
        S-->>-T: { "✅ Assignment Complete" if action == "grant" else "🔓 Revocation Complete" }
        T-->>-U: Access {action.capitalize()}ed 🎉
    """
    )

# Create tools from configuration for both grant and revoke actions
tools = {
    f"{access_type}_{action}": create_jit_tool(config, action)
    for access_type, config in ACCESS_CONFIGS.items()
    for action in ["grant", "revoke"]
}

# Register all tools
for tool in tools.values():
    tool_registry.register("aws_jit", tool)

# Export all tools
__all__ = list(tools.keys())
globals().update(tools) 