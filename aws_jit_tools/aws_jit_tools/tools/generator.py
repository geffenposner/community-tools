import inspect
import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any, List
from kubiya_sdk.tools import FileSpec
from kubiya_sdk.tools.registry import tool_registry
from .base import AWSJITTool

logger = logging.getLogger(__name__)

class ToolGenerator:
    def __init__(self):
        self.config = self._load_config()
        if not self.config:
            logger.error("Failed to load configuration")
            return
        logger.info(f"Loaded configuration with {len(self.config.get('tools', {}))} tools")

    def _load_config(self) -> Dict[str, Any]:
        """Load tool configuration from JSON."""
        try:
            config_path = Path(__file__).resolve().parent.parent.parent / 'aws_jit_config.json'
            logger.info(f"Loading config from: {config_path}")
            if not config_path.exists():
                logger.error(f"Config file not found at {config_path}")
                return {}
            with open(config_path) as f:
                config = json.load(f)
                logger.info("Successfully loaded config")
                return config
        except Exception as e:
            logger.error(f"Failed to load config: {str(e)}")
            return {}

    def generate_tools(self) -> List[Any]:
        """Generate tools based on configuration."""
        tools = []
        try:
            for tool_id, config in self.config.get('tools', {}).items():
                logger.info(f"Generating tool for: {tool_id}")
                tool = self._create_tool(tool_id, config)
                if tool:
                    tools.append(tool)
                    # Register tool with jit_access_to_ prefix
                    tool_name = f"jit_access_to_{tool_id}"
                    logger.info(f"Registering tool: {tool_name}")
                    tool_registry.register("aws_jit", tool)
                    logger.info(f"Successfully registered tool: {tool_name}")

            logger.info(f"Generated {len(tools)} tools")
            return tools
        except Exception as e:
            logger.error(f"Error generating tools: {str(e)}")
            return []

    def _create_tool(self, tool_id: str, config: Dict[str, Any]) -> Any:
        """Create individual tool based on configuration."""
        try:
            from aws_jit_tools.scripts.access_handler import AWSAccessHandler
            
            tool = AWSJITTool(
                name=f"jit_access_to_{tool_id}",
                description=config['description'],
                content=self._generate_tool_content(config),
                env=[
                    "AWS_PROFILE",
                    "KUBIYA_USER_EMAIL",
                    "KUBIYA_API_KEY",
                    "KUBIYA_USER_ORG",
                    "KUBIYA_AGENT_PROFILE"
                ],
                with_files=[
                    FileSpec(
                        destination="/opt/scripts/access_handler.py",
                        content=inspect.getsource(AWSAccessHandler)
                    )
                ],
                mermaid=self._generate_mermaid(tool_id, config)
            )
            logger.info(f"Created tool: jit_access_to_{tool_id}")
            return tool
        except Exception as e:
            logger.error(f"Error creating tool {tool_id}: {str(e)}")
            return None

    def _generate_tool_content(self, config: Dict[str, Any]) -> str:
        return f"""
#!/bin/bash
set -e

echo "Installing required packages..."
apk add --no-cache python3 py3-pip
pip3 install boto3

echo "Setting environment variables..."
export AWS_ACCOUNT_ID="{config['account_id']}"
export PERMISSION_SET_NAME="{config['permission_set']}"

echo "Executing access handler..."
python3 /opt/scripts/access_handler.py
"""

    def _generate_mermaid(self, tool_id: str, config: Dict[str, Any]) -> str:
        return f"""
sequenceDiagram
    participant U as User
    participant T as Tool
    participant I as IAM Identity Center
    participant A as AWS Account

    U->>+T: Request {tool_id} access
    T->>+I: Find user by email
    I-->>-T: User found
    T->>+A: Assign permission set
    A-->>-T: Access granted
    T-->>-U: Access confirmed
""" 