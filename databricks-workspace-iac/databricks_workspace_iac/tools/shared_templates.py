# shared_templates.py

import json

# Function to create Terraform variable dictionaries
def tf_var(name, description, required=False, default=None):
    return {
        "name": name,
        "description": description,
        "required": required,
        "default": default
    }

# Git clone command for fetching Terraform configurations
GIT_CLONE_COMMAND = 'git clone -b "$BRANCH" "https://$PAT@github.com/$GIT_ORG/$GIT_REPO.git" "iac_workspace"'

def generate_terraform_vars_json(tf_vars):
    vars_dict = {}
    for var in tf_vars:
        name = var['name']
        default = var.get('default')

        if default is not None:
            value = default
        else:
            value = "${" + name + "}"

        # Try to parse the default value as JSON
        try:
            # This will handle booleans, numbers, lists, and nulls
            value_parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            # If it's not valid JSON, treat it as a string
            value_parsed = value

        vars_dict[name] = value_parsed

    return json.dumps(vars_dict, indent=2)

# Common workspace creation template
COMMON_WORKSPACE_TEMPLATE = """
#!/bin/bash
export TERRAFORM_NO_COLOR=true
export TF_INPUT=false
set -euo pipefail

DATABRICKS_ICON_URL="{DATABRICKS_ICON_URL}"

apk add jq curl git --quiet

send_slack_message() {{
    local status=$1
    local message=$2
    local color=$3

    SLACK_MESSAGE_CONTENT=$(cat <<EOF
{{
    "attachments": [
        {{
            "color": "$color",
            "blocks": [
                {{
                    "type": "context",
                    "elements": [
                        {{
                            "type": "image",
                            "image_url": "{DATABRICKS_ICON_URL}",
                            "alt_text": "Databricks Logo"
                        }},
                        {{
                            "type": "mrkdwn",
                            "text": "🔧 Databricks workspace provisioning $status"
                        }}
                    ]
                }},
                {{
                    "type": "section",
                    "text": {{
                        "type": "mrkdwn",
                        "text": "$message"
                    }}
                }}
            ]
        }}
    ]
}}
EOF
    )

    curl -X POST "https://slack.com/api/chat.postMessage" \\
        -H "Authorization: Bearer $SLACK_API_TOKEN" \\
        -H "Content-Type: application/json" \\
        --data "$SLACK_MESSAGE_CONTENT"
}}

echo -e "🛠️ Setting up Databricks workspace on {CLOUD_PROVIDER}..."
{GIT_CLONE_COMMAND}

cd iac_workspace/{TERRAFORM_MODULE_PATH}

echo -e "🔍 Validating input parameters..."
check_var() {{
    var_name="$1"
    if [ -z "${{!var_name:-}}" ]]; then
        echo "❌ Error: ${{var_name}} is not set."
        send_slack_message "failed" "❌ Error: ${{var_name}} is not set." "danger"
        exit 1
    fi
}}
# Check required variables
{CHECK_REQUIRED_VARS}

echo -e "✅ All required parameters are set."
echo -e "🚀 Initializing Terraform..."
{TERRAFORM_INIT_COMMAND}

echo -e "🏗️ Applying Terraform configuration..."
cat << EOF > terraform.tfvars.json
{TERRAFORM_VARS_JSON}
EOF

if ! terraform apply -auto-approve -var-file=terraform.tfvars.json; then
    error_message=$(terraform show -json | jq -r '.values.root_module.resources[] | select(.type == "error") | .values.summary')
    truncated_error=$(echo "$error_message" | tail -n 10)
    escaped_error=$(echo "$truncated_error" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\\n/\\\\n/g')
    send_slack_message "failed" "*Terraform apply failed. Last 10 lines of error:*\n\`\`\`$escaped_error\`\`\`" "danger"
    exit 1
fi

echo "📊 Capturing Terraform output..."
tf_output=$(terraform output -json)
workspace_url=$(echo "$tf_output" | jq -r '.databricks_host.value // empty')
workspace_url="${{workspace_url:-"{FALLBACK_WORKSPACE_URL}"}}"

echo "🔍 Getting backend config..."
backend_config=$(terraform show -json | jq -r '.values.backend_config // empty')

echo "💬 Preparing Slack message..."
success_message=$(cat <<EOF
🎉 Your *Databricks workspace* was successfully provisioned using *Terraform*, following *Infrastructure as Code (IAC)* best practices.

*Module Source code*: <https://github.com/$GIT_ORG/{GIT_REPO}|Explore the module>

*To import the state locally, follow these steps:*
1. Configure your Terraform backend:
\`\`\`
terraform {{
  backend "{BACKEND_TYPE}" {{
    $backend_config
  }}
}}
\`\`\`
2. Run the import command:
\`\`\`
{IMPORT_COMMAND}
\`\`\`
EOF
)

send_slack_message "succeeded" "$success_message" "good"

echo -e "✅ Databricks workspace setup complete!"
"""

# Workspace template with error handling
WORKSPACE_TEMPLATE_WITH_ERROR_HANDLING = """{WORKSPACE_TEMPLATE}"""
