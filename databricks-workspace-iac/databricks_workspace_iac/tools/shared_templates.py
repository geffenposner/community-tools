# Shared templates for both AWS and Azure

# Function to create Terraform variable dictionaries
def tf_var(name, description, required=False, default=None):
    return {
        "name": name,
        "description": description,
        "required": required,
        "default": default
    }

# Git clone command for fetching Terraform configurations
GIT_CLONE_COMMAND = 'git clone -b "$BRANCH" https://"$PAT"@github.com/"$GIT_ORG"/"$GIT_REPO".git $DIR'

# Common workspace creation template
COMMON_WORKSPACE_TEMPLATE = """
set -e
apk add jq
echo "🛠️ Setting up Databricks workspace on {CLOUD_PROVIDER}..."
{GIT_CLONE_COMMAND}
cd {TERRAFORM_DIR}

echo "🔍 Validating input parameters..."

# Function to check if a variable is set
check_var() {{
    if [ -z "${{1}}" ]; then
        echo "❌ Error: ${{1}} is not set. Please provide it as an argument or environment variable."
        exit 1
    fi
}}

# Check required variables
{CHECK_REQUIRED_VARS}

echo "✅ All required parameters are set."

echo "🚀 Initializing Terraform..."
{TERRAFORM_INIT_COMMAND}

echo "🏗️ Applying Terraform configuration..."
tf_vars=""
{TERRAFORM_VARS_COMMAND}
terraform apply -auto-approve $tf_vars

echo "📊 Capturing Terraform output..."
tf_output=$(terraform output -json || echo "{{}}")
workspace_url=$(echo "$tf_output" | jq -r '.databricks_host.value // empty')
workspace_url=${{workspace_url:-"{FALLBACK_WORKSPACE_URL}"}}

echo "🔍 Getting backend config..."
backend_config=$(terraform show -json | jq -r '.values.backend_config // empty')

echo "💬 Preparing Slack message..."
SLACK_MESSAGE=$(cat <<EOF
{{
    "blocks": [
        {{
            "type": "context",
            "elements": [
                {{
                    "type": "image",
                    "image_url": "https://static-00.iconduck.com/assets.00/terraform-icon-1803x2048-hodrzd3t.png",
                    "alt_text": "Terraform Logo"
                }},
                {{
                    "type": "mrkdwn",
                    "text": "🔧 Your *Databricks workspace* was provisioned using *Terraform*, following *Infrastructure as Code (IAC)* best practices for smooth future changes and management. \\n\\n🚀 *Going forward*, you can easily manage and track updates on your infrastructure.\\n\\n🔗 *Module Source code*: <$workspace_url|Explore the module>"
                }}
            ]
        }},
        {{
            "type": "section",
            "text": {{
                "type": "mrkdwn",
                "text": "*To import the state locally, follow these steps:*\\n\\n1. Configure your Terraform backend:\\n\`\`\`\\nterraform {{\\n  backend \\"{BACKEND_TYPE}\\" {{\\n    $backend_config\\n  }}\\n}}\\n\`\`\`\\n2. Run the import command:\\n\`\`\`\\n{IMPORT_COMMAND}\\n\`\`\`"
            }}
        }}
    ]
}}
EOF
)

echo "📤 Sending Slack message..."
curl -X POST "https://slack.com/api/chat.postMessage" \\
-H "Authorization: Bearer $SLACK_API_TOKEN" \\
-H "Content-Type: application/json" \\
--data "{{\\"channel\\": \\"$SLACK_CHANNEL_ID\\", \\"thread_ts\\": \\"$SLACK_THREAD_TS\\", \\"blocks\\": $SLACK_MESSAGE}}"

echo "✅ Databricks workspace setup complete!"
"""

# Error notification template
ERROR_NOTIFICATION_TEMPLATE = """
SLACK_ERROR_MESSAGE=$(cat <<EOF
{
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "❌ Error: Databricks Workspace Creation Failed",
                "emoji": true
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "An error occurred while creating the Databricks workspace on {CLOUD_PROVIDER}. Please check the logs for more details."
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Error Message:*\\n\`\`\`$1\`\`\`"
            }
        }
    ]
}
EOF
)

curl -X POST "https://slack.com/api/chat.postMessage" \
-H "Authorization: Bearer $SLACK_API_TOKEN" \
-H "Content-Type: application/json" \
--data "{\"channel\": \"$SLACK_CHANNEL_ID\", \"thread_ts\": \"$SLACK_THREAD_TS\", \"blocks\": $SLACK_ERROR_MESSAGE}"
"""

# Wrap the workspace template with error handling
WORKSPACE_TEMPLATE_WITH_ERROR_HANDLING = """
set -e
{{
{WORKSPACE_TEMPLATE}
}} || {{
    error_message="$?"
    echo "❌ An error occurred: $error_message"
    {ERROR_NOTIFICATION_TEMPLATE}
    exit 1
}}
"""

def generate_terraform_vars_command(tf_vars):
    return '\n'.join([f'if [ ! -z "${{var["name"]}}" ]; then tf_vars="$tf_vars -var \'{var["name"]}=${{{var["name"]}}}\'"; fi' for var in tf_vars])