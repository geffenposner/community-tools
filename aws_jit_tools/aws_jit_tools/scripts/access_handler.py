import logging
import os
import sys
import json
import time
import requests
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError, ProfileNotFound
except ImportError as e:
    logger.error(f"Failed to import boto3: {str(e)}")
    print(json.dumps({
        "status": "error",
        "error_type": "ImportError",
        "message": "Required package boto3 is not installed - its OK during discovery"
    }))
    pass

class AWSAccessHandler:
    def __init__(self, profile_name: Optional[str] = None):
        """Initialize AWS access handler."""
        try:
            # Use default profile
            self.session = boto3.Session()
            # Add a print to the caller identity
            print("Using profile: ", self.session.profile_name)
            print(self.session.client('sts').get_caller_identity())
            self.identitystore = self.session.client('identitystore')
            self.sso_admin = self.session.client('sso-admin')
            
            # Get Identity Store ID from SSO Instance
            instances = self.sso_admin.list_instances()['Instances']
            if not instances:
                raise ValueError("No SSO instance found - please make sure you have the correct profile set (this tool should run from the main account) - ask your operator for help if you are unsure")
            self.instance_arn = instances[0]['InstanceArn']
            self.identity_store_id = instances[0]['IdentityStoreId']
            
        except Exception as e:
            self._handle_error("Failed to initialize AWS handler", e)

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Find user in IAM Identity Center by email."""
        try:
            # List all users and filter manually since the API doesn't support email filtering
            paginator = self.identitystore.get_paginator('list_users')
            
            for page in paginator.paginate(IdentityStoreId=self.identity_store_id):
                for user in page['Users']:
                    # Get user details to check email
                    user_info = self.identitystore.describe_user(
                        IdentityStoreId=self.identity_store_id,
                        UserId=user['UserId']
                    )
                    
                    # Check if any email matches
                    user_emails = user_info.get('Emails', [])
                    if any(e.get('Value', '').lower() == email.lower() for e in user_emails):
                        return user_info
            
            logger.error(f"No user found with email: {email}")
            return None

        except Exception as e:
            logger.error(f"Error finding user by email: {str(e)}")
            raise

    def get_slack_user_id(self, email: str) -> Optional[str]:
        """Get Slack user ID from email."""
        try:
            slack_token = os.environ.get('SLACK_API_TOKEN')
            if not slack_token:
                logger.error("SLACK_API_TOKEN not set")
                return None

            response = requests.post(
                'https://slack.com/api/users.lookupByEmail',
                headers={'Authorization': f'Bearer {slack_token}'},
                data={'email': email}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    return data['user']['id']
            
            logger.error(f"Failed to find Slack user for email: {email}")
            return None

        except Exception as e:
            logger.error(f"Error getting Slack user ID: {str(e)}")
            return None

    def send_slack_notification(self, user_id: str, message: str):
        """Send Slack message to user."""
        try:
            slack_token = os.environ.get('SLACK_API_TOKEN')
            if not slack_token:
                logger.error("SLACK_API_TOKEN not set")
                return

            response = requests.post(
                'https://slack.com/api/chat.postMessage',
                headers={'Authorization': f'Bearer {slack_token}'},
                json={
                    'channel': user_id,
                    'text': message
                }
            )

            if not response.ok:
                logger.error(f"Failed to send Slack message: {response.text}")

        except Exception as e:
            logger.error(f"Error sending Slack notification: {str(e)}")

    def parse_iso8601_duration(self, duration: str) -> int:
        """Convert ISO8601 duration to seconds."""
        try:
            # Handle basic format PT#H or PT#M
            if duration.startswith('PT'):
                value = int(duration[2:-1])
                unit = duration[-1]
                if unit == 'H':
                    return value * 3600
                elif unit == 'M':
                    return value * 60
            return 3600  # Default 1 hour
        except Exception:
            return 3600

    def _handle_error(self, message: str, error: Exception):
        """Handle and log errors."""
        error_msg = f"{message}: {str(error)}"
        logger.error(error_msg)
        print(json.dumps({
            "status": "error",
            "error_type": type(error).__name__,
            "message": error_msg
        }))
        sys.exit(1)

    def get_permission_set_arn(self, permission_set_name: str) -> str:
        """Get Permission Set ARN from name."""
        try:
            paginator = self.sso_admin.get_paginator('list_permission_sets')
            
            for page in paginator.paginate(InstanceArn=self.instance_arn):
                for arn in page['PermissionSets']:
                    # Get permission set details
                    response = self.sso_admin.describe_permission_set(
                        InstanceArn=self.instance_arn,
                        PermissionSetArn=arn
                    )
                    if response['PermissionSet']['Name'] == permission_set_name:
                        return arn
                    
            raise ValueError(f"Permission set not found: {permission_set_name}")

        except Exception as e:
            logger.error(f"Error getting permission set ARN: {str(e)}")
            raise

def main():
    """Main execution function."""
    try:
        # Get environment variables
        user_email = os.environ['KUBIYA_USER_EMAIL']
        account_id = os.environ['AWS_ACCOUNT_ID']
        permission_set_name = os.environ['PERMISSION_SET_NAME']
        session_duration = os.environ.get('SESSION_DURATION', 'PT1H')

        handler = AWSAccessHandler()
        
        # Find user by email
        user = handler.get_user_by_email(user_email)
        if not user:
            raise ValueError(f"User not found: {user_email}")

        # Get Permission Set ARN
        permission_set_arn = handler.get_permission_set_arn(permission_set_name)

        # Get Slack user ID
        slack_user_id = handler.get_slack_user_id(user_email)
        
        # Create assignment
        response = handler.sso_admin.create_account_assignment(
            InstanceArn=handler.instance_arn,
            TargetId=account_id,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=permission_set_arn,
            PrincipalType='USER',
            PrincipalId=user['UserId']
        )

        # Get session duration in seconds
        duration_seconds = handler.parse_iso8601_duration(session_duration)
        
        # Print success response
        print(json.dumps({
            "status": "success",
            "message": f"Access granted for {duration_seconds} seconds",
            "details": response['AccountAssignmentCreationStatus']
        }))

        # Sleep for the duration
        time.sleep(duration_seconds)

        # Send Slack notification if possible
        if slack_user_id:
            handler.send_slack_notification(
                slack_user_id,
                f"Your AWS session for account {account_id} with permission set {permission_set_name} has expired."
            )

    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        print(json.dumps({
            "status": "error",
            "error_type": type(e).__name__,
            "message": error_msg
        }))
        sys.exit(1)

if __name__ == "__main__":
    main() 