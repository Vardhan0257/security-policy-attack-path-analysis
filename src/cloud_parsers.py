"""
Cloud IAM Policy Parsers for AWS, Azure, and GCP.

Extracts security policies from cloud provider APIs and converts them
to the internal graph format for analysis.
"""

import json
import logging
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod
from datetime import datetime

logger = logging.getLogger(__name__)


class CloudPolicyParser(ABC):
    """Abstract base class for cloud policy parsers."""
    
    def __init__(self):
        self.policies = []
        self.errors = []
    
    @abstractmethod
    def parse(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """Parse cloud policies and return standardized format."""
        pass
    
    def _validate_policy(self, policy: Dict) -> bool:
        """Validate policy has required fields."""
        required = {'Principal', 'Resource', 'Action', 'Effect'}
        return all(field in policy for field in required)


class AWSIAMParser(CloudPolicyParser):
    """
    Parses AWS IAM policies from:
    - Inline policies
    - Managed policies
    - S3 bucket policies
    - VPC endpoint policies
    - API Gateway resource policies
    """
    
    def __init__(self, credentials: Optional[Dict] = None):
        super().__init__()
        self.credentials = credentials
        self._init_client()
    
    def _init_client(self):
        """Initialize AWS IAM client."""
        try:
            import boto3
            if self.credentials:
                self.client = boto3.client(
                    'iam',
                    access_key_id=self.credentials.get('access_key'),
                    secret_access_key=self.credentials.get('secret_key'),
                    region_name=self.credentials.get('region', 'us-east-1')
                )
            else:
                self.client = boto3.client('iam')
            logger.info("AWS IAM client initialized")
        except ImportError:
            logger.error("boto3 not installed. Install with: pip install boto3")
            self.client = None
        except Exception as e:
            logger.error(f"Failed to initialize AWS client: {e}")
            self.client = None
    
    def parse_user_policies(self, user_name: str) -> List[Dict]:
        """Parse inline and attached policies for an IAM user."""
        if not self.client:
            return []
        
        policies = []
        
        try:
            # Get inline policies
            inline = self.client.list_user_policies(UserName=user_name)
            for policy_name in inline.get('PolicyNames', []):
                policy_doc = self.client.get_user_policy(
                    UserName=user_name,
                    PolicyName=policy_name
                )
                parsed = self._parse_policy_document(
                    policy_doc['PolicyDocument'],
                    principal=user_name,
                    policy_type='user_inline'
                )
                policies.extend(parsed)
            
            # Get attached managed policies
            attached = self.client.list_attached_user_policies(UserName=user_name)
            for policy in attached.get('AttachedPolicies', []):
                policy_doc = self.client.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId='v1'  # Get default version
                )
                parsed = self._parse_policy_document(
                    policy_doc['PolicyVersion']['Document'],
                    principal=user_name,
                    policy_type='user_managed'
                )
                policies.extend(parsed)
            
            logger.info(f"Parsed {len(policies)} policies for user {user_name}")
            return policies
            
        except Exception as e:
            logger.error(f"Error parsing policies for {user_name}: {e}")
            self.errors.append(str(e))
            return []
    
    def parse_role_policies(self, role_name: str) -> List[Dict]:
        """Parse inline and attached policies for an IAM role."""
        if not self.client:
            return []
        
        policies = []
        
        try:
            # Get inline policies
            inline = self.client.list_role_policies(RoleName=role_name)
            for policy_name in inline.get('PolicyNames', []):
                policy_doc = self.client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                parsed = self._parse_policy_document(
                    policy_doc['PolicyDocument'],
                    principal=role_name,
                    policy_type='role_inline'
                )
                policies.extend(parsed)
            
            # Get attached managed policies
            attached = self.client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get('AttachedPolicies', []):
                policy_doc = self.client.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId='v1'
                )
                parsed = self._parse_policy_document(
                    policy_doc['PolicyVersion']['Document'],
                    principal=role_name,
                    policy_type='role_managed'
                )
                policies.extend(parsed)
            
            logger.info(f"Parsed {len(policies)} policies for role {role_name}")
            return policies
            
        except Exception as e:
            logger.error(f"Error parsing policies for {role_name}: {e}")
            self.errors.append(str(e))
            return []
    
    def parse_all_users(self) -> List[Dict]:
        """Parse all IAM users and their policies."""
        if not self.client:
            return []
        
        all_policies = []
        
        try:
            paginator = self.client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    user_policies = self.parse_user_policies(user['UserName'])
                    all_policies.extend(user_policies)
            
            logger.info(f"Parsed policies for {len(all_policies)} users")
            return all_policies
            
        except Exception as e:
            logger.error(f"Error parsing all users: {e}")
            self.errors.append(str(e))
            return []
    
    def parse_all_roles(self) -> List[Dict]:
        """Parse all IAM roles and their policies."""
        if not self.client:
            return []
        
        all_policies = []
        
        try:
            paginator = self.client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    role_policies = self.parse_role_policies(role['RoleName'])
                    all_policies.extend(role_policies)
            
            logger.info(f"Parsed policies for {len(all_policies)} roles")
            return all_policies
            
        except Exception as e:
            logger.error(f"Error parsing all roles: {e}")
            self.errors.append(str(e))
            return []
    
    def parse(self, what: str = "all") -> List[Dict]:
        """
        Parse AWS IAM policies.
        
        Args:
            what: 'users', 'roles', or 'all'
        """
        policies = []
        
        if what in ['users', 'all']:
            policies.extend(self.parse_all_users())
        
        if what in ['roles', 'all']:
            policies.extend(self.parse_all_roles())
        
        self.policies = policies
        return policies
    
    @staticmethod
    def _parse_policy_document(doc: Dict, principal: str, policy_type: str) -> List[Dict]:
        """
        Parse AWS policy document into standardized format.
        
        Args:
            doc: Policy document
            principal: IAM user/role
            policy_type: Type of policy
            
        Returns:
            List of standardized policy dicts
        """
        policies = []
        
        for statement in doc.get('Statement', []):
            if statement.get('Effect') != 'Allow':
                continue  # Skip Deny statements for now
            
            # Handle multiple actions
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            # Handle multiple resources
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
            
            # Create policy for each principal-action-resource combo
            for resource in resources:
                policy = {
                    'Principal': principal,
                    'Resource': resource,
                    'Action': actions,
                    'Effect': 'Allow',
                    'PolicyName': policy_type,
                    'Source': 'AWS',
                    'Condition': statement.get('Condition'),
                    'ParsedAt': datetime.utcnow().isoformat()
                }
                
                if AWSIAMParser._is_valid_policy(policy):
                    policies.append(policy)
        
        return policies
    
    @staticmethod
    def _is_valid_policy(policy: Dict) -> bool:
        """Validate parsed policy."""
        required = {'Principal', 'Resource', 'Action', 'Effect'}
        return all(policy.get(k) for k in required)


class AzureRBACParser(CloudPolicyParser):
    """
    Parses Azure RBAC (Role-Based Access Control) policies.
    
    Supports:
    - Built-in roles
    - Custom roles
    - Role assignments (users, groups, service principals)
    """
    
    def __init__(self, credentials: Optional[Dict] = None):
        super().__init__()
        self.credentials = credentials
        self._init_client()
    
    def _init_client(self):
        """Initialize Azure clients."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            
            if self.credentials:
                # Use provided credentials
                # In production, use managed identity or service principal
                credential = None
            else:
                credential = DefaultAzureCredential()
            
            # Would need subscription ID
            subscription_id = self.credentials.get('subscription_id') if self.credentials else None
            
            if credential and subscription_id:
                self.client = AuthorizationManagementClient(credential, subscription_id)
                logger.info("Azure RBAC client initialized")
            else:
                self.client = None
                
        except ImportError:
            logger.error("Azure SDK not installed. Install with: pip install azure-mgmt-authorization")
            self.client = None
        except Exception as e:
            logger.error(f"Failed to initialize Azure client: {e}")
            self.client = None
    
    def parse_role_assignments(self, scope: str) -> List[Dict]:
        """
        Parse role assignments at given scope.
        
        Args:
            scope: Azure resource scope (subscription, resource group, etc)
        """
        if not self.client:
            return []
        
        policies = []
        
        try:
            # Get all role assignments
            assignments = self.client.role_assignments.list(filter=f"atScope('{scope}')")
            
            for assignment in assignments:
                role_def = self.client.role_definitions.get_by_id(assignment.role_definition_id)
                
                policy = {
                    'Principal': assignment.principal_id,
                    'Resource': scope,
                    'Action': [perm['actions'] for perm in role_def.permissions],
                    'Effect': 'Allow',
                    'PolicyName': role_def.role_name,
                    'Source': 'Azure',
                    'RoleId': role_def.id,
                    'ParsedAt': datetime.utcnow().isoformat()
                }
                
                if self._validate_policy(policy):
                    policies.append(policy)
            
            logger.info(f"Parsed {len(policies)} role assignments at {scope}")
            return policies
            
        except Exception as e:
            logger.error(f"Error parsing role assignments: {e}")
            self.errors.append(str(e))
            return []
    
    def parse(self, scope: str) -> List[Dict]:
        """
        Parse Azure RBAC policies.
        
        Args:
            scope: Azure resource scope
        """
        policies = self.parse_role_assignments(scope)
        self.policies = policies
        return policies


class GCPIAMParser(CloudPolicyParser):
    """
    Parses Google Cloud IAM policies.
    
    Supports:
    - Project-level IAM bindings
    - Custom roles
    - Service account policies
    """
    
    def __init__(self, credentials: Optional[Dict] = None):
        super().__init__()
        self.credentials = credentials
        self._init_client()
    
    def _init_client(self):
        """Initialize GCP client."""
        try:
            from google.cloud import iam_v1
            
            self.client = iam_v1.IAMClient()
            logger.info("GCP IAM client initialized")
            
        except ImportError:
            logger.error("Google Cloud SDK not installed. Install with: pip install google-cloud-iam")
            self.client = None
        except Exception as e:
            logger.error(f"Failed to initialize GCP client: {e}")
            self.client = None
    
    def parse(self, project_id: str) -> List[Dict]:
        """
        Parse GCP IAM policies.
        
        Args:
            project_id: GCP project ID
        """
        if not self.client:
            return []
        
        # Implementation would fetch from GCP APIs
        logger.warning("GCP IAM parser not fully implemented yet")
        return []


def parse_cloud_policies(provider: str, credentials: Optional[Dict] = None, **kwargs) -> List[Dict]:
    """
    Convenience function to parse cloud policies.
    
    Args:
        provider: 'aws', 'azure', or 'gcp'
        credentials: Cloud provider credentials
        **kwargs: Provider-specific arguments
    
    Returns:
        List of standardized policies
    """
    parser = None
    
    if provider.lower() == 'aws':
        parser = AWSIAMParser(credentials)
        return parser.parse()
    
    elif provider.lower() == 'azure':
        parser = AzureRBACParser(credentials)
        scope = kwargs.get('scope', '/subscriptions/{subscription_id}')
        return parser.parse(scope)
    
    elif provider.lower() == 'gcp':
        parser = GCPIAMParser(credentials)
        project_id = kwargs.get('project_id')
        return parser.parse(project_id)
    
    else:
        raise ValueError(f"Unsupported provider: {provider}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example usage
    parser = AWSIAMParser()
    # policies = parser.parse_all_users()
    # print(f"Found {len(policies)} policies")
