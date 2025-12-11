"""
AWS IAM & Permission Analyzer for Argus.

Analyzes IAM policies and permissions to detect:
- Privilege escalation paths
- Overly permissive policies
- Unused permissions
- External trust relationships
"""

import json
from datetime import datetime
from typing import Any, Optional

from src.config import get_settings
from src.core.exceptions import AWSError, IAMAnalysisError
from src.core.logger import ScanLogger, get_logger
from src.scanners.base import BaseScanner, Finding, Severity
from src.utils.aws_boto_helper import AWSClient

logger = get_logger(__name__)


# Dangerous IAM actions for privilege escalation
ESCALATION_ACTIONS = {
    # Create new credentials
    "iam:CreateAccessKey": "Can create access keys for any user",
    "iam:CreateLoginProfile": "Can create console login for any user",
    "iam:UpdateLoginProfile": "Can change password for any user",
    
    # Assume roles
    "sts:AssumeRole": "Can assume roles with higher privileges",
    "iam:UpdateAssumeRolePolicy": "Can modify who can assume roles",
    
    # Attach policies
    "iam:AttachUserPolicy": "Can attach any policy to users",
    "iam:AttachRolePolicy": "Can attach any policy to roles",
    "iam:AttachGroupPolicy": "Can attach any policy to groups",
    "iam:PutUserPolicy": "Can add inline policies to users",
    "iam:PutRolePolicy": "Can add inline policies to roles",
    "iam:PutGroupPolicy": "Can add inline policies to groups",
    
    # Modify policies
    "iam:CreatePolicyVersion": "Can create new version of managed policies",
    "iam:SetDefaultPolicyVersion": "Can set default policy version",
    
    # Pass roles
    "iam:PassRole": "Can pass roles to AWS services",
    
    # Lambda
    "lambda:CreateFunction": "Can create Lambda functions with any role",
    "lambda:UpdateFunctionCode": "Can modify Lambda function code",
    "lambda:InvokeFunction": "Can invoke Lambda functions",
    
    # EC2
    "ec2:RunInstances": "Can launch EC2 instances with any role",
    
    # CloudFormation
    "cloudformation:CreateStack": "Can create stacks with any role",
    
    # Glue
    "glue:CreateDevEndpoint": "Can create dev endpoints with any role",
    "glue:UpdateDevEndpoint": "Can update dev endpoint configurations",
    
    # Data Pipeline
    "datapipeline:CreatePipeline": "Can create pipelines with any role",
    
    # SageMaker
    "sagemaker:CreateNotebookInstance": "Can create notebooks with any role",
}

# Overly permissive patterns
DANGEROUS_PATTERNS = [
    ("*", "*", "Full admin access - allows all actions on all resources"),
    ("iam:*", "*", "Full IAM access - can escalate privileges"),
    ("s3:*", "*", "Full S3 access - can access all buckets"),
    ("ec2:*", "*", "Full EC2 access - can manage all compute resources"),
    ("lambda:*", "*", "Full Lambda access - can execute arbitrary code"),
    ("*:*", "*", "Wildcard action pattern - extremely dangerous"),
]


class IAMAnalyzer(BaseScanner):
    """
    AWS IAM permission analyzer.
    
    Analyzes IAM entities and policies to identify:
    - Privilege escalation paths
    - Overly permissive policies
    - Unused permissions (with CloudTrail)
    - External trust relationships
    - Best practice violations
    """
    
    scanner_type = "iam"
    
    def __init__(
        self,
        profile: Optional[str] = None,
        check_escalation: bool = True,
        check_unused: bool = True,
        debug: bool = False,
    ):
        """
        Initialize the IAM analyzer.
        
        Args:
            profile: AWS profile name
            check_escalation: Check for privilege escalation paths
            check_unused: Check for unused permissions (requires CloudTrail)
            debug: Enable debug mode
        """
        super().__init__()
        
        settings = get_settings()
        
        self.profile = profile
        self.check_escalation = check_escalation
        self.check_unused = check_unused
        self.debug = debug or settings.debug
        
        self._aws_client: Optional[AWSClient] = None
        self._scan_logger: Optional[ScanLogger] = None
        self._stats = {
            "users_analyzed": 0,
            "roles_analyzed": 0,
            "groups_analyzed": 0,
            "policies_analyzed": 0,
            "escalation_paths": 0,
        }
        
        # Cache for policy documents
        self._policy_cache: dict[str, dict] = {}

    @property
    def aws(self) -> AWSClient:
        """Get AWS client."""
        if self._aws_client is None:
            self._aws_client = AWSClient(profile=self.profile)
        return self._aws_client

    async def analyze(self) -> dict[str, Any]:
        """
        Analyze IAM permissions.
        
        Returns:
            Dictionary containing analysis results
        """
        started_at = datetime.utcnow()
        self.clear_findings()
        
        target = f"AWS IAM (Profile: {self.profile or 'default'})"
        self._scan_logger = ScanLogger("iam", target)
        self._scan_logger.start()
        
        try:
            account_id = self.aws.get_account_id()
            self._debug_log(f"Analyzing IAM for account: {account_id}")
            
            iam = self.aws.get_client("iam")
            
            # Analyze users
            await self._analyze_users(iam)
            
            # Analyze roles
            await self._analyze_roles(iam)
            
            # Analyze groups
            await self._analyze_groups(iam)
            
            # Check for privilege escalation paths
            if self.check_escalation:
                await self._check_escalation_paths(iam)
            
            # Create result
            result = self.create_result(
                target=target,
                started_at=started_at,
                metadata={
                    "account_id": account_id,
                    **self._stats,
                },
            )
            
            self._scan_logger.end(len(self._findings))
            return result.to_dict()
            
        except AWSError:
            raise
        except Exception as e:
            self._scan_logger.error(f"Analysis failed: {e}", e)
            raise IAMAnalysisError(f"IAM analysis failed: {e}")

    def _debug_log(self, message: str) -> None:
        """Log debug message if debug mode enabled."""
        if self.debug:
            logger.debug(f"[IAM ANALYZE] {message}")

    async def _analyze_users(self, iam) -> None:
        """Analyze IAM users."""
        self._debug_log("Analyzing IAM users...")
        
        try:
            users = list(self.aws.paginate(iam, "list_users", "Users"))
            
            for user in users:
                self._stats["users_analyzed"] += 1
                username = user["UserName"]
                user_arn = user["Arn"]
                
                # Get user's policies
                await self._analyze_entity_policies(iam, "user", username, user_arn)
                
                # Check inline policies
                inline_policies = iam.list_user_policies(UserName=username)["PolicyNames"]
                for policy_name in inline_policies:
                    policy_doc = iam.get_user_policy(
                        UserName=username, 
                        PolicyName=policy_name
                    )["PolicyDocument"]
                    
                    await self._analyze_policy_document(
                        policy_doc,
                        f"{username}/{policy_name}",
                        "inline",
                        user_arn,
                    )
                
        except Exception as e:
            self._debug_log(f"Error analyzing users: {e}")

    async def _analyze_roles(self, iam) -> None:
        """Analyze IAM roles."""
        self._debug_log("Analyzing IAM roles...")
        
        try:
            roles = list(self.aws.paginate(iam, "list_roles", "Roles"))
            
            for role in roles:
                self._stats["roles_analyzed"] += 1
                role_name = role["RoleName"]
                role_arn = role["Arn"]
                
                # Skip AWS service-linked roles
                if role.get("Path", "").startswith("/aws-service-role/"):
                    continue
                
                # Check trust policy
                trust_policy = role.get("AssumeRolePolicyDocument", {})
                await self._analyze_trust_policy(trust_policy, role_name, role_arn)
                
                # Get role's policies
                await self._analyze_entity_policies(iam, "role", role_name, role_arn)
                
                # Check inline policies
                inline_policies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
                for policy_name in inline_policies:
                    policy_doc = iam.get_role_policy(
                        RoleName=role_name, 
                        PolicyName=policy_name
                    )["PolicyDocument"]
                    
                    await self._analyze_policy_document(
                        policy_doc,
                        f"{role_name}/{policy_name}",
                        "inline",
                        role_arn,
                    )
                
        except Exception as e:
            self._debug_log(f"Error analyzing roles: {e}")

    async def _analyze_groups(self, iam) -> None:
        """Analyze IAM groups."""
        self._debug_log("Analyzing IAM groups...")
        
        try:
            groups = list(self.aws.paginate(iam, "list_groups", "Groups"))
            
            for group in groups:
                self._stats["groups_analyzed"] += 1
                group_name = group["GroupName"]
                group_arn = group["Arn"]
                
                # Get group's policies
                await self._analyze_entity_policies(iam, "group", group_name, group_arn)
                
        except Exception as e:
            self._debug_log(f"Error analyzing groups: {e}")

    async def _analyze_entity_policies(
        self,
        iam,
        entity_type: str,
        entity_name: str,
        entity_arn: str,
    ) -> None:
        """Analyze attached policies for an IAM entity."""
        try:
            # Get attached managed policies
            if entity_type == "user":
                attached = iam.list_attached_user_policies(UserName=entity_name)
            elif entity_type == "role":
                attached = iam.list_attached_role_policies(RoleName=entity_name)
            else:
                attached = iam.list_attached_group_policies(GroupName=entity_name)
            
            for policy in attached.get("AttachedPolicies", []):
                policy_arn = policy["PolicyArn"]
                
                # Get policy document
                policy_doc = await self._get_policy_document(iam, policy_arn)
                if policy_doc:
                    await self._analyze_policy_document(
                        policy_doc,
                        policy["PolicyName"],
                        "managed",
                        entity_arn,
                    )
                    
        except Exception as e:
            self._debug_log(f"Error analyzing policies for {entity_type} {entity_name}: {e}")

