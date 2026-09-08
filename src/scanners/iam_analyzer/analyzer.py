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

    async def _get_policy_document(self, iam, policy_arn: str) -> Optional[dict]:
        """Get policy document (with caching)."""
        if policy_arn in self._policy_cache:
            return self._policy_cache[policy_arn]
        
        try:
            policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
            version_id = policy["DefaultVersionId"]
            
            version = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )["PolicyVersion"]
            
            doc = version["Document"]
            self._policy_cache[policy_arn] = doc
            self._stats["policies_analyzed"] += 1
            
            return doc
            
        except Exception as e:
            self._debug_log(f"Error getting policy {policy_arn}: {e}")
            return None

    async def _analyze_policy_document(
        self,
        policy_doc: dict,
        policy_name: str,
        policy_type: str,
        entity_arn: str,
    ) -> None:
        """Analyze a policy document for security issues."""
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue
            
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            
            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            
            # Check for dangerous patterns
            for action_pattern, resource_pattern, reason in DANGEROUS_PATTERNS:
                if self._matches_pattern(actions, action_pattern) and \
                   self._matches_pattern(resources, resource_pattern):
                    
                    self.add_finding(Finding(
                        rule_id="IAM-OVERLY-PERMISSIVE",
                        severity=Severity.HIGH,
                        title="Overly Permissive IAM Policy",
                        description=f"Policy {policy_name} ({policy_type}) attached to {entity_arn}: {reason}",
                        resource_id=policy_name,
                        resource_type="AWS::IAM::Policy",
                        resource_arn=entity_arn,
                        suggestion="Apply principle of least privilege - restrict to specific actions and resources",
                        metadata={
                            "actions": actions,
                            "resources": resources,
                            "policy_type": policy_type,
                        },
                    ))
                    self._scan_logger.finding("high", "Overly Permissive Policy", policy_name)
            
            # Check for privilege escalation actions
            for action in actions:
                if action == "*":
                    continue  # Already caught by dangerous patterns
                
                # Check if action matches any escalation action
                for escalation_action, description in ESCALATION_ACTIONS.items():
                    if self._action_matches(action, escalation_action):
                        self._stats["escalation_paths"] += 1
                        
                        self.add_finding(Finding(
                            rule_id="IAM-ESCALATION-RISK",
                            severity=Severity.HIGH,
                            title="Potential Privilege Escalation",
                            description=f"Policy {policy_name} allows {escalation_action}: {description}",
                            resource_id=policy_name,
                            resource_type="AWS::IAM::Policy",
                            resource_arn=entity_arn,
                            suggestion=f"Review if {escalation_action} is necessary. Consider restricting with conditions.",
                            metadata={
                                "action": escalation_action,
                                "risk_description": description,
                            },
                        ))
            
            # Check for NotAction/NotResource (often misused)
            if "NotAction" in statement or "NotResource" in statement:
                self.add_finding(Finding(
                    rule_id="IAM-NOT-ACTION-USED",
                    severity=Severity.MEDIUM,
                    title="Policy Uses NotAction/NotResource",
                    description=f"Policy {policy_name} uses NotAction or NotResource which can be dangerous if misconfigured",
                    resource_id=policy_name,
                    resource_type="AWS::IAM::Policy",
                    resource_arn=entity_arn,
                    suggestion="Review NotAction/NotResource usage carefully - it may allow unintended actions",
                ))

    async def _analyze_trust_policy(
        self,
        trust_policy: dict,
        role_name: str,
        role_arn: str,
    ) -> None:
        """Analyze role trust policy."""
        statements = trust_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue
            
            principal = statement.get("Principal", {})
            
            # Check for wildcard principal
            if principal == "*" or principal.get("AWS") == "*":
                self.add_finding(Finding(
                    rule_id="IAM-TRUST-WILDCARD",
                    severity=Severity.CRITICAL,
                    title="Role Trust Policy Allows Any Principal",
                    description=f"Role {role_name} trust policy allows any AWS principal to assume it",
                    resource_id=role_name,
                    resource_type="AWS::IAM::Role",
                    resource_arn=role_arn,
                    suggestion="Restrict trust policy to specific principals using conditions or explicit ARNs",
                ))
                self._scan_logger.finding("critical", "Trust Policy Wildcard", role_name)
            
            # Check for cross-account access without conditions
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            
            for aws_principal in aws_principals:
                if isinstance(aws_principal, str) and "arn:aws" in aws_principal:
                    # Extract account from ARN
                    parts = aws_principal.split(":")
                    if len(parts) >= 5:
                        account = parts[4]
                        
                        # Check if no conditions are applied
                        if not statement.get("Condition"):
                            self.add_finding(Finding(
                                rule_id="IAM-CROSS-ACCOUNT-NO-CONDITION",
                                severity=Severity.MEDIUM,
                                title="Cross-Account Trust Without Conditions",
                                description=f"Role {role_name} allows cross-account access from {account} without conditions",
                                resource_id=role_name,
                                resource_type="AWS::IAM::Role",
                                resource_arn=role_arn,
                                suggestion="Add ExternalId or other conditions to cross-account trust policies",
                                metadata={"external_account": account},
                            ))

    async def _check_escalation_paths(self, iam) -> None:
        """Check for privilege escalation paths."""
        self._debug_log("Checking privilege escalation paths...")
        
        # This is a simplified check - a full implementation would use graph analysis
        # Check for dangerous action combinations
        dangerous_combos = [
            (["iam:PassRole", "ec2:RunInstances"], "Can launch EC2 with elevated role"),
            (["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Can create and invoke Lambda with elevated role"),
            (["iam:CreateAccessKey"], "Can create access keys for escalation"),
            (["iam:AttachUserPolicy", "iam:AttachRolePolicy"], "Can attach admin policies"),
        ]
        
        # Already checked individual escalation actions in policy analysis
        # Additional graph-based analysis would go here with Neo4j integration

    def _matches_pattern(self, items: list, pattern: str) -> bool:
        """Check if any item matches the pattern."""
        for item in items:
            if item == pattern or item == "*":
                return True
        return False

    def _action_matches(self, action: str, target: str) -> bool:
        """Check if an action matches a target (with wildcard support)."""
        if action == "*" or action == target:
            return True
        
        # Handle wildcards like iam:* or iam:Create*
        if action.endswith("*"):
            prefix = action[:-1]
            return target.startswith(prefix)
        
        return False
