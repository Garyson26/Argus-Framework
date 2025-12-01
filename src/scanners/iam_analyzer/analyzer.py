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

