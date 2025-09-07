"""
AWS Boto3 helper utilities for Argus.

Provides session management, pagination handling, and rate limiting for AWS API calls.
"""

from functools import lru_cache
from typing import Any, Generator, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

from src.config import get_settings
from src.core.exceptions import AWSError
from src.core.logger import get_logger

logger = get_logger(__name__)


class AWSClient:
    """
    AWS client wrapper with session management and utilities.
    
    Provides a unified interface for AWS API operations with:
    - Profile/credentials management
    - Assume role support
    - Automatic pagination
    - Rate limiting and retry logic
    - Error handling
    """

    def __init__(
        self,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        assume_role_arn: Optional[str] = None,
        external_id: Optional[str] = None,
    ):
        """
        Initialize AWS client.
        
        Args:
            profile: AWS profile name (optional)
            region: AWS region (optional, uses config default)
            assume_role_arn: ARN of role to assume (optional)
            external_id: External ID for assume role (optional)
        """
        settings = get_settings()
        
        self.profile = profile or settings.aws_profile
        self.region = region or settings.aws_region
        self.assume_role_arn = assume_role_arn or settings.aws_assume_role_arn
        self.external_id = external_id
        
        # Configure retries
        self._config = Config(
            retries={
                "max_attempts": 3,
                "mode": "adaptive",
            },
            connect_timeout=10,
            read_timeout=30,
        )
        
        self._session: Optional[boto3.Session] = None
        self._assumed_credentials: Optional[dict] = None

    @property
    def session(self) -> boto3.Session:
        """Get or create boto3 session."""
        if self._session is None:
            if self.profile:
                self._session = boto3.Session(
                    profile_name=self.profile,
                    region_name=self.region,
                )
            else:
                settings = get_settings()
                self._session = boto3.Session(
                    aws_access_key_id=settings.aws_access_key_id,
                    aws_secret_access_key=settings.aws_secret_access_key,
                    aws_session_token=settings.aws_session_token,
                    region_name=self.region,
                )
        return self._session

    def _get_assumed_credentials(self) -> dict:
        """Get credentials from assumed role."""
        if self._assumed_credentials is None:
            sts = self.session.client("sts", config=self._config)
            
            assume_params = {
                "RoleArn": self.assume_role_arn,
                "RoleSessionName": "ArgusSession",
                "DurationSeconds": 3600,
            }
            
            if self.external_id:
                assume_params["ExternalId"] = self.external_id
            
            try:
                response = sts.assume_role(**assume_params)
                self._assumed_credentials = response["Credentials"]
            except ClientError as e:
                raise AWSError(
                    f"Failed to assume role: {e}",
                    service="sts",
                    operation="assume_role",
                    details={"role_arn": self.assume_role_arn},
                )
        
        return self._assumed_credentials

    def get_client(self, service_name: str, region: Optional[str] = None) -> Any:
        """
        Get a boto3 client for the specified service.
        
        Args:
            service_name: AWS service name (e.g., 's3', 'ec2', 'iam')
            region: Optional region override
            
        Returns:
            Boto3 service client
        """
        region = region or self.region
        
        if self.assume_role_arn:
            creds = self._get_assumed_credentials()
            return boto3.client(
                service_name,
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                config=self._config,
            )
        
        return self.session.client(
            service_name,
            region_name=region,
            config=self._config,
        )

