"""
Secret detection patterns for Argus.

Comprehensive regex patterns for detecting hardcoded credentials, API keys,
private keys, tokens, and other sensitive data.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from src.scanners.base import Severity


class SecretType(str, Enum):
    """Types of secrets that can be detected."""
    
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    AWS_SESSION_TOKEN = "aws_session_token"
    PRIVATE_KEY = "private_key"
    RSA_PRIVATE_KEY = "rsa_private_key"
    SSH_PRIVATE_KEY = "ssh_private_key"
    PGP_PRIVATE_KEY = "pgp_private_key"
    GITHUB_TOKEN = "github_token"
    GITHUB_APP_TOKEN = "github_app_token"
    GITLAB_TOKEN = "gitlab_token"
    SLACK_TOKEN = "slack_token"
    SLACK_WEBHOOK = "slack_webhook"
    GOOGLE_API_KEY = "google_api_key"
    GOOGLE_OAUTH = "google_oauth"
    GOOGLE_CLOUD_KEY = "google_cloud_key"
    AZURE_KEY = "azure_key"
    JWT = "jwt"
    GENERIC_API_KEY = "generic_api_key"
    GENERIC_SECRET = "generic_secret"
    DATABASE_URL = "database_url"
    PRIVATE_PASSWORD = "password"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    STRIPE_KEY = "stripe_key"
    TWILIO_KEY = "twilio_key"
    SENDGRID_KEY = "sendgrid_key"
    MAILCHIMP_KEY = "mailchimp_key"
    NPM_TOKEN = "npm_token"
    PYPI_TOKEN = "pypi_token"
    DOCKER_AUTH = "docker_auth"
    HEROKU_KEY = "heroku_key"
    FIREBASE_KEY = "firebase_key"
    TELEGRAM_TOKEN = "telegram_token"
    DISCORD_TOKEN = "discord_token"
    TWITTER_KEY = "twitter_key"
    FACEBOOK_TOKEN = "facebook_token"
    OKTA_TOKEN = "okta_token"
    DATADOG_KEY = "datadog_key"
    NEW_RELIC_KEY = "new_relic_key"
    SENTRY_DSN = "sentry_dsn"
    HIGH_ENTROPY = "high_entropy"


@dataclass
class SecretPattern:
    """Definition of a secret detection pattern."""
    
    name: str
    secret_type: SecretType
    pattern: str
    severity: Severity
    description: str
    suggestion: str
    confidence: float = 0.9  # Default confidence level
    keywords: Optional[list[str]] = None  # Keywords that must be present nearby
    
    def __post_init__(self):
        # Convert None to empty list to avoid mutable default issues
        if self.keywords is None:
            object.__setattr__(self, 'keywords', [])
        self._compiled_pattern: Optional[re.Pattern] = None
    
    @property
    def regex(self) -> re.Pattern:
        """Get compiled regex pattern."""
        if self._compiled_pattern is None:
            self._compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        return self._compiled_pattern
    
    def match(self, text: str) -> list[re.Match]:
        """Find all matches in text."""
        return list(self.regex.finditer(text))


# =============================================================================
# SECRET PATTERNS DATABASE
# =============================================================================

AWS_PATTERNS = [
    SecretPattern(
        name="AWS Access Key ID",
        secret_type=SecretType.AWS_ACCESS_KEY,
        pattern=r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        severity=Severity.CRITICAL,
        description="AWS Access Key ID found in code",
        suggestion="Remove hardcoded AWS credentials and use IAM roles, environment variables, or AWS Secrets Manager",
        confidence=0.95,
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        secret_type=SecretType.AWS_SECRET_KEY,
        pattern=r"(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        severity=Severity.CRITICAL,
        description="AWS Secret Access Key found in code",
        suggestion="Remove hardcoded AWS credentials and use IAM roles or AWS Secrets Manager",
        confidence=0.9,
        keywords=["aws", "secret", "key"],
    ),
    SecretPattern(
        name="AWS Session Token",
        secret_type=SecretType.AWS_SESSION_TOKEN,
        pattern=r"(?i)aws[_-]?session[_-]?token['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
        severity=Severity.HIGH,
        description="AWS Session Token found in code",
        suggestion="Session tokens should not be hardcoded. Use temporary credentials properly.",
        confidence=0.85,
    ),
]

PRIVATE_KEY_PATTERNS = [
    SecretPattern(
        name="Private Key",
        secret_type=SecretType.PRIVATE_KEY,
        pattern=r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        description="Private key found in code",
        suggestion="Remove private keys from code and store them securely using a secrets manager",
        confidence=0.99,
    ),
    SecretPattern(
        name="PGP Private Key",
        secret_type=SecretType.PGP_PRIVATE_KEY,
        pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        severity=Severity.CRITICAL,
        description="PGP private key found in code",
        suggestion="Remove PGP private keys from code and store them in a secure keyring",
        confidence=0.99,
    ),
]

GITHUB_PATTERNS = [
    SecretPattern(
        name="GitHub Personal Access Token",
        secret_type=SecretType.GITHUB_TOKEN,
        pattern=r"ghp_[A-Za-z0-9_]{36,}",
        severity=Severity.CRITICAL,
        description="GitHub Personal Access Token found",
        suggestion="Revoke this token immediately and use GitHub Apps or environment variables",
        confidence=0.98,
    ),
    SecretPattern(
        name="GitHub OAuth Token",
        secret_type=SecretType.GITHUB_TOKEN,
        pattern=r"gho_[A-Za-z0-9_]{36,}",
        severity=Severity.CRITICAL,
        description="GitHub OAuth Token found",
        suggestion="Revoke this token immediately",
        confidence=0.98,
    ),
    SecretPattern(
        name="GitHub App Token",
        secret_type=SecretType.GITHUB_APP_TOKEN,
        pattern=r"(?:ghu|ghs)_[A-Za-z0-9_]{36,}",
        severity=Severity.CRITICAL,
        description="GitHub App Token found",
        suggestion="Rotate this token immediately",
        confidence=0.98,
    ),
    SecretPattern(
        name="GitHub Refresh Token",
        secret_type=SecretType.GITHUB_TOKEN,
        pattern=r"ghr_[A-Za-z0-9_]{36,}",
        severity=Severity.HIGH,
        description="GitHub Refresh Token found",
        suggestion="Revoke and rotate this token",
        confidence=0.98,
    ),
]

GITLAB_PATTERNS = [
    SecretPattern(
        name="GitLab Personal Access Token",
        secret_type=SecretType.GITLAB_TOKEN,
        pattern=r"glpat-[A-Za-z0-9\-_]{20,}",
        severity=Severity.CRITICAL,
        description="GitLab Personal Access Token found",
        suggestion="Revoke this token and use CI/CD variables instead",
        confidence=0.98,
    ),
]

SLACK_PATTERNS = [
    SecretPattern(
        name="Slack Bot Token",
        secret_type=SecretType.SLACK_TOKEN,
        pattern=r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        severity=Severity.HIGH,
        description="Slack Bot Token found",
        suggestion="Rotate this token in your Slack app settings",
        confidence=0.98,
    ),
    SecretPattern(
        name="Slack User Token",
        secret_type=SecretType.SLACK_TOKEN,
        pattern=r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}",
        severity=Severity.HIGH,
        description="Slack User Token found",
        suggestion="Rotate this token immediately",
        confidence=0.98,
    ),
    SecretPattern(
        name="Slack Webhook URL",
        secret_type=SecretType.SLACK_WEBHOOK,
        pattern=r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}",
        severity=Severity.MEDIUM,
        description="Slack Webhook URL found",
        suggestion="Regenerate this webhook URL and store it as an environment variable",
        confidence=0.98,
    ),
]

