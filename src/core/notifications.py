"""
Webhook Notifications for Argus.

Sends notifications to external services when scans complete or
critical findings are detected.

Supported Integrations:
- Slack
- Microsoft Teams
- Discord
- PagerDuty
- Generic Webhooks
"""

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Optional

import httpx

from src.config import get_settings
from src.core.logger import get_logger
from src.scanners.base import Finding, Severity

logger = get_logger(__name__)


class WebhookType(str, Enum):
    """Supported webhook types."""
    
    SLACK = "slack"
    TEAMS = "teams"
    DISCORD = "discord"
    PAGERDUTY = "pagerduty"
    GENERIC = "generic"


@dataclass
class WebhookConfig:
    """
    Webhook configuration.
    
    Attributes:
        name: Webhook name for logging
        webhook_type: Type of webhook
        url: Webhook URL
        min_severity: Minimum severity to notify on
        enabled: Whether webhook is active
        headers: Additional HTTP headers
        secret: Webhook secret for signing
    """
    
    name: str
    webhook_type: WebhookType
    url: str
    min_severity: Severity = Severity.HIGH
    enabled: bool = True
    headers: dict[str, str] | None = None
    secret: str | None = None


