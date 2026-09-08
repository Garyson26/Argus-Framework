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


@dataclass 
class NotificationPayload:
    """
    Notification content.
    
    Attributes:
        title: Notification title
        message: Message body
        severity: Finding severity
        scan_type: Type of scan
        findings_count: Number of findings
        critical_count: Critical findings count
        high_count: High findings count
        target: Scan target
        timestamp: Notification time
        metadata: Additional data
    """
    
    title: str
    message: str
    severity: Severity
    scan_type: str
    findings_count: int
    critical_count: int
    high_count: int
    target: str
    timestamp: datetime
    metadata: dict[str, Any] | None = None


class NotificationService:
    """
    Notification service for sending alerts.
    
    Manages webhook configurations and sends notifications
    to configured services.
    """
    
    def __init__(self, webhooks: list[WebhookConfig] | None = None):
        """
        Initialize notification service.
        
        Args:
            webhooks: List of webhook configurations
        """
        self.webhooks = webhooks or []
        self._client = httpx.Client(timeout=30.0)
    
    def add_webhook(self, config: WebhookConfig) -> None:
        """Add a webhook configuration."""
        self.webhooks.append(config)
    
    async def notify_scan_complete(
        self,
        scan_results: dict[str, Any],
        notify_all: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Send notifications for scan completion.
        
        Args:
            scan_results: Scan result dictionary
            notify_all: Send regardless of severity threshold
            
        Returns:
            List of notification results
        """
        results = []
        
        # Build notification payload
        critical = scan_results.get("severity_counts", {}).get("critical", 0)
        high = scan_results.get("severity_counts", {}).get("high", 0)
        total = scan_results.get("total_findings", 0)
        
        # Determine effective severity
        if critical > 0:
            severity = Severity.CRITICAL
        elif high > 0:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        
        payload = NotificationPayload(
            title=f"Argus Scan Complete: {scan_results.get('scan_type', 'Unknown')}",
            message=self._build_message(scan_results),
            severity=severity,
            scan_type=scan_results.get("scan_type", "unknown"),
            findings_count=total,
            critical_count=critical,
            high_count=high,
            target=scan_results.get("target", "unknown"),
            timestamp=datetime.utcnow(),
            metadata=scan_results.get("metadata"),
        )
        
        # Send to enabled webhooks
        for webhook in self.webhooks:
            if not webhook.enabled:
                continue
            
            # Check severity threshold
            if not notify_all:
                if not self._meets_threshold(severity, webhook.min_severity):
                    continue
            
            try:
                result = await self._send_webhook(webhook, payload)
                results.append({
                    "webhook": webhook.name,
                    "success": result,
                    "type": webhook.webhook_type.value,
                })
            except Exception as e:
                logger.error(f"Failed to send webhook {webhook.name}: {e}")
                results.append({
                    "webhook": webhook.name,
                    "success": False,
                    "error": str(e),
                })
        
        return results
    
    def _meets_threshold(self, severity: Severity, threshold: Severity) -> bool:
        """Check if severity meets or exceeds threshold."""
        severity_order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return severity_order.index(severity) >= severity_order.index(threshold)
    
    def _build_message(self, results: dict[str, Any]) -> str:
        """Build notification message from results."""
        counts = results.get("severity_counts", {})
        lines = [
            f"**Target**: {results.get('target', 'Unknown')}",
            f"**Scan Type**: {results.get('scan_type', 'Unknown')}",
            f"**Total Findings**: {results.get('total_findings', 0)}",
            "",
            "**Severity Breakdown**:",
            f"  • Critical: {counts.get('critical', 0)}",
            f"  • High: {counts.get('high', 0)}",
            f"  • Medium: {counts.get('medium', 0)}",
            f"  • Low: {counts.get('low', 0)}",
        ]
        return "\n".join(lines)
    
    async def _send_webhook(
        self,
        config: WebhookConfig,
        payload: NotificationPayload,
    ) -> bool:
        """
        Send notification to webhook.
        
        Args:
            config: Webhook configuration
            payload: Notification payload
            
        Returns:
            True if successful
        """
        if config.webhook_type == WebhookType.SLACK:
            return await self._send_slack(config, payload)
        elif config.webhook_type == WebhookType.TEAMS:
            return await self._send_teams(config, payload)
        elif config.webhook_type == WebhookType.DISCORD:
            return await self._send_discord(config, payload)
        elif config.webhook_type == WebhookType.PAGERDUTY:
            return await self._send_pagerduty(config, payload)
        else:
            return await self._send_generic(config, payload)
    
    async def _send_slack(
        self,
        config: WebhookConfig,
        payload: NotificationPayload,
    ) -> bool:
        """Send Slack notification."""
        color = self._severity_color(payload.severity, "slack")
        
        slack_payload = {
            "attachments": [
                {
                    "color": color,
                    "title": payload.title,
                    "text": payload.message,
                    "fields": [
                        {
                            "title": "Critical",
                            "value": str(payload.critical_count),
                            "short": True,
                        },
                        {
                            "title": "High",
                            "value": str(payload.high_count),
                            "short": True,
                        },
                        {
                            "title": "Total Findings",
                            "value": str(payload.findings_count),
                            "short": True,
                        },
                        {
                            "title": "Target",
                            "value": payload.target,
                            "short": True,
                        },
                    ],
                    "footer": "Argus Security Scanner",
                    "ts": int(payload.timestamp.timestamp()),
                }
            ]
        }
        
        return await self._http_post(config.url, slack_payload, config.headers)
    
    async def _send_teams(
        self,
        config: WebhookConfig,
        payload: NotificationPayload,
    ) -> bool:
        """Send Microsoft Teams notification."""
        color = self._severity_color(payload.severity, "teams")
        
        teams_payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": payload.title,
            "sections": [
                {
                    "activityTitle": payload.title,
                    "facts": [
                        {"name": "Target", "value": payload.target},
                        {"name": "Scan Type", "value": payload.scan_type},
                        {"name": "Critical", "value": str(payload.critical_count)},
                        {"name": "High", "value": str(payload.high_count)},
                        {"name": "Total", "value": str(payload.findings_count)},
                    ],
                    "markdown": True,
                }
            ],
        }
        
        return await self._http_post(config.url, teams_payload, config.headers)
    
    async def _send_discord(
        self,
        config: WebhookConfig,
        payload: NotificationPayload,
    ) -> bool:
        """Send Discord notification."""
        color = self._severity_color(payload.severity, "discord")
        
        discord_payload = {
            "embeds": [
                {
                    "title": payload.title,
                    "description": payload.message,
                    "color": color,
                    "fields": [
                        {"name": "Critical", "value": str(payload.critical_count), "inline": True},
                        {"name": "High", "value": str(payload.high_count), "inline": True},
                        {"name": "Total", "value": str(payload.findings_count), "inline": True},
                    ],
                    "footer": {"text": "Argus Security Scanner"},
                    "timestamp": payload.timestamp.isoformat(),
                }
            ]
        }
        
        return await self._http_post(config.url, discord_payload, config.headers)
    
    async def _send_pagerduty(
        self,
        config: WebhookConfig,
        payload: NotificationPayload,
    ) -> bool:
        """Send PagerDuty alert."""
        severity_map = {
            Severity.CRITICAL: "critical",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "info",
            Severity.INFO: "info",
        }
        
        pd_payload = {
            "routing_key": config.secret,
            "event_action": "trigger",
            "payload": {
                "summary": payload.title,
                "severity": severity_map.get(payload.severity, "warning"),
                "source": "argus",
                "custom_details": {
                    "target": payload.target,
                    "scan_type": payload.scan_type,
                    "findings_count": payload.findings_count,
                    "critical_count": payload.critical_count,
                    "high_count": payload.high_count,
                },
            },
        }
        
        return await self._http_post(config.url, pd_payload, config.headers)
    
    async def _send_generic(
        self,
        config: WebhookConfig,
        payload: NotificationPayload,
    ) -> bool:
        """Send generic webhook notification."""
        generic_payload = {
            "event": "scan_complete",
            "title": payload.title,
            "message": payload.message,
            "severity": payload.severity.value,
            "scan_type": payload.scan_type,
            "target": payload.target,
            "findings": {
                "total": payload.findings_count,
                "critical": payload.critical_count,
                "high": payload.high_count,
            },
            "timestamp": payload.timestamp.isoformat(),
            "metadata": payload.metadata,
        }
        
        return await self._http_post(config.url, generic_payload, config.headers)
    
    def _severity_color(self, severity: Severity, platform: str) -> str | int:
        """Get color for severity by platform."""
        colors = {
            "slack": {
                Severity.CRITICAL: "#dc3545",
                Severity.HIGH: "#fd7e14",
                Severity.MEDIUM: "#ffc107",
                Severity.LOW: "#17a2b8",
                Severity.INFO: "#6c757d",
            },
            "teams": {
                Severity.CRITICAL: "dc3545",
                Severity.HIGH: "fd7e14",
                Severity.MEDIUM: "ffc107",
                Severity.LOW: "17a2b8",
                Severity.INFO: "6c757d",
            },
            "discord": {
                Severity.CRITICAL: 0xdc3545,
                Severity.HIGH: 0xfd7e14,
                Severity.MEDIUM: 0xffc107,
                Severity.LOW: 0x17a2b8,
                Severity.INFO: 0x6c757d,
            },
        }
        return colors.get(platform, {}).get(severity, "#6c757d")
    
    async def _http_post(
        self,
        url: str,
        payload: dict,
        headers: dict[str, str] | None = None,
    ) -> bool:
        """Send HTTP POST request."""
        try:
            default_headers = {"Content-Type": "application/json"}
            if headers:
                default_headers.update(headers)
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers=default_headers,
                )
                response.raise_for_status()
                return True
                
        except httpx.HTTPError as e:
            logger.error(f"HTTP error sending webhook: {e}")
            return False
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")
            return False
    
    def close(self) -> None:
        """Close HTTP client."""
        self._client.close()
    
    def __enter__(self) -> "NotificationService":
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
