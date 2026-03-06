"""
Slack MCP Client for SecurityAgents Platform

Enterprise-grade Slack integration with OAuth 2.0 authentication, rate limiting,
and complete audit trail for security team collaboration workflows.

P0 Deliverable for SecurityAgents Phase 2C Slack Integration
Author: Tiger Team Alpha-3 Slack Workflows Specialist
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import traceback
import httpx
import boto3
from botocore.exceptions import ClientError

# Import Alpha-2's gateway infrastructure
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gateway.enterprise_mcp_gateway import SecurityEvent, EventSeverity, EventType


class SlackScope(Enum):
    """Slack OAuth 2.0 scopes for enterprise security operations."""
    # Core messaging capabilities
    CHANNELS_READ = "channels:read"
    CHANNELS_WRITE = "channels:write"
    CHAT_WRITE = "chat:write"
    CHAT_WRITE_PUBLIC = "chat:write.public"
    
    # Thread management for incident tracking
    CHANNELS_HISTORY = "channels:history"
    GROUPS_HISTORY = "groups:history"
    
    # User and channel management for role-based routing  
    USERS_READ = "users:read"
    USERS_READ_EMAIL = "users:read.email"
    USERGROUPS_READ = "usergroups:read"
    
    # Canvas management for incident documentation
    CANVAS_WRITE = "canvas:write"
    CANVAS_READ = "canvas:read"
    
    # Search capabilities for threat intelligence
    SEARCH_READ = "search:read"
    
    # Workspace management for enterprise controls
    TEAM_READ = "team:read"


class SlackRateLimit(Enum):
    """Slack rate limit tiers for enterprise operations."""
    TIER_1 = 1  # 1+ requests per minute
    TIER_2 = 20  # 20+ requests per minute  
    TIER_3 = 50  # 50+ requests per minute
    TIER_4 = 100  # 100+ requests per minute


@dataclass
class SlackConfig:
    """Slack MCP server configuration for enterprise security integration."""
    # OAuth 2.0 configuration
    client_id: str
    client_secret: str
    bot_token: str
    workspace_id: str
    
    # Enterprise security settings
    rate_limit_tier: SlackRateLimit = SlackRateLimit.TIER_3
    audit_logging: bool = True
    scope_limitation: bool = True
    
    # Required OAuth scopes for security operations
    required_scopes: List[SlackScope] = field(default_factory=lambda: [
        SlackScope.CHANNELS_READ,
        SlackScope.CHANNELS_WRITE, 
        SlackScope.CHAT_WRITE,
        SlackScope.CHANNELS_HISTORY,
        SlackScope.USERS_READ,
        SlackScope.CANVAS_WRITE,
        SlackScope.SEARCH_READ
    ])
    
    # Enterprise controls
    workspace_admin_approval: bool = True
    credential_rotation_days: int = 90
    

@dataclass  
class SlackMessage:
    """Structured Slack message for security incident notifications."""
    channel: str
    text: str
    thread_ts: Optional[str] = None
    
    # Security context
    incident_id: Optional[str] = None
    severity: Optional[EventSeverity] = None
    correlation_id: Optional[str] = None
    
    # Message formatting
    blocks: Optional[List[Dict[str, Any]]] = None
    attachments: Optional[List[Dict[str, Any]]] = None
    
    # Enterprise audit trail
    timestamp: datetime = field(default_factory=datetime.utcnow)
    sent_by: str = "SecurityAgents"
    audit_trail: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SlackThread:
    """Slack thread for incident management and correlation."""
    channel: str
    thread_ts: str
    incident_id: str
    
    # Thread metadata
    created_at: datetime
    updated_at: datetime
    status: str  # "active", "resolved", "escalated"
    
    # Correlation data
    jira_ticket: Optional[str] = None
    canvas_id: Optional[str] = None
    participants: List[str] = field(default_factory=list)
    
    # Business context
    severity: EventSeverity = EventSeverity.MEDIUM
    business_impact: str = ""
    affected_systems: List[str] = field(default_factory=list)


class SlackMCPClient:
    """
    Enterprise Slack MCP client for SecurityAgents platform integration.
    
    Provides OAuth 2.0 authenticated access to Slack workspace with enterprise 
    security controls, rate limiting, audit logging, and incident management workflows.
    """
    
    def __init__(self, config: SlackConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.SlackMCPClient")
        
        # HTTP client with enterprise settings
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            headers={
                "Authorization": f"Bearer {config.bot_token}",
                "Content-Type": "application/json",
                "User-Agent": "SecurityAgents-SlackMCP/1.0"
            }
        )
        
        # Rate limiting and audit
        self.rate_limiter = SlackRateLimiter(config.rate_limit_tier)
        self.audit_logger = SlackAuditLogger() if config.audit_logging else None
        
        # Thread tracking for incident correlation
        self.active_threads: Dict[str, SlackThread] = {}
        
        # Enterprise security controls
        self.security_validator = SlackSecurityValidator(config)
        
    async def authenticate_oauth2(self) -> Dict[str, Any]:
        """
        Authenticate Slack OAuth 2.0 with enterprise security validation.
        
        Returns:
            Dict containing auth info, scopes, and enterprise validation results
        """
        try:
            # Validate OAuth configuration
            await self.security_validator.validate_oauth_config()
            
            # Test authentication with minimal API call
            response = await self._api_call("auth.test")
            
            if not response.get("ok"):
                raise SlackAuthenticationError(f"OAuth authentication failed: {response.get('error')}")
                
            auth_info = {
                "user_id": response.get("user_id"),
                "team_id": response.get("team_id"),
                "team": response.get("team"),
                "url": response.get("url"),
                "scopes": await self._get_bot_scopes(),
                "enterprise_validation": await self.security_validator.validate_workspace()
            }
            
            # Audit successful authentication
            if self.audit_logger:
                await self.audit_logger.log_authentication(auth_info)
                
            self.logger.info(f"Slack OAuth 2.0 authentication successful for workspace {auth_info['team']}")
            return auth_info
            
        except Exception as e:
            self.logger.error(f"Slack OAuth 2.0 authentication failed: {str(e)}")
            if self.audit_logger:
                await self.audit_logger.log_auth_failure(str(e))
            raise
            
    async def send_security_incident_notification(
        self, 
        incident: SecurityEvent, 
        channel: str,
        mention_groups: List[str] = None
    ) -> SlackMessage:
        """
        Send structured security incident notification to Slack channel.
        
        Args:
            incident: SecurityEvent from Alpha-2 gateway
            channel: Target Slack channel
            mention_groups: Groups to mention (@security-team, @security-leadership)
            
        Returns:
            SlackMessage with correlation data and audit trail
        """
        try:
            # Rate limiting compliance
            await self.rate_limiter.wait_if_needed()
            
            # Create structured incident message
            message_blocks = await self._create_incident_blocks(incident, mention_groups)
            
            # Send message with thread creation
            response = await self._api_call("chat.postMessage", {
                "channel": channel,
                "text": f"🚨 {incident.severity.value.upper()} Security Incident: {incident.title}",
                "blocks": message_blocks,
                "unfurl_links": False,
                "unfurl_media": False
            })
            
            if not response.get("ok"):
                raise SlackAPIError(f"Failed to send incident notification: {response.get('error')}")
                
            # Create thread correlation for incident tracking
            thread = SlackThread(
                channel=channel,
                thread_ts=response["ts"],
                incident_id=incident.event_id,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                status="active",
                severity=incident.severity,
                business_impact=incident.description,
                affected_systems=incident.affected_resources
            )
            
            self.active_threads[incident.event_id] = thread
            
            # Create slack message for audit and correlation
            slack_message = SlackMessage(
                channel=channel,
                text=f"🚨 {incident.severity.value.upper()} Security Incident: {incident.title}",
                thread_ts=response["ts"],
                incident_id=incident.event_id,
                severity=incident.severity,
                correlation_id=incident.correlation_id,
                blocks=message_blocks,
                audit_trail={
                    "message_ts": response["ts"],
                    "channel_id": response["channel"],
                    "mention_groups": mention_groups or [],
                    "rate_limit_tier": self.config.rate_limit_tier.name
                }
            )
            
            # Audit trail logging
            if self.audit_logger:
                await self.audit_logger.log_incident_notification(slack_message, incident)
                
            self.logger.info(f"Security incident notification sent: {incident.event_id} in {channel}")
            return slack_message
            
        except Exception as e:
            self.logger.error(f"Failed to send security incident notification: {str(e)}")
            if self.audit_logger:
                await self.audit_logger.log_error("incident_notification", str(e), incident.event_id)
            raise
            
    async def update_incident_thread(
        self, 
        incident_id: str, 
        status_update: str,
        milestone: str = None
    ) -> bool:
        """
        Update incident thread with status milestones and progress tracking.
        
        Args:
            incident_id: SecurityEvent incident identifier
            status_update: Status message for thread
            milestone: Progress milestone (containment, investigation, resolution)
            
        Returns:
            bool indicating successful thread update
        """
        try:
            thread = self.active_threads.get(incident_id)
            if not thread:
                self.logger.warning(f"No active thread found for incident {incident_id}")
                return False
                
            # Rate limiting compliance
            await self.rate_limiter.wait_if_needed()
            
            # Create milestone status message
            status_blocks = await self._create_status_blocks(status_update, milestone)
            
            # Post thread reply with status update
            response = await self._api_call("chat.postMessage", {
                "channel": thread.channel,
                "thread_ts": thread.thread_ts,
                "text": f"📋 Status Update: {status_update}",
                "blocks": status_blocks
            })
            
            if not response.get("ok"):
                self.logger.error(f"Failed to update incident thread: {response.get('error')}")
                return False
                
            # Update thread metadata
            thread.updated_at = datetime.utcnow()
            if milestone:
                thread.status = milestone
                
            # Audit trail
            if self.audit_logger:
                await self.audit_logger.log_thread_update(incident_id, status_update, milestone)
                
            self.logger.info(f"Incident thread updated: {incident_id} - {milestone or 'status'}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update incident thread {incident_id}: {str(e)}")
            return False
            
    async def create_incident_canvas(
        self, 
        incident_id: str, 
        canvas_title: str,
        initial_content: Dict[str, Any]
    ) -> Optional[str]:
        """
        Create Slack canvas for incident war room documentation.
        
        Args:
            incident_id: SecurityEvent incident identifier  
            canvas_title: Canvas title for incident documentation
            initial_content: Initial canvas content structure
            
        Returns:
            Canvas ID if successful, None if failed
        """
        try:
            thread = self.active_threads.get(incident_id)
            if not thread:
                self.logger.warning(f"No active thread for incident {incident_id}")
                return None
                
            # Rate limiting compliance
            await self.rate_limiter.wait_if_needed()
            
            # Create canvas with incident documentation structure
            canvas_data = {
                "title": canvas_title,
                "document_content": {
                    "type": "document",
                    "children": await self._create_incident_canvas_content(initial_content)
                }
            }
            
            response = await self._api_call("canvas.create", canvas_data)
            
            if not response.get("ok"):
                self.logger.error(f"Failed to create incident canvas: {response.get('error')}")
                return None
                
            canvas_id = response.get("canvas", {}).get("id")
            
            # Link canvas to incident thread
            thread.canvas_id = canvas_id
            
            # Share canvas in incident thread
            await self._api_call("chat.postMessage", {
                "channel": thread.channel,
                "thread_ts": thread.thread_ts,
                "text": f"📄 Incident documentation canvas created: {canvas_title}",
                "blocks": [{
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*📄 Incident War Room Canvas*\n<canvas://{canvas_id}|{canvas_title}>\n\nDocumentation and evidence collection for incident {incident_id}"
                    }
                }]
            })
            
            # Audit trail
            if self.audit_logger:
                await self.audit_logger.log_canvas_creation(incident_id, canvas_id, canvas_title)
                
            self.logger.info(f"Incident canvas created: {canvas_id} for {incident_id}")
            return canvas_id
            
        except Exception as e:
            self.logger.error(f"Failed to create incident canvas for {incident_id}: {str(e)}")
            return None
            
    async def _api_call(self, method: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make authenticated API call to Slack with error handling and audit logging."""
        try:
            url = f"https://slack.com/api/{method}"
            
            if method in ["chat.postMessage", "canvas.create"]:
                response = await self.http_client.post(url, json=data or {})
            else:
                response = await self.http_client.get(url, params=data or {})
                
            response.raise_for_status()
            result = response.json()
            
            # Audit API calls for compliance
            if self.audit_logger:
                await self.audit_logger.log_api_call(method, data, result)
                
            return result
            
        except httpx.HTTPStatusError as e:
            self.logger.error(f"Slack API HTTP error {e.response.status_code}: {e}")
            raise SlackAPIError(f"HTTP {e.response.status_code}: {e}")
        except Exception as e:
            self.logger.error(f"Slack API call failed for {method}: {str(e)}")
            raise SlackAPIError(f"API call failed: {str(e)}")
            
    async def _create_incident_blocks(
        self, 
        incident: SecurityEvent, 
        mention_groups: List[str] = None
    ) -> List[Dict[str, Any]]:
        """Create structured Slack blocks for security incident notifications."""
        severity_emoji = {
            EventSeverity.CRITICAL: "🔴",
            EventSeverity.HIGH: "🟠", 
            EventSeverity.MEDIUM: "🟡",
            EventSeverity.LOW: "🟢",
            EventSeverity.INFO: "🔵"
        }
        
        # Build mention string for stakeholder alerting
        mentions = ""
        if mention_groups:
            mentions = " ".join([f"<!subteam^{group}>" for group in mention_groups])
            
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji.get(incident.severity, '⚠️')} {incident.severity.value.upper()} Security Incident"
                }
            },
            {
                "type": "section", 
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Incident ID:*\n{incident.event_id}"
                    },
                    {
                        "type": "mrkdwn", 
                        "text": f"*Source Platform:*\n{incident.source_platform}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Event Type:*\n{incident.event_type.value}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Timestamp:*\n{incident.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{incident.description}"
                }
            }
        ]
        
        # Add affected resources if present
        if incident.affected_resources:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn", 
                    "text": f"*Affected Resources:*\n• " + "\n• ".join(incident.affected_resources)
                }
            })
            
        # Add stakeholder mentions
        if mentions:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Team Notifications:* {mentions}"
                }
            })
            
        # Add action buttons for incident response
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Acknowledge"
                    },
                    "style": "primary",
                    "action_id": f"acknowledge_{incident.event_id}"
                },
                {
                    "type": "button", 
                    "text": {
                        "type": "plain_text",
                        "text": "Escalate"
                    },
                    "style": "danger",
                    "action_id": f"escalate_{incident.event_id}"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text", 
                        "text": "Create War Room"
                    },
                    "action_id": f"war_room_{incident.event_id}"
                }
            ]
        })
        
        return blocks
        
    async def _create_status_blocks(
        self, 
        status_update: str, 
        milestone: str = None
    ) -> List[Dict[str, Any]]:
        """Create structured blocks for incident status updates."""
        milestone_emoji = {
            "containment": "🛡️",
            "investigation": "🔍", 
            "resolution": "✅",
            "escalated": "⬆️",
            "monitoring": "👁️"
        }
        
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{milestone_emoji.get(milestone, '📋')} *Status Update*: {status_update}"
                }
            }
        ]
        
        if milestone:
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Milestone: {milestone.title()} | {datetime.utcnow().strftime('%H:%M UTC')}"
                    }
                ]
            })
            
        return blocks
        
    async def _create_incident_canvas_content(
        self, 
        initial_content: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Create structured canvas content for incident documentation."""
        return [
            {
                "type": "heading",
                "level": 1,
                "children": [{"type": "text", "text": "Security Incident War Room"}]
            },
            {
                "type": "heading", 
                "level": 2,
                "children": [{"type": "text", "text": "Incident Overview"}]
            },
            {
                "type": "paragraph",
                "children": [
                    {"type": "text", "text": f"Incident ID: {initial_content.get('incident_id', 'N/A')}"},
                    {"type": "text", "text": "\n"},
                    {"type": "text", "text": f"Severity: {initial_content.get('severity', 'N/A')}"},
                    {"type": "text", "text": "\n"},
                    {"type": "text", "text": f"Start Time: {initial_content.get('start_time', 'N/A')}"}
                ]
            },
            {
                "type": "heading",
                "level": 2, 
                "children": [{"type": "text", "text": "Timeline & Actions"}]
            },
            {
                "type": "bulleted_list",
                "children": [
                    {
                        "type": "list_item", 
                        "children": [{"type": "text", "text": "Initial detection and alert"}]
                    }
                ]
            },
            {
                "type": "heading",
                "level": 2,
                "children": [{"type": "text", "text": "Evidence & Indicators"}]
            },
            {
                "type": "paragraph",
                "children": [{"type": "text", "text": "Evidence collection and analysis will be documented here."}]
            }
        ]
        
    async def _get_bot_scopes(self) -> List[str]:
        """Get current bot OAuth scopes for validation."""
        try:
            response = await self._api_call("auth.test")
            return response.get("scopes", [])
        except:
            return []
            
    async def close(self):
        """Close HTTP client and cleanup resources."""
        await self.http_client.aclose()


# Supporting classes for enterprise security controls

class SlackRateLimiter:
    """Rate limiter for Slack API compliance."""
    
    def __init__(self, tier: SlackRateLimit):
        self.tier = tier
        self.requests_per_minute = tier.value
        self.requests = []
        
    async def wait_if_needed(self):
        """Implement rate limiting with tier compliance."""
        now = time.time()
        # Remove requests older than 1 minute
        self.requests = [req_time for req_time in self.requests if now - req_time < 60]
        
        if len(self.requests) >= self.requests_per_minute:
            # Calculate wait time
            oldest_request = min(self.requests)
            wait_time = 60 - (now - oldest_request) + 1
            if wait_time > 0:
                await asyncio.sleep(wait_time)
                
        self.requests.append(now)


class SlackSecurityValidator:
    """Enterprise security validation for Slack integration."""
    
    def __init__(self, config: SlackConfig):
        self.config = config
        
    async def validate_oauth_config(self):
        """Validate OAuth 2.0 configuration for enterprise security."""
        if not self.config.client_id or not self.config.client_secret:
            raise SlackConfigurationError("OAuth client credentials not configured")
            
        if not self.config.bot_token:
            raise SlackConfigurationError("Bot token not configured")
            
        if self.config.workspace_admin_approval and not self.config.workspace_id:
            raise SlackConfigurationError("Workspace admin approval required but workspace_id not set")
            
    async def validate_workspace(self) -> Dict[str, Any]:
        """Validate workspace configuration and enterprise controls."""
        return {
            "workspace_admin_approval": self.config.workspace_admin_approval,
            "scope_limitation": self.config.scope_limitation,
            "required_scopes": [scope.value for scope in self.config.required_scopes],
            "rate_limit_tier": self.config.rate_limit_tier.name,
            "audit_logging": self.config.audit_logging
        }


class SlackAuditLogger:
    """Comprehensive audit logging for compliance and security monitoring."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.SlackAuditLogger")
        
    async def log_authentication(self, auth_info: Dict[str, Any]):
        """Log OAuth authentication events."""
        self.logger.info(f"Slack OAuth authentication: {json.dumps(auth_info, default=str)}")
        
    async def log_auth_failure(self, error: str):
        """Log authentication failures."""
        self.logger.error(f"Slack authentication failure: {error}")
        
    async def log_incident_notification(self, message: SlackMessage, incident: SecurityEvent):
        """Log security incident notifications."""
        audit_data = {
            "event_type": "incident_notification",
            "incident_id": incident.event_id,
            "message_ts": message.audit_trail.get("message_ts"),
            "channel": message.channel,
            "severity": incident.severity.value,
            "timestamp": message.timestamp.isoformat()
        }
        self.logger.info(f"Incident notification: {json.dumps(audit_data)}")
        
    async def log_thread_update(self, incident_id: str, status_update: str, milestone: str):
        """Log incident thread updates."""
        audit_data = {
            "event_type": "thread_update",
            "incident_id": incident_id,
            "status_update": status_update,
            "milestone": milestone,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.logger.info(f"Thread update: {json.dumps(audit_data)}")
        
    async def log_canvas_creation(self, incident_id: str, canvas_id: str, title: str):
        """Log canvas creation for incident documentation."""
        audit_data = {
            "event_type": "canvas_creation",
            "incident_id": incident_id, 
            "canvas_id": canvas_id,
            "title": title,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.logger.info(f"Canvas creation: {json.dumps(audit_data)}")
        
    async def log_api_call(self, method: str, data: Dict[str, Any], result: Dict[str, Any]):
        """Log all Slack API calls for audit trail."""
        audit_data = {
            "event_type": "api_call",
            "method": method,
            "success": result.get("ok", False),
            "timestamp": datetime.utcnow().isoformat()
        }
        # Don't log sensitive data in production
        self.logger.debug(f"API call: {json.dumps(audit_data)}")
        
    async def log_error(self, operation: str, error: str, incident_id: str = None):
        """Log errors for troubleshooting and monitoring."""
        audit_data = {
            "event_type": "error", 
            "operation": operation,
            "error": error,
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.logger.error(f"Operation error: {json.dumps(audit_data)}")


# Custom exceptions for error handling

class SlackAPIError(Exception):
    """Slack API interaction errors."""
    pass


class SlackAuthenticationError(Exception):
    """OAuth 2.0 authentication errors."""
    pass
    

class SlackConfigurationError(Exception):
    """Configuration and setup errors."""
    pass


# Configuration factory functions

def create_slack_config(
    client_id: str,
    client_secret: str, 
    bot_token: str,
    workspace_id: str,
    rate_limit_tier: SlackRateLimit = SlackRateLimit.TIER_3
) -> SlackConfig:
    """Create Slack configuration for enterprise security integration."""
    return SlackConfig(
        client_id=client_id,
        client_secret=client_secret,
        bot_token=bot_token,
        workspace_id=workspace_id,
        rate_limit_tier=rate_limit_tier,
        audit_logging=True,
        scope_limitation=True,
        workspace_admin_approval=True
    )