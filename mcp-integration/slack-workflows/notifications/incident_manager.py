"""
Security Incident Management & Notification System

Real-time incident notification system with structured alerts, business impact 
assessment, and automatic stakeholder routing for enterprise security operations.

P0 Deliverable for SecurityAgents Phase 2C Slack Integration  
Author: Tiger Team Alpha-3 Slack Workflows Specialist
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import traceback

# Import Alpha-2's gateway infrastructure and our Slack client
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from gateway.enterprise_mcp_gateway import SecurityEvent, EventSeverity, EventType
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from slack_mcp_client import SlackMCPClient, SlackMessage, SlackThread, SlackConfig


class BusinessImpact(Enum):
    """Business impact classification for incident prioritization."""
    CRITICAL = "critical"  # Revenue loss, compliance violation, data breach
    HIGH = "high"         # Service degradation, customer impact
    MEDIUM = "medium"     # Internal systems, productivity impact  
    LOW = "low"          # Minimal business impact
    NONE = "none"        # No business impact


class NotificationChannel(Enum):
    """Slack channels for different incident types and escalation levels."""
    # Primary incident channels
    SECURITY_INCIDENTS = "security-incidents"
    SECURITY_ALERTS = "security-alerts"
    
    # Escalation channels
    SECURITY_LEADERSHIP = "security-leadership"
    EXECUTIVE_SECURITY = "executive-security"
    
    # Specialized channels
    THREAT_INTEL = "threat-intelligence"
    COMPLIANCE_ALERTS = "compliance-alerts"
    DEVOPS_SECURITY = "devops-security"
    
    # Crisis management
    INCIDENT_COMMAND = "incident-command"
    LEGAL_SECURITY = "legal-security"
    PR_SECURITY = "pr-security"


class StakeholderGroup(Enum):
    """Stakeholder groups for @mention routing based on incident severity."""
    # Core security team
    SECURITY_TEAM = "security-team"
    SECURITY_ANALYSTS = "security-analysts"
    
    # Leadership escalation
    SECURITY_LEADERSHIP = "security-leadership"
    SECURITY_MANAGERS = "security-managers"
    
    # Executive escalation  
    CISO = "ciso"
    EXECUTIVE_TEAM = "executive-team"
    
    # Specialized teams
    IR_TEAM = "incident-response-team"
    COMPLIANCE_TEAM = "compliance-team"
    LEGAL_TEAM = "legal-team"
    PR_TEAM = "pr-team"


@dataclass
class BusinessContext:
    """Business context for incident impact assessment."""
    # Asset classification
    asset_criticality: str = "medium"  # critical, high, medium, low
    asset_classification: str = "internal"  # public, internal, confidential, secret
    
    # Business impact
    revenue_impact: float = 0.0  # Estimated revenue impact per hour
    customer_impact: int = 0     # Number of affected customers
    compliance_impact: List[str] = field(default_factory=list)  # Affected frameworks
    
    # Operational context
    business_hours: bool = True
    environment: str = "production"  # production, staging, development
    geography: List[str] = field(default_factory=list)  # Affected regions
    
    # Escalation context
    media_attention_risk: bool = False
    regulatory_notification_required: bool = False
    customer_notification_required: bool = False


@dataclass
class NotificationRule:
    """Notification routing rules based on incident characteristics."""
    # Matching criteria
    severity_levels: List[EventSeverity]
    event_types: List[EventType] 
    business_impact_levels: List[BusinessImpact]
    
    # Notification targets
    primary_channel: NotificationChannel
    mention_groups: List[StakeholderGroup]
    escalation_channels: List[NotificationChannel] = field(default_factory=list)
    
    # Timing
    immediate_notification: bool = True
    escalation_delay_minutes: int = 30
    executive_escalation_delay_hours: int = 2
    
    # Special handling
    requires_war_room: bool = False
    requires_legal_review: bool = False
    requires_pr_coordination: bool = False


@dataclass
class IncidentTracker:
    """Incident tracking for correlation and status management."""
    incident_id: str
    event: SecurityEvent
    business_context: BusinessContext
    
    # Notification state
    slack_thread: Optional[SlackThread] = None
    canvas_id: Optional[str] = None
    jira_ticket: Optional[str] = None
    
    # Timeline tracking
    created_at: datetime = field(default_factory=datetime.utcnow)
    first_notification_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    escalated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    # Status tracking
    status: str = "new"  # new, acknowledged, investigating, contained, resolved
    assigned_analyst: Optional[str] = None
    escalation_level: int = 0  # 0=team, 1=leadership, 2=executive
    
    # Response tracking
    response_actions: List[str] = field(default_factory=list)
    status_updates: List[Dict[str, Any]] = field(default_factory=list)
    evidence_collected: List[str] = field(default_factory=list)


class SecurityIncidentManager:
    """
    Enterprise security incident management with Slack workflow automation.
    
    Handles structured notifications, business impact assessment, stakeholder routing,
    and incident lifecycle management for SecurityAgents platform integration.
    """
    
    def __init__(self, slack_client: SlackMCPClient):
        self.slack_client = slack_client
        self.logger = logging.getLogger(f"{__name__}.SecurityIncidentManager")
        
        # Incident tracking
        self.active_incidents: Dict[str, IncidentTracker] = {}
        
        # Load notification rules  
        self.notification_rules = self._initialize_notification_rules()
        
        # Business impact assessment engine
        self.impact_assessor = BusinessImpactAssessor()
        
        # Integration components will be initialized
        self.jira_integration = None  # TODO: Integrate with Atlassian MCP
        self.tines_integration = None  # TODO: Integrate with Tines workflows
        
    async def process_security_incident(
        self, 
        event: SecurityEvent,
        business_context: Optional[BusinessContext] = None
    ) -> IncidentTracker:
        """
        Process security incident with full workflow automation.
        
        Args:
            event: SecurityEvent from Alpha-2 gateway
            business_context: Optional business context for impact assessment
            
        Returns:
            IncidentTracker with notification status and correlation data
        """
        try:
            # Create incident tracker
            incident = IncidentTracker(
                incident_id=event.event_id,
                event=event,
                business_context=business_context or BusinessContext()
            )
            
            self.active_incidents[event.event_id] = incident
            
            # Assess business impact
            business_impact = await self.impact_assessor.assess_impact(event, incident.business_context)
            
            # Find matching notification rules
            notification_rule = await self._find_notification_rule(event, business_impact)
            
            if not notification_rule:
                self.logger.warning(f"No notification rule found for incident {event.event_id}")
                return incident
                
            # Send primary notification
            await self._send_primary_notification(incident, notification_rule, business_impact)
            
            # Handle special requirements
            if notification_rule.requires_war_room:
                await self._create_incident_war_room(incident)
                
            if notification_rule.requires_legal_review:
                await self._notify_legal_team(incident, business_impact)
                
            if notification_rule.requires_pr_coordination:
                await self._notify_pr_team(incident, business_impact)
                
            # Schedule escalation if needed
            if notification_rule.escalation_delay_minutes > 0:
                await self._schedule_escalation(incident, notification_rule)
                
            self.logger.info(f"Security incident processed: {event.event_id} with {business_impact.value} impact")
            return incident
            
        except Exception as e:
            self.logger.error(f"Failed to process security incident {event.event_id}: {str(e)}")
            self.logger.error(traceback.format_exc())
            raise
            
    async def update_incident_status(
        self, 
        incident_id: str, 
        status: str,
        status_message: str,
        analyst: Optional[str] = None,
        evidence: Optional[List[str]] = None
    ) -> bool:
        """
        Update incident status with Slack thread notifications and audit trail.
        
        Args:
            incident_id: SecurityEvent incident identifier
            status: New status (acknowledged, investigating, contained, resolved)
            status_message: Human-readable status update
            analyst: Assigned analyst identifier
            evidence: List of evidence items collected
            
        Returns:
            bool indicating successful status update
        """
        try:
            incident = self.active_incidents.get(incident_id)
            if not incident:
                self.logger.warning(f"Incident not found: {incident_id}")
                return False
                
            # Update incident tracker
            old_status = incident.status
            incident.status = status
            
            if analyst:
                incident.assigned_analyst = analyst
                
            if evidence:
                incident.evidence_collected.extend(evidence)
                
            # Record status update
            status_update = {
                "timestamp": datetime.utcnow(),
                "old_status": old_status,
                "new_status": status,
                "message": status_message,
                "analyst": analyst,
                "evidence_count": len(evidence) if evidence else 0
            }
            incident.status_updates.append(status_update)
            
            # Update milestones based on status
            if status == "acknowledged" and not incident.acknowledged_at:
                incident.acknowledged_at = datetime.utcnow()
                
            if status == "resolved" and not incident.resolved_at:
                incident.resolved_at = datetime.utcnow()
                
            # Send Slack thread update
            milestone = self._status_to_milestone(status)
            success = await self.slack_client.update_incident_thread(
                incident_id, 
                status_message, 
                milestone
            )
            
            if not success:
                self.logger.error(f"Failed to update Slack thread for incident {incident_id}")
                
            # Handle resolution workflow
            if status == "resolved":
                await self._handle_incident_resolution(incident)
                
            self.logger.info(f"Incident status updated: {incident_id} -> {status}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update incident status {incident_id}: {str(e)}")
            return False
            
    async def escalate_incident(
        self, 
        incident_id: str, 
        escalation_reason: str,
        target_level: int = None
    ) -> bool:
        """
        Escalate incident to higher stakeholder levels with business context.
        
        Args:
            incident_id: SecurityEvent incident identifier
            escalation_reason: Reason for escalation
            target_level: Target escalation level (1=leadership, 2=executive)
            
        Returns:
            bool indicating successful escalation
        """
        try:
            incident = self.active_incidents.get(incident_id)
            if not incident:
                self.logger.warning(f"Incident not found for escalation: {incident_id}")
                return False
                
            # Determine escalation level
            if target_level is None:
                target_level = incident.escalation_level + 1
                
            if target_level > 2:
                self.logger.warning(f"Maximum escalation level reached for {incident_id}")
                return False
                
            # Update incident tracking
            incident.escalation_level = target_level
            incident.escalated_at = datetime.utcnow()
            
            # Determine escalation targets
            if target_level == 1:  # Leadership escalation
                channel = NotificationChannel.SECURITY_LEADERSHIP
                mention_groups = [StakeholderGroup.SECURITY_LEADERSHIP, StakeholderGroup.SECURITY_MANAGERS]
            elif target_level == 2:  # Executive escalation
                channel = NotificationChannel.EXECUTIVE_SECURITY  
                mention_groups = [StakeholderGroup.CISO, StakeholderGroup.EXECUTIVE_TEAM]
            else:
                self.logger.error(f"Invalid escalation level: {target_level}")
                return False
                
            # Create escalation notification
            escalation_message = await self._create_escalation_message(
                incident, escalation_reason, target_level
            )
            
            # Send escalation notification
            response = await self.slack_client.send_security_incident_notification(
                incident.event,
                channel.value,
                [group.value for group in mention_groups]
            )
            
            if not response:
                self.logger.error(f"Failed to send escalation notification for {incident_id}")
                return False
                
            # Update thread with escalation notice
            await self.slack_client.update_incident_thread(
                incident_id,
                f"⬆️ Escalated to {channel.value}: {escalation_reason}",
                "escalated"
            )
            
            self.logger.info(f"Incident escalated: {incident_id} to level {target_level}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to escalate incident {incident_id}: {str(e)}")
            return False
            
    async def _send_primary_notification(
        self, 
        incident: IncidentTracker, 
        rule: NotificationRule,
        business_impact: BusinessImpact
    ) -> bool:
        """Send primary incident notification following routing rules."""
        try:
            # Send notification to primary channel
            slack_message = await self.slack_client.send_security_incident_notification(
                incident.event,
                rule.primary_channel.value,
                [group.value for group in rule.mention_groups]
            )
            
            # Update incident tracking
            incident.slack_thread = SlackThread(
                channel=rule.primary_channel.value,
                thread_ts=slack_message.thread_ts,
                incident_id=incident.incident_id,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                status="active",
                severity=incident.event.severity,
                business_impact=business_impact.value,
                affected_systems=incident.event.affected_resources
            )
            
            incident.first_notification_at = datetime.utcnow()
            
            # Add business context to thread
            if business_impact != BusinessImpact.NONE:
                await self._add_business_context_to_thread(incident, business_impact)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send primary notification: {str(e)}")
            return False
            
    async def _add_business_context_to_thread(
        self, 
        incident: IncidentTracker, 
        business_impact: BusinessImpact
    ) -> bool:
        """Add business impact context to incident thread."""
        try:
            context_message = await self._format_business_context(
                incident.business_context, business_impact
            )
            
            return await self.slack_client.update_incident_thread(
                incident.incident_id,
                context_message,
                "business_impact"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to add business context: {str(e)}")
            return False
            
    async def _create_incident_war_room(self, incident: IncidentTracker) -> bool:
        """Create incident war room canvas for documentation and coordination."""
        try:
            canvas_title = f"Incident War Room - {incident.incident_id}"
            
            canvas_content = {
                "incident_id": incident.incident_id,
                "severity": incident.event.severity.value,
                "start_time": incident.created_at.isoformat(),
                "description": incident.event.description,
                "affected_systems": incident.event.affected_resources
            }
            
            canvas_id = await self.slack_client.create_incident_canvas(
                incident.incident_id,
                canvas_title,
                canvas_content
            )
            
            if canvas_id:
                incident.canvas_id = canvas_id
                return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to create incident war room: {str(e)}")
            return False
            
    async def _notify_legal_team(self, incident: IncidentTracker, business_impact: BusinessImpact):
        """Notify legal team for incidents requiring legal review.""" 
        try:
            # TODO: Implement legal team notification
            self.logger.info(f"Legal notification required for incident {incident.incident_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to notify legal team: {str(e)}")
            
    async def _notify_pr_team(self, incident: IncidentTracker, business_impact: BusinessImpact):
        """Notify PR team for incidents with media attention risk."""
        try:
            # TODO: Implement PR team notification
            self.logger.info(f"PR coordination required for incident {incident.incident_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to notify PR team: {str(e)}")
            
    async def _schedule_escalation(self, incident: IncidentTracker, rule: NotificationRule):
        """Schedule automatic escalation if incident is not resolved."""
        try:
            # TODO: Implement escalation scheduling with asyncio tasks
            self.logger.info(f"Escalation scheduled for incident {incident.incident_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to schedule escalation: {str(e)}")
            
    async def _handle_incident_resolution(self, incident: IncidentTracker):
        """Handle incident resolution workflow and lessons learned."""
        try:
            # Calculate response time metrics
            if incident.first_notification_at and incident.resolved_at:
                response_time = incident.resolved_at - incident.first_notification_at
                self.logger.info(f"Incident {incident.incident_id} resolved in {response_time}")
                
            # TODO: Implement post-incident analysis automation
            
        except Exception as e:
            self.logger.error(f"Failed to handle incident resolution: {str(e)}")
            
    async def _find_notification_rule(
        self, 
        event: SecurityEvent, 
        business_impact: BusinessImpact
    ) -> Optional[NotificationRule]:
        """Find matching notification rule for incident characteristics."""
        for rule in self.notification_rules:
            if (event.severity in rule.severity_levels and 
                event.event_type in rule.event_types and
                business_impact in rule.business_impact_levels):
                return rule
                
        # Default rule for unmatched incidents
        return self.notification_rules[-1] if self.notification_rules else None
        
    def _initialize_notification_rules(self) -> List[NotificationRule]:
        """Initialize notification routing rules for different incident types."""
        return [
            # Critical incidents requiring immediate executive attention
            NotificationRule(
                severity_levels=[EventSeverity.CRITICAL],
                event_types=[EventType.THREAT_DETECTION, EventType.SECURITY_POLICY_VIOLATION],
                business_impact_levels=[BusinessImpact.CRITICAL, BusinessImpact.HIGH],
                primary_channel=NotificationChannel.SECURITY_INCIDENTS,
                mention_groups=[StakeholderGroup.SECURITY_TEAM, StakeholderGroup.SECURITY_LEADERSHIP],
                escalation_channels=[NotificationChannel.EXECUTIVE_SECURITY],
                escalation_delay_minutes=30,
                executive_escalation_delay_hours=1,
                requires_war_room=True,
                requires_legal_review=True
            ),
            
            # High-severity incidents requiring leadership attention  
            NotificationRule(
                severity_levels=[EventSeverity.HIGH],
                event_types=[EventType.VULNERABILITY_DISCOVERY, EventType.COMPLIANCE_VIOLATION],
                business_impact_levels=[BusinessImpact.HIGH, BusinessImpact.MEDIUM],
                primary_channel=NotificationChannel.SECURITY_INCIDENTS,
                mention_groups=[StakeholderGroup.SECURITY_TEAM],
                escalation_channels=[NotificationChannel.SECURITY_LEADERSHIP],
                escalation_delay_minutes=60,
                executive_escalation_delay_hours=4,
                requires_war_room=True
            ),
            
            # Medium-severity standard workflow
            NotificationRule(
                severity_levels=[EventSeverity.MEDIUM],
                event_types=[EventType.THREAT_DETECTION, EventType.VULNERABILITY_DISCOVERY],
                business_impact_levels=[BusinessImpact.MEDIUM, BusinessImpact.LOW],
                primary_channel=NotificationChannel.SECURITY_ALERTS,
                mention_groups=[StakeholderGroup.SECURITY_ANALYSTS],
                escalation_delay_minutes=120
            ),
            
            # Default rule for all other incidents
            NotificationRule(
                severity_levels=[EventSeverity.LOW, EventSeverity.INFO],
                event_types=list(EventType),
                business_impact_levels=list(BusinessImpact),
                primary_channel=NotificationChannel.SECURITY_ALERTS,
                mention_groups=[],
                immediate_notification=False
            )
        ]
        
    def _status_to_milestone(self, status: str) -> str:
        """Convert incident status to milestone for thread updates."""
        status_mapping = {
            "acknowledged": "containment",
            "investigating": "investigation", 
            "contained": "containment",
            "resolved": "resolution",
            "escalated": "escalated"
        }
        return status_mapping.get(status, "monitoring")
        
    async def _create_escalation_message(
        self, 
        incident: IncidentTracker, 
        reason: str, 
        level: int
    ) -> str:
        """Create formatted escalation message with business context."""
        level_names = {1: "Leadership", 2: "Executive"}
        level_name = level_names.get(level, "Unknown")
        
        duration = ""
        if incident.first_notification_at:
            elapsed = datetime.utcnow() - incident.first_notification_at
            duration = f" (Duration: {elapsed})"
            
        return f"🚨 {level_name} Escalation Required{duration}\n\nReason: {reason}\n\nIncident: {incident.event.title}\nSeverity: {incident.event.severity.value.upper()}\nStatus: {incident.status.title()}"
        
    async def _format_business_context(
        self, 
        context: BusinessContext, 
        impact: BusinessImpact
    ) -> str:
        """Format business context for incident thread."""
        message_parts = [f"💼 **Business Impact: {impact.value.upper()}**"]
        
        if context.asset_criticality != "medium":
            message_parts.append(f"• Asset Criticality: {context.asset_criticality.title()}")
            
        if context.revenue_impact > 0:
            message_parts.append(f"• Estimated Revenue Impact: ${context.revenue_impact:,.2f}/hour")
            
        if context.customer_impact > 0:
            message_parts.append(f"• Affected Customers: {context.customer_impact:,}")
            
        if context.compliance_impact:
            message_parts.append(f"• Compliance Impact: {', '.join(context.compliance_impact)}")
            
        if context.regulatory_notification_required:
            message_parts.append("⚠️ Regulatory notification may be required")
            
        return "\n".join(message_parts)


class BusinessImpactAssessor:
    """
    Business impact assessment engine for incident prioritization.
    
    Evaluates business context and incident characteristics to determine
    appropriate response levels and stakeholder notification requirements.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.BusinessImpactAssessor")
        
    async def assess_impact(
        self, 
        event: SecurityEvent, 
        context: BusinessContext
    ) -> BusinessImpact:
        """
        Assess business impact based on incident characteristics and context.
        
        Args:
            event: SecurityEvent from Alpha-2 gateway
            context: BusinessContext for impact calculation
            
        Returns:
            BusinessImpact classification for routing decisions
        """
        try:
            impact_score = 0
            
            # Severity-based scoring
            severity_scores = {
                EventSeverity.CRITICAL: 50,
                EventSeverity.HIGH: 30,
                EventSeverity.MEDIUM: 15,
                EventSeverity.LOW: 5,
                EventSeverity.INFO: 0
            }
            impact_score += severity_scores.get(event.severity, 0)
            
            # Event type impact
            event_type_scores = {
                EventType.THREAT_DETECTION: 20,
                EventType.SECURITY_POLICY_VIOLATION: 15,
                EventType.VULNERABILITY_DISCOVERY: 10,
                EventType.COMPLIANCE_VIOLATION: 25,
                EventType.INCIDENT_ESCALATION: 30
            }
            impact_score += event_type_scores.get(event.event_type, 5)
            
            # Business context scoring
            if context.asset_criticality == "critical":
                impact_score += 30
            elif context.asset_criticality == "high":
                impact_score += 20
            elif context.asset_criticality == "medium":
                impact_score += 10
                
            # Asset classification impact
            if context.asset_classification in ["secret", "confidential"]:
                impact_score += 20
            elif context.asset_classification == "internal":
                impact_score += 10
                
            # Revenue and customer impact
            if context.revenue_impact > 100000:  # $100k+/hour
                impact_score += 40
            elif context.revenue_impact > 10000:  # $10k+/hour  
                impact_score += 20
            elif context.revenue_impact > 1000:   # $1k+/hour
                impact_score += 10
                
            if context.customer_impact > 10000:
                impact_score += 30
            elif context.customer_impact > 1000:
                impact_score += 15
            elif context.customer_impact > 100:
                impact_score += 5
                
            # Compliance and regulatory impact
            if context.compliance_impact:
                impact_score += len(context.compliance_impact) * 10
                
            if context.regulatory_notification_required:
                impact_score += 25
                
            # Environmental factors
            if context.environment == "production":
                impact_score += 15
            elif context.environment == "staging":
                impact_score += 5
                
            if not context.business_hours:
                impact_score *= 0.8  # Reduce impact outside business hours
                
            # Risk factors
            if context.media_attention_risk:
                impact_score += 20
                
            # Determine final business impact classification
            if impact_score >= 80:
                return BusinessImpact.CRITICAL
            elif impact_score >= 60:
                return BusinessImpact.HIGH
            elif impact_score >= 30:
                return BusinessImpact.MEDIUM
            elif impact_score >= 10:
                return BusinessImpact.LOW
            else:
                return BusinessImpact.NONE
                
        except Exception as e:
            self.logger.error(f"Failed to assess business impact: {str(e)}")
            # Default to medium impact for safety
            return BusinessImpact.MEDIUM