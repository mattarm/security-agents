"""
Role-Based Escalation Engine for SecurityAgents Platform

Dynamic escalation workflows with time-based triggers, stakeholder routing,
and executive notification for enterprise security incident management.

P0 Deliverable for SecurityAgents Phase 2C Slack Integration
Author: Tiger Team Alpha-3 Slack Workflows Specialist
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import traceback

# Import Alpha-2's gateway infrastructure and our Slack components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from gateway.enterprise_mcp_gateway import SecurityEvent, EventSeverity, EventType
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from slack_mcp_client import SlackMCPClient, SlackMessage, SlackThread
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from notifications.incident_manager import (
    IncidentTracker, BusinessImpact, BusinessContext,
    NotificationChannel, StakeholderGroup
)


class EscalationLevel(Enum):
    """Escalation levels for incident management hierarchy."""
    TEAM = 0           # Security team and analysts
    LEADERSHIP = 1     # Security leadership and managers  
    EXECUTIVE = 2      # CISO and executive team
    CRISIS = 3         # Crisis management and external coordination


class EscalationTrigger(Enum):
    """Triggers that initiate escalation workflows."""
    TIME_BASED = "time_based"           # Duration without resolution
    SEVERITY_BASED = "severity_based"   # Incident severity level
    IMPACT_BASED = "impact_based"       # Business impact assessment
    MANUAL = "manual"                   # Manual escalation request
    AUTOMATED = "automated"             # System-triggered escalation
    COMPLIANCE = "compliance"           # Regulatory/compliance requirement


class EscalationStatus(Enum):
    """Status of escalation processes."""
    PENDING = "pending"       # Escalation scheduled but not triggered
    ACTIVE = "active"         # Escalation in progress
    ACKNOWLEDGED = "acknowledged"  # Escalation acknowledged by stakeholder
    COMPLETED = "completed"   # Escalation resolved or superseded
    FAILED = "failed"         # Escalation attempt failed


@dataclass
class EscalationRule:
    """Rules defining when and how to escalate incidents."""
    # Matching criteria
    severity_levels: List[EventSeverity]
    business_impact_levels: List[BusinessImpact]
    event_types: List[EventType]
    
    # Timing triggers
    team_response_timeout_minutes: int = 30      # Team level timeout
    leadership_response_timeout_minutes: int = 120  # Leadership timeout
    executive_notification_hours: int = 2       # Executive notification
    crisis_escalation_hours: int = 4            # Crisis management
    
    # Escalation targets by level
    team_stakeholders: List[StakeholderGroup] = field(default_factory=list)
    leadership_stakeholders: List[StakeholderGroup] = field(default_factory=list)
    executive_stakeholders: List[StakeholderGroup] = field(default_factory=list)
    crisis_stakeholders: List[StakeholderGroup] = field(default_factory=list)
    
    # Escalation channels by level
    team_channels: List[NotificationChannel] = field(default_factory=list)
    leadership_channels: List[NotificationChannel] = field(default_factory=list)
    executive_channels: List[NotificationChannel] = field(default_factory=list)
    crisis_channels: List[NotificationChannel] = field(default_factory=list)
    
    # Special requirements
    requires_war_room: bool = False
    requires_legal_notification: bool = False
    requires_pr_coordination: bool = False
    requires_vendor_coordination: bool = False
    requires_regulatory_notification: bool = False
    
    # Business context requirements
    business_hours_only: bool = False
    weekend_executive_approval: bool = False
    
    
@dataclass  
class EscalationEvent:
    """Individual escalation event tracking."""
    escalation_id: str
    incident_id: str
    trigger: EscalationTrigger
    from_level: EscalationLevel
    to_level: EscalationLevel
    
    # Timing
    scheduled_at: datetime
    triggered_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Status and context
    status: EscalationStatus = EscalationStatus.PENDING
    reason: str = ""
    business_justification: str = ""
    
    # Notification tracking
    slack_messages: List[SlackMessage] = field(default_factory=list)
    notified_stakeholders: Set[str] = field(default_factory=set)
    
    # Response tracking
    acknowledged_by: Optional[str] = None
    response_actions: List[str] = field(default_factory=list)
    
    
@dataclass
class StakeholderMap:
    """Mapping of stakeholder groups to Slack users and channels."""
    # Security team mapping
    security_team_members: List[str] = field(default_factory=list)
    security_analysts: List[str] = field(default_factory=list)
    
    # Leadership mapping  
    security_leadership: List[str] = field(default_factory=list)
    security_managers: List[str] = field(default_factory=list)
    
    # Executive mapping
    ciso: List[str] = field(default_factory=list)
    executive_team: List[str] = field(default_factory=list)
    
    # Specialized teams
    ir_team: List[str] = field(default_factory=list)
    compliance_team: List[str] = field(default_factory=list)
    legal_team: List[str] = field(default_factory=list)
    pr_team: List[str] = field(default_factory=list)
    
    # On-call schedules
    on_call_security: Optional[str] = None
    on_call_leadership: Optional[str] = None
    on_call_executive: Optional[str] = None


class EscalationEngine:
    """
    Enterprise escalation engine for security incident management.
    
    Provides time-based and impact-driven escalation workflows with dynamic
    stakeholder routing, executive notifications, and compliance integration.
    """
    
    def __init__(self, slack_client: SlackMCPClient):
        self.slack_client = slack_client
        self.logger = logging.getLogger(f"{__name__}.EscalationEngine")
        
        # Escalation tracking
        self.active_escalations: Dict[str, EscalationEvent] = {}
        self.escalation_history: List[EscalationEvent] = []
        
        # Configuration
        self.escalation_rules = self._initialize_escalation_rules()
        self.stakeholder_map = StakeholderMap()  # TODO: Load from configuration
        
        # Background tasks
        self.escalation_monitor_task: Optional[asyncio.Task] = None
        self.is_monitoring = False
        
    async def start_monitoring(self):
        """Start background escalation monitoring."""
        if self.is_monitoring:
            return
            
        self.is_monitoring = True
        self.escalation_monitor_task = asyncio.create_task(self._escalation_monitor_loop())
        self.logger.info("Escalation monitoring started")
        
    async def stop_monitoring(self):
        """Stop background escalation monitoring."""
        self.is_monitoring = False
        if self.escalation_monitor_task:
            self.escalation_monitor_task.cancel()
            try:
                await self.escalation_monitor_task
            except asyncio.CancelledError:
                pass
        self.logger.info("Escalation monitoring stopped")
        
    async def schedule_incident_escalation(
        self, 
        incident: IncidentTracker,
        business_impact: BusinessImpact
    ) -> List[EscalationEvent]:
        """
        Schedule escalation workflows for incident based on rules and business impact.
        
        Args:
            incident: IncidentTracker with incident details
            business_impact: Business impact classification
            
        Returns:
            List of EscalationEvents scheduled for this incident
        """
        try:
            escalation_rule = await self._find_escalation_rule(
                incident.event, business_impact
            )
            
            if not escalation_rule:
                self.logger.warning(f"No escalation rule found for incident {incident.incident_id}")
                return []
                
            scheduled_escalations = []
            
            # Schedule team level escalation (if timeout configured)
            if escalation_rule.team_response_timeout_minutes > 0:
                team_escalation = await self._schedule_escalation_level(
                    incident, escalation_rule, EscalationLevel.TEAM,
                    escalation_rule.team_response_timeout_minutes
                )
                if team_escalation:
                    scheduled_escalations.append(team_escalation)
                    
            # Schedule leadership escalation
            if escalation_rule.leadership_response_timeout_minutes > 0:
                leadership_escalation = await self._schedule_escalation_level(
                    incident, escalation_rule, EscalationLevel.LEADERSHIP,
                    escalation_rule.leadership_response_timeout_minutes
                )
                if leadership_escalation:
                    scheduled_escalations.append(leadership_escalation)
                    
            # Schedule executive notification
            if escalation_rule.executive_notification_hours > 0:
                executive_escalation = await self._schedule_escalation_level(
                    incident, escalation_rule, EscalationLevel.EXECUTIVE,
                    escalation_rule.executive_notification_hours * 60  # Convert to minutes
                )
                if executive_escalation:
                    scheduled_escalations.append(executive_escalation)
                    
            # Schedule crisis escalation if configured
            if escalation_rule.crisis_escalation_hours > 0:
                crisis_escalation = await self._schedule_escalation_level(
                    incident, escalation_rule, EscalationLevel.CRISIS,
                    escalation_rule.crisis_escalation_hours * 60  # Convert to minutes
                )
                if crisis_escalation:
                    scheduled_escalations.append(crisis_escalation)
                    
            self.logger.info(f"Scheduled {len(scheduled_escalations)} escalations for incident {incident.incident_id}")
            return scheduled_escalations
            
        except Exception as e:
            self.logger.error(f"Failed to schedule escalations for incident {incident.incident_id}: {str(e)}")
            return []
            
    async def execute_manual_escalation(
        self, 
        incident_id: str,
        target_level: EscalationLevel,
        reason: str,
        requested_by: str
    ) -> bool:
        """
        Execute manual escalation requested by security team member.
        
        Args:
            incident_id: SecurityEvent incident identifier
            target_level: Target escalation level
            reason: Reason for manual escalation
            requested_by: User requesting escalation
            
        Returns:
            bool indicating successful escalation execution
        """
        try:
            # Create manual escalation event
            escalation_event = EscalationEvent(
                escalation_id=str(uuid.uuid4()),
                incident_id=incident_id,
                trigger=EscalationTrigger.MANUAL,
                from_level=EscalationLevel.TEAM,  # Assume manual from team level
                to_level=target_level,
                scheduled_at=datetime.utcnow(),
                triggered_at=datetime.utcnow(),
                reason=reason,
                business_justification=f"Manual escalation requested by {requested_by}: {reason}"
            )
            
            # Execute escalation immediately
            success = await self._execute_escalation(escalation_event)
            
            if success:
                escalation_event.status = EscalationStatus.ACTIVE
                self.active_escalations[escalation_event.escalation_id] = escalation_event
                self.escalation_history.append(escalation_event)
                
            self.logger.info(f"Manual escalation executed for incident {incident_id} to {target_level.name}")
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to execute manual escalation: {str(e)}")
            return False
            
    async def acknowledge_escalation(
        self, 
        escalation_id: str, 
        acknowledged_by: str,
        response_actions: List[str] = None
    ) -> bool:
        """
        Acknowledge escalation and update tracking.
        
        Args:
            escalation_id: EscalationEvent identifier
            acknowledged_by: User acknowledging escalation
            response_actions: Planned response actions
            
        Returns:
            bool indicating successful acknowledgment
        """
        try:
            escalation = self.active_escalations.get(escalation_id)
            if not escalation:
                self.logger.warning(f"Escalation not found: {escalation_id}")
                return False
                
            # Update escalation tracking
            escalation.status = EscalationStatus.ACKNOWLEDGED
            escalation.acknowledged_at = datetime.utcnow()
            escalation.acknowledged_by = acknowledged_by
            
            if response_actions:
                escalation.response_actions.extend(response_actions)
                
            # Notify incident thread of acknowledgment
            await self.slack_client.update_incident_thread(
                escalation.incident_id,
                f"✅ Escalation acknowledged by {acknowledged_by}",
                "acknowledged"
            )
            
            self.logger.info(f"Escalation acknowledged: {escalation_id} by {acknowledged_by}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to acknowledge escalation {escalation_id}: {str(e)}")
            return False
            
    async def cancel_escalations(self, incident_id: str, reason: str = "Incident resolved") -> int:
        """
        Cancel all pending escalations for resolved incident.
        
        Args:
            incident_id: SecurityEvent incident identifier
            reason: Reason for cancellation
            
        Returns:
            int number of escalations cancelled
        """
        try:
            cancelled_count = 0
            
            # Find and cancel pending escalations
            for escalation_id, escalation in list(self.active_escalations.items()):
                if (escalation.incident_id == incident_id and 
                    escalation.status == EscalationStatus.PENDING):
                    
                    escalation.status = EscalationStatus.COMPLETED
                    escalation.completed_at = datetime.utcnow()
                    escalation.reason = reason
                    
                    # Remove from active escalations
                    del self.active_escalations[escalation_id]
                    cancelled_count += 1
                    
            if cancelled_count > 0:
                self.logger.info(f"Cancelled {cancelled_count} escalations for incident {incident_id}")
                
            return cancelled_count
            
        except Exception as e:
            self.logger.error(f"Failed to cancel escalations for incident {incident_id}: {str(e)}")
            return 0
            
    async def get_escalation_status(self, incident_id: str) -> Dict[str, Any]:
        """Get escalation status summary for incident."""
        try:
            incident_escalations = [
                escalation for escalation in self.active_escalations.values()
                if escalation.incident_id == incident_id
            ]
            
            status_summary = {
                "incident_id": incident_id,
                "total_escalations": len(incident_escalations),
                "pending_escalations": len([e for e in incident_escalations if e.status == EscalationStatus.PENDING]),
                "active_escalations": len([e for e in incident_escalations if e.status == EscalationStatus.ACTIVE]),
                "acknowledged_escalations": len([e for e in incident_escalations if e.status == EscalationStatus.ACKNOWLEDGED]),
                "escalation_levels": [e.to_level.name for e in incident_escalations],
                "next_escalation": None
            }
            
            # Find next pending escalation
            pending_escalations = [e for e in incident_escalations if e.status == EscalationStatus.PENDING]
            if pending_escalations:
                next_escalation = min(pending_escalations, key=lambda x: x.scheduled_at)
                status_summary["next_escalation"] = {
                    "level": next_escalation.to_level.name,
                    "scheduled_at": next_escalation.scheduled_at.isoformat(),
                    "trigger": next_escalation.trigger.value
                }
                
            return status_summary
            
        except Exception as e:
            self.logger.error(f"Failed to get escalation status for incident {incident_id}: {str(e)}")
            return {"error": str(e)}
            
    async def _escalation_monitor_loop(self):
        """Background loop to monitor and trigger scheduled escalations."""
        while self.is_monitoring:
            try:
                current_time = datetime.utcnow()
                
                # Check for escalations ready to trigger
                for escalation_id, escalation in list(self.active_escalations.items()):
                    if (escalation.status == EscalationStatus.PENDING and 
                        escalation.scheduled_at <= current_time):
                        
                        try:
                            success = await self._execute_escalation(escalation)
                            
                            if success:
                                escalation.status = EscalationStatus.ACTIVE
                                escalation.triggered_at = current_time
                            else:
                                escalation.status = EscalationStatus.FAILED
                                
                        except Exception as e:
                            self.logger.error(f"Failed to execute escalation {escalation_id}: {str(e)}")
                            escalation.status = EscalationStatus.FAILED
                            
                # Clean up old escalations
                await self._cleanup_completed_escalations()
                
                # Wait before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in escalation monitor loop: {str(e)}")
                await asyncio.sleep(60)
                
    async def _schedule_escalation_level(
        self,
        incident: IncidentTracker,
        rule: EscalationRule,
        level: EscalationLevel,
        delay_minutes: int
    ) -> Optional[EscalationEvent]:
        """Schedule escalation for specific level."""
        try:
            escalation_event = EscalationEvent(
                escalation_id=str(uuid.uuid4()),
                incident_id=incident.incident_id,
                trigger=EscalationTrigger.TIME_BASED,
                from_level=EscalationLevel.TEAM,  # Default from team
                to_level=level,
                scheduled_at=datetime.utcnow() + timedelta(minutes=delay_minutes),
                reason=f"Automatic escalation after {delay_minutes} minutes",
                business_justification=await self._create_business_justification(incident, level)
            )
            
            self.active_escalations[escalation_event.escalation_id] = escalation_event
            
            self.logger.info(f"Scheduled {level.name} escalation for incident {incident.incident_id} in {delay_minutes} minutes")
            return escalation_event
            
        except Exception as e:
            self.logger.error(f"Failed to schedule {level.name} escalation: {str(e)}")
            return None
            
    async def _execute_escalation(self, escalation: EscalationEvent) -> bool:
        """Execute escalation by sending notifications to appropriate stakeholders."""
        try:
            # Get escalation rule for context
            # Note: This is simplified - in production, we'd store rule reference with escalation
            rule = self.escalation_rules[0]  # Use default rule for now
            
            # Determine target stakeholders and channels
            stakeholders, channels = await self._get_escalation_targets(escalation.to_level, rule)
            
            if not stakeholders and not channels:
                self.logger.warning(f"No escalation targets found for level {escalation.to_level.name}")
                return False
                
            # Create escalation notification message
            escalation_message = await self._create_escalation_notification(escalation, stakeholders)
            
            # Send notifications to appropriate channels
            success = True
            for channel in channels:
                try:
                    # For now, we'll use a simplified approach
                    # In production, we'd create a proper SecurityEvent for escalation
                    await self.slack_client.update_incident_thread(
                        escalation.incident_id,
                        escalation_message,
                        "escalated"
                    )
                    
                except Exception as e:
                    self.logger.error(f"Failed to send escalation to {channel.value}: {str(e)}")
                    success = False
                    
            # Update escalation tracking
            escalation.notified_stakeholders.update([s.value for s in stakeholders])
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to execute escalation {escalation.escalation_id}: {str(e)}")
            return False
            
    async def _get_escalation_targets(
        self, 
        level: EscalationLevel, 
        rule: EscalationRule
    ) -> Tuple[List[StakeholderGroup], List[NotificationChannel]]:
        """Get stakeholder groups and channels for escalation level."""
        if level == EscalationLevel.TEAM:
            return rule.team_stakeholders, rule.team_channels
        elif level == EscalationLevel.LEADERSHIP:
            return rule.leadership_stakeholders, rule.leadership_channels
        elif level == EscalationLevel.EXECUTIVE:
            return rule.executive_stakeholders, rule.executive_channels
        elif level == EscalationLevel.CRISIS:
            return rule.crisis_stakeholders, rule.crisis_channels
        else:
            return [], []
            
    async def _create_escalation_notification(
        self, 
        escalation: EscalationEvent, 
        stakeholders: List[StakeholderGroup]
    ) -> str:
        """Create escalation notification message."""
        level_names = {
            EscalationLevel.TEAM: "Team",
            EscalationLevel.LEADERSHIP: "Leadership", 
            EscalationLevel.EXECUTIVE: "Executive",
            EscalationLevel.CRISIS: "Crisis Management"
        }
        
        level_name = level_names.get(escalation.to_level, "Unknown")
        
        message = f"🚨 **{level_name} Escalation**\n\n"
        message += f"**Incident:** {escalation.incident_id}\n"
        message += f"**Trigger:** {escalation.trigger.value.replace('_', ' ').title()}\n"
        message += f"**Reason:** {escalation.reason}\n"
        
        if escalation.business_justification:
            message += f"**Business Justification:** {escalation.business_justification}\n"
            
        # Add stakeholder mentions
        if stakeholders:
            mentions = " ".join([f"@{group.value}" for group in stakeholders])
            message += f"\n**Stakeholders:** {mentions}"
            
        return message
        
    async def _create_business_justification(
        self, 
        incident: IncidentTracker, 
        level: EscalationLevel
    ) -> str:
        """Create business justification for escalation."""
        justifications = {
            EscalationLevel.LEADERSHIP: f"Incident {incident.incident_id} requires leadership attention due to {incident.event.severity.value} severity",
            EscalationLevel.EXECUTIVE: f"Critical incident {incident.incident_id} requires executive notification for business impact assessment",
            EscalationLevel.CRISIS: f"Crisis-level incident {incident.incident_id} requires immediate executive coordination"
        }
        
        return justifications.get(level, f"Escalation to {level.name} required for incident {incident.incident_id}")
        
    async def _find_escalation_rule(
        self, 
        event: SecurityEvent, 
        business_impact: BusinessImpact
    ) -> Optional[EscalationRule]:
        """Find matching escalation rule for incident characteristics."""
        for rule in self.escalation_rules:
            if (event.severity in rule.severity_levels and 
                business_impact in rule.business_impact_levels and
                event.event_type in rule.event_types):
                return rule
                
        # Return default rule if no match
        return self.escalation_rules[-1] if self.escalation_rules else None
        
    async def _cleanup_completed_escalations(self):
        """Clean up escalations older than 24 hours."""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            completed_escalations = []
            for escalation_id, escalation in list(self.active_escalations.items()):
                if (escalation.status in [EscalationStatus.COMPLETED, EscalationStatus.FAILED] and
                    escalation.scheduled_at < cutoff_time):
                    completed_escalations.append(escalation_id)
                    
            for escalation_id in completed_escalations:
                del self.active_escalations[escalation_id]
                
            if completed_escalations:
                self.logger.info(f"Cleaned up {len(completed_escalations)} completed escalations")
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup completed escalations: {str(e)}")
            
    def _initialize_escalation_rules(self) -> List[EscalationRule]:
        """Initialize escalation rules for different incident types and business impacts."""
        return [
            # Critical incidents with immediate executive escalation
            EscalationRule(
                severity_levels=[EventSeverity.CRITICAL],
                business_impact_levels=[BusinessImpact.CRITICAL],
                event_types=list(EventType),
                team_response_timeout_minutes=15,
                leadership_response_timeout_minutes=30,
                executive_notification_hours=1,
                crisis_escalation_hours=2,
                team_stakeholders=[StakeholderGroup.SECURITY_TEAM],
                leadership_stakeholders=[StakeholderGroup.SECURITY_LEADERSHIP, StakeholderGroup.SECURITY_MANAGERS],
                executive_stakeholders=[StakeholderGroup.CISO, StakeholderGroup.EXECUTIVE_TEAM],
                crisis_stakeholders=[StakeholderGroup.EXECUTIVE_TEAM, StakeholderGroup.LEGAL_TEAM, StakeholderGroup.PR_TEAM],
                team_channels=[NotificationChannel.SECURITY_INCIDENTS],
                leadership_channels=[NotificationChannel.SECURITY_LEADERSHIP],
                executive_channels=[NotificationChannel.EXECUTIVE_SECURITY],
                crisis_channels=[NotificationChannel.INCIDENT_COMMAND],
                requires_war_room=True,
                requires_legal_notification=True,
                requires_pr_coordination=True
            ),
            
            # High-severity incidents with leadership escalation
            EscalationRule(
                severity_levels=[EventSeverity.HIGH],
                business_impact_levels=[BusinessImpact.HIGH, BusinessImpact.CRITICAL],
                event_types=list(EventType),
                team_response_timeout_minutes=30,
                leadership_response_timeout_minutes=60,
                executive_notification_hours=2,
                crisis_escalation_hours=4,
                team_stakeholders=[StakeholderGroup.SECURITY_TEAM, StakeholderGroup.SECURITY_ANALYSTS],
                leadership_stakeholders=[StakeholderGroup.SECURITY_LEADERSHIP],
                executive_stakeholders=[StakeholderGroup.CISO],
                team_channels=[NotificationChannel.SECURITY_INCIDENTS],
                leadership_channels=[NotificationChannel.SECURITY_LEADERSHIP],
                executive_channels=[NotificationChannel.EXECUTIVE_SECURITY],
                requires_war_room=True
            ),
            
            # Medium-severity standard escalation
            EscalationRule(
                severity_levels=[EventSeverity.MEDIUM],
                business_impact_levels=[BusinessImpact.MEDIUM, BusinessImpact.HIGH],
                event_types=list(EventType),
                team_response_timeout_minutes=60,
                leadership_response_timeout_minutes=120,
                executive_notification_hours=4,
                team_stakeholders=[StakeholderGroup.SECURITY_TEAM],
                leadership_stakeholders=[StakeholderGroup.SECURITY_LEADERSHIP],
                team_channels=[NotificationChannel.SECURITY_ALERTS],
                leadership_channels=[NotificationChannel.SECURITY_LEADERSHIP]
            ),
            
            # Default escalation rule
            EscalationRule(
                severity_levels=list(EventSeverity),
                business_impact_levels=list(BusinessImpact),
                event_types=list(EventType),
                team_response_timeout_minutes=120,
                leadership_response_timeout_minutes=240,
                executive_notification_hours=8,
                team_stakeholders=[StakeholderGroup.SECURITY_TEAM],
                leadership_stakeholders=[StakeholderGroup.SECURITY_LEADERSHIP],
                team_channels=[NotificationChannel.SECURITY_ALERTS],
                leadership_channels=[NotificationChannel.SECURITY_LEADERSHIP]
            )
        ]