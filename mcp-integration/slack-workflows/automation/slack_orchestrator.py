"""
Slack Workflow Orchestrator for SecurityAgents Platform

Main coordination engine integrating Slack MCP server with Alpha-2's enterprise 
gateway infrastructure for real-time security incident management workflows.

P0 Deliverable for SecurityAgents Phase 2C Slack Integration
Author: Tiger Team Alpha-3 Slack Workflows Specialist  
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import traceback

# Import Alpha-2's gateway infrastructure
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from gateway.enterprise_mcp_gateway import (
    EnterpriseMCPGateway, SecurityEvent, EventSeverity, EventType,
    OrchestrationStrategy, SecurityEventHandler
)

# Import our Slack workflow components
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from slack_mcp_client import SlackMCPClient, SlackConfig, SlackRateLimit, create_slack_config
from notifications.incident_manager import (
    SecurityIncidentManager, IncidentTracker, BusinessImpact, 
    BusinessContext, BusinessImpactAssessor
)
from escalation.escalation_engine import (
    EscalationEngine, EscalationLevel, EscalationTrigger, EscalationEvent
)


class SlackWorkflowStatus(Enum):
    """Status of Slack workflow processes."""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    DEGRADED = "degraded"     # Partial functionality
    FAILED = "failed"         # Service unavailable
    MAINTENANCE = "maintenance"


class SlackIntegrationHealth(Enum):
    """Health status of Slack integration components."""
    HEALTHY = "healthy"
    WARNING = "warning"       # Performance issues
    CRITICAL = "critical"     # Service disruption
    UNKNOWN = "unknown"       # Health check failed


@dataclass
class SlackMetrics:
    """Performance metrics for Slack workflow automation."""
    # Notification metrics
    total_notifications_sent: int = 0
    notification_success_rate: float = 0.0
    average_notification_latency_ms: float = 0.0
    
    # Escalation metrics  
    total_escalations_triggered: int = 0
    escalation_acknowledgment_rate: float = 0.0
    average_escalation_response_time_minutes: float = 0.0
    
    # Thread and collaboration metrics
    active_incident_threads: int = 0
    canvas_documents_created: int = 0
    thread_engagement_rate: float = 0.0
    
    # Rate limiting and performance
    api_calls_per_minute: float = 0.0
    rate_limit_violations: int = 0
    circuit_breaker_trips: int = 0
    
    # Business impact metrics
    incidents_by_severity: Dict[str, int] = field(default_factory=dict)
    mean_time_to_notification_seconds: float = 0.0
    executive_escalation_frequency: float = 0.0
    

@dataclass 
class SlackWorkflowConfiguration:
    """Configuration for Slack workflow automation."""
    # Slack MCP configuration
    slack_config: SlackConfig
    
    # Workflow behavior
    enable_auto_escalation: bool = True
    enable_executive_notifications: bool = True
    enable_war_room_creation: bool = True
    enable_compliance_logging: bool = True
    
    # Performance tuning
    max_concurrent_notifications: int = 50
    notification_timeout_seconds: int = 30
    thread_update_batch_size: int = 10
    
    # Business rules
    business_hours_start: int = 8    # 8 AM
    business_hours_end: int = 18     # 6 PM
    weekend_escalation_threshold: EventSeverity = EventSeverity.HIGH
    
    # Integration settings
    jira_integration_enabled: bool = False
    tines_integration_enabled: bool = False
    canvas_auto_creation: bool = True


class SlackWorkflowOrchestrator:
    """
    Main Slack workflow orchestrator for SecurityAgents platform.
    
    Integrates with Alpha-2's enterprise MCP gateway to provide real-time
    security incident management through Slack workflows, escalation automation,
    and team collaboration features.
    """
    
    def __init__(
        self, 
        gateway: EnterpriseMCPGateway,
        config: SlackWorkflowConfiguration
    ):
        self.gateway = gateway
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.SlackWorkflowOrchestrator")
        
        # Initialize Slack components
        self.slack_client = SlackMCPClient(config.slack_config)
        self.incident_manager = SecurityIncidentManager(self.slack_client)
        self.escalation_engine = EscalationEngine(self.slack_client)
        
        # Status and metrics
        self.status = SlackWorkflowStatus.INITIALIZING
        self.health = SlackIntegrationHealth.UNKNOWN
        self.metrics = SlackMetrics()
        self.last_health_check = datetime.utcnow()
        
        # Event processing
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.event_processors: List[asyncio.Task] = []
        self.is_processing = False
        
        # Rate limiting and circuit breaker
        self.circuit_breaker_state = "closed"  # closed, open, half-open
        self.circuit_breaker_failures = 0
        self.circuit_breaker_last_failure = None
        
        # Integration tracking
        self.active_incidents: Dict[str, IncidentTracker] = {}
        self.webhook_handlers: Dict[str, Callable] = {}
        
    async def initialize(self) -> bool:
        """
        Initialize Slack workflow orchestrator and integrate with Alpha-2 gateway.
        
        Returns:
            bool indicating successful initialization
        """
        try:
            self.logger.info("Initializing Slack workflow orchestrator")
            
            # Authenticate Slack MCP client
            auth_info = await self.slack_client.authenticate_oauth2()
            if not auth_info:
                raise Exception("Failed to authenticate Slack MCP client")
                
            self.logger.info(f"Slack authentication successful for workspace {auth_info.get('team')}")
            
            # Register with Alpha-2 gateway as security event handler
            await self._register_with_gateway()
            
            # Start escalation engine monitoring
            await self.escalation_engine.start_monitoring()
            
            # Start event processing
            await self._start_event_processing()
            
            # Perform initial health check
            await self._perform_health_check()
            
            self.status = SlackWorkflowStatus.ACTIVE
            self.logger.info("Slack workflow orchestrator initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Slack workflow orchestrator: {str(e)}")
            self.status = SlackWorkflowStatus.FAILED
            return False
            
    async def shutdown(self):
        """Shutdown Slack workflow orchestrator gracefully."""
        try:
            self.logger.info("Shutting down Slack workflow orchestrator")
            
            self.status = SlackWorkflowStatus.MAINTENANCE
            self.is_processing = False
            
            # Stop event processing
            for processor in self.event_processors:
                processor.cancel()
                
            await asyncio.gather(*self.event_processors, return_exceptions=True)
            
            # Stop escalation monitoring
            await self.escalation_engine.stop_monitoring()
            
            # Close Slack client
            await self.slack_client.close()
            
            self.logger.info("Slack workflow orchestrator shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {str(e)}")
            
    async def process_security_event(
        self, 
        event: SecurityEvent,
        business_context: Optional[BusinessContext] = None
    ) -> Dict[str, Any]:
        """
        Process security event through Slack workflow automation.
        
        Args:
            event: SecurityEvent from Alpha-2 gateway
            business_context: Optional business context for impact assessment
            
        Returns:
            Dict containing processing results and correlation IDs
        """
        try:
            # Circuit breaker check
            if not await self._check_circuit_breaker():
                self.logger.warning(f"Circuit breaker open, queuing event {event.event_id}")
                await self.event_queue.put((event, business_context))
                return {"status": "queued", "reason": "circuit_breaker_open"}
                
            start_time = datetime.utcnow()
            
            # Process incident through incident manager
            incident = await self.incident_manager.process_security_incident(
                event, business_context
            )
            
            # Store incident reference
            self.active_incidents[event.event_id] = incident
            
            # Assess business impact for escalation scheduling
            business_impact = await BusinessImpactAssessor().assess_impact(
                event, incident.business_context
            )
            
            # Schedule escalations based on rules
            escalations = await self.escalation_engine.schedule_incident_escalation(
                incident, business_impact
            )
            
            # Calculate processing metrics
            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            self._update_processing_metrics(processing_time, True)
            
            result = {
                "status": "processed",
                "incident_id": incident.incident_id,
                "slack_thread_ts": incident.slack_thread.thread_ts if incident.slack_thread else None,
                "canvas_id": incident.canvas_id,
                "business_impact": business_impact.value,
                "escalations_scheduled": len(escalations),
                "processing_time_ms": processing_time,
                "correlation_id": event.correlation_id
            }
            
            self.logger.info(f"Security event processed: {event.event_id} with {business_impact.value} impact")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to process security event {event.event_id}: {str(e)}")
            self._update_processing_metrics(0, False)
            self._handle_circuit_breaker_failure()
            return {"status": "failed", "error": str(e)}
            
    async def handle_slack_interaction(
        self, 
        interaction_type: str,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle interactive Slack events (button clicks, approvals, etc.).
        
        Args:
            interaction_type: Type of interaction (button_click, approval, etc.)
            payload: Interaction payload data
            
        Returns:
            Dict containing response data for Slack
        """
        try:
            # Extract incident ID from interaction
            incident_id = self._extract_incident_id_from_payload(payload)
            if not incident_id:
                return {"error": "Cannot identify incident from interaction"}
                
            # Route interaction to appropriate handler
            if interaction_type == "acknowledge_incident":
                return await self._handle_incident_acknowledgment(incident_id, payload)
            elif interaction_type == "escalate_incident":
                return await self._handle_manual_escalation(incident_id, payload)
            elif interaction_type == "create_war_room":
                return await self._handle_war_room_creation(incident_id, payload)
            elif interaction_type == "update_status":
                return await self._handle_status_update(incident_id, payload)
            else:
                self.logger.warning(f"Unknown interaction type: {interaction_type}")
                return {"error": f"Unknown interaction type: {interaction_type}"}
                
        except Exception as e:
            self.logger.error(f"Failed to handle Slack interaction: {str(e)}")
            return {"error": str(e)}
            
    async def get_incident_status(self, incident_id: str) -> Dict[str, Any]:
        """Get comprehensive incident status including Slack workflow state."""
        try:
            incident = self.active_incidents.get(incident_id)
            if not incident:
                return {"error": "Incident not found"}
                
            # Get escalation status
            escalation_status = await self.escalation_engine.get_escalation_status(incident_id)
            
            # Get thread and canvas status
            thread_status = {
                "channel": incident.slack_thread.channel if incident.slack_thread else None,
                "thread_ts": incident.slack_thread.thread_ts if incident.slack_thread else None,
                "canvas_id": incident.canvas_id,
                "jira_ticket": incident.jira_ticket
            }
            
            # Calculate timeline metrics
            timeline = self._calculate_incident_timeline(incident)
            
            return {
                "incident_id": incident_id,
                "status": incident.status,
                "severity": incident.event.severity.value,
                "business_impact": incident.business_context.asset_criticality,
                "assigned_analyst": incident.assigned_analyst,
                "thread_status": thread_status,
                "escalation_status": escalation_status,
                "timeline": timeline,
                "response_actions": incident.response_actions,
                "evidence_collected": incident.evidence_collected,
                "last_updated": incident.status_updates[-1] if incident.status_updates else None
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get incident status {incident_id}: {str(e)}")
            return {"error": str(e)}
            
    async def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status of Slack workflow automation."""
        try:
            # Perform health check if stale
            if datetime.utcnow() - self.last_health_check > timedelta(minutes=5):
                await self._perform_health_check()
                
            return {
                "status": self.status.value,
                "health": self.health.value,
                "metrics": {
                    "notifications_sent": self.metrics.total_notifications_sent,
                    "success_rate": self.metrics.notification_success_rate,
                    "avg_latency_ms": self.metrics.average_notification_latency_ms,
                    "active_threads": self.metrics.active_incident_threads,
                    "escalations_triggered": self.metrics.total_escalations_triggered,
                    "api_calls_per_minute": self.metrics.api_calls_per_minute,
                    "rate_limit_violations": self.metrics.rate_limit_violations
                },
                "circuit_breaker": {
                    "state": self.circuit_breaker_state,
                    "failures": self.circuit_breaker_failures
                },
                "active_incidents": len(self.active_incidents),
                "last_health_check": self.last_health_check.isoformat(),
                "integration_status": {
                    "slack_authenticated": True,  # If we got this far
                    "escalation_monitoring": self.escalation_engine.is_monitoring,
                    "event_processing": self.is_processing
                }
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get health status: {str(e)}")
            return {"error": str(e)}
            
    async def _register_with_gateway(self):
        """Register as security event handler with Alpha-2 gateway."""
        try:
            # Create event handler for Slack workflow processing
            slack_handler = SecurityEventHandler(
                handler_id="slack_workflows",
                name="Slack Workflow Orchestrator",
                event_types=list(EventType),
                severity_levels=list(EventSeverity),
                handler_function=self.process_security_event,
                priority=100  # High priority for user notifications
            )
            
            # Register with gateway
            await self.gateway.register_event_handler(slack_handler)
            
            self.logger.info("Registered with Alpha-2 gateway as security event handler")
            
        except Exception as e:
            self.logger.error(f"Failed to register with gateway: {str(e)}")
            raise
            
    async def _start_event_processing(self):
        """Start background event processing tasks."""
        try:
            self.is_processing = True
            
            # Start multiple event processors for parallel processing
            for i in range(self.config.max_concurrent_notifications):
                processor = asyncio.create_task(self._event_processor_loop(f"processor-{i}"))
                self.event_processors.append(processor)
                
            self.logger.info(f"Started {len(self.event_processors)} event processors")
            
        except Exception as e:
            self.logger.error(f"Failed to start event processing: {str(e)}")
            raise
            
    async def _event_processor_loop(self, processor_name: str):
        """Background event processing loop."""
        while self.is_processing:
            try:
                # Get event from queue with timeout
                try:
                    event, business_context = await asyncio.wait_for(
                        self.event_queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                    
                # Process event
                await self.process_security_event(event, business_context)
                self.event_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error in event processor {processor_name}: {str(e)}")
                await asyncio.sleep(1)
                
    async def _check_circuit_breaker(self) -> bool:
        """Check circuit breaker state for fault tolerance."""
        if self.circuit_breaker_state == "closed":
            return True
        elif self.circuit_breaker_state == "open":
            # Check if we should transition to half-open
            if (self.circuit_breaker_last_failure and 
                datetime.utcnow() - self.circuit_breaker_last_failure > timedelta(minutes=5)):
                self.circuit_breaker_state = "half-open"
                self.logger.info("Circuit breaker transitioning to half-open")
                return True
            return False
        elif self.circuit_breaker_state == "half-open":
            return True
        return False
        
    def _handle_circuit_breaker_failure(self):
        """Handle circuit breaker failure condition."""
        self.circuit_breaker_failures += 1
        self.circuit_breaker_last_failure = datetime.utcnow()
        
        if self.circuit_breaker_failures >= 5:  # Threshold
            self.circuit_breaker_state = "open"
            self.logger.warning("Circuit breaker opened due to failures")
        elif self.circuit_breaker_state == "half-open":
            self.circuit_breaker_state = "open"
            self.logger.warning("Circuit breaker re-opened from half-open state")
            
    def _update_processing_metrics(self, processing_time_ms: float, success: bool):
        """Update processing performance metrics."""
        if success:
            self.metrics.total_notifications_sent += 1
            
            # Update success rate (rolling average)
            total_attempts = self.metrics.total_notifications_sent + self.circuit_breaker_failures
            self.metrics.notification_success_rate = self.metrics.total_notifications_sent / total_attempts
            
            # Update latency (rolling average)
            if self.metrics.average_notification_latency_ms == 0:
                self.metrics.average_notification_latency_ms = processing_time_ms
            else:
                self.metrics.average_notification_latency_ms = (
                    (self.metrics.average_notification_latency_ms * 0.9) + 
                    (processing_time_ms * 0.1)
                )
                
            # Reset circuit breaker on success
            if self.circuit_breaker_state == "half-open":
                self.circuit_breaker_state = "closed"
                self.circuit_breaker_failures = 0
                self.logger.info("Circuit breaker closed after successful operation")
                
    async def _perform_health_check(self):
        """Perform comprehensive health check of Slack integration.""" 
        try:
            health_issues = []
            
            # Test Slack API connectivity
            try:
                await self.slack_client._api_call("auth.test")
            except Exception as e:
                health_issues.append(f"Slack API connectivity: {str(e)}")
                
            # Check escalation engine status
            if not self.escalation_engine.is_monitoring:
                health_issues.append("Escalation engine not monitoring")
                
            # Check event processing
            if not self.is_processing:
                health_issues.append("Event processing not active")
                
            # Check circuit breaker state
            if self.circuit_breaker_state == "open":
                health_issues.append("Circuit breaker open")
                
            # Check performance metrics
            if self.metrics.notification_success_rate < 0.95:
                health_issues.append(f"Low success rate: {self.metrics.notification_success_rate:.2%}")
                
            if self.metrics.average_notification_latency_ms > 5000:  # 5 seconds
                health_issues.append(f"High latency: {self.metrics.average_notification_latency_ms:.0f}ms")
                
            # Determine health status
            if not health_issues:
                self.health = SlackIntegrationHealth.HEALTHY
            elif len(health_issues) <= 2:
                self.health = SlackIntegrationHealth.WARNING
            else:
                self.health = SlackIntegrationHealth.CRITICAL
                
            self.last_health_check = datetime.utcnow()
            
            if health_issues:
                self.logger.warning(f"Health check issues: {', '.join(health_issues)}")
            else:
                self.logger.debug("Health check passed")
                
        except Exception as e:
            self.logger.error(f"Health check failed: {str(e)}")
            self.health = SlackIntegrationHealth.UNKNOWN
            
    async def _handle_incident_acknowledgment(
        self, 
        incident_id: str, 
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle incident acknowledgment button click."""
        try:
            user_id = payload.get("user", {}).get("id")
            if not user_id:
                return {"error": "Cannot identify user"}
                
            # Update incident status
            success = await self.incident_manager.update_incident_status(
                incident_id,
                "acknowledged",
                f"Incident acknowledged by <@{user_id}>",
                user_id
            )
            
            if success:
                return {"text": "✅ Incident acknowledged"}
            else:
                return {"error": "Failed to acknowledge incident"}
                
        except Exception as e:
            self.logger.error(f"Failed to handle acknowledgment: {str(e)}")
            return {"error": str(e)}
            
    async def _handle_manual_escalation(
        self, 
        incident_id: str, 
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle manual escalation button click."""
        try:
            user_id = payload.get("user", {}).get("id")
            reason = "Manual escalation requested"
            
            success = await self.escalation_engine.execute_manual_escalation(
                incident_id,
                EscalationLevel.LEADERSHIP,
                reason,
                user_id
            )
            
            if success:
                return {"text": "⬆️ Incident escalated to leadership"}
            else:
                return {"error": "Failed to escalate incident"}
                
        except Exception as e:
            self.logger.error(f"Failed to handle escalation: {str(e)}")
            return {"error": str(e)}
            
    async def _handle_war_room_creation(
        self, 
        incident_id: str, 
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle war room creation button click."""
        try:
            incident = self.active_incidents.get(incident_id)
            if not incident:
                return {"error": "Incident not found"}
                
            if incident.canvas_id:
                return {"text": "📄 War room canvas already exists"}
                
            canvas_title = f"Incident War Room - {incident_id}"
            canvas_content = {
                "incident_id": incident_id,
                "severity": incident.event.severity.value,
                "start_time": incident.created_at.isoformat()
            }
            
            canvas_id = await self.slack_client.create_incident_canvas(
                incident_id, canvas_title, canvas_content
            )
            
            if canvas_id:
                return {"text": f"📄 War room canvas created: {canvas_title}"}
            else:
                return {"error": "Failed to create war room canvas"}
                
        except Exception as e:
            self.logger.error(f"Failed to create war room: {str(e)}")
            return {"error": str(e)}
            
    async def _handle_status_update(
        self, 
        incident_id: str, 
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle status update interaction."""
        # TODO: Implement status update modal handling
        return {"text": "Status update functionality coming soon"}
        
    def _extract_incident_id_from_payload(self, payload: Dict[str, Any]) -> Optional[str]:
        """Extract incident ID from Slack interaction payload."""
        try:
            # Look for incident ID in action ID
            actions = payload.get("actions", [])
            for action in actions:
                action_id = action.get("action_id", "")
                if "_" in action_id:
                    parts = action_id.split("_")
                    if len(parts) >= 2:
                        return parts[1]  # Extract incident ID
                        
            return None
            
        except Exception:
            return None
            
    def _calculate_incident_timeline(self, incident: IncidentTracker) -> Dict[str, Any]:
        """Calculate incident timeline metrics."""
        timeline = {
            "created_at": incident.created_at.isoformat(),
            "first_notification_at": incident.first_notification_at.isoformat() if incident.first_notification_at else None,
            "acknowledged_at": incident.acknowledged_at.isoformat() if incident.acknowledged_at else None,
            "escalated_at": incident.escalated_at.isoformat() if incident.escalated_at else None,
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None
        }
        
        # Calculate durations
        now = datetime.utcnow()
        timeline["total_duration_minutes"] = (
            (incident.resolved_at or now) - incident.created_at
        ).total_seconds() / 60
        
        if incident.first_notification_at:
            timeline["time_to_notification_seconds"] = (
                incident.first_notification_at - incident.created_at
            ).total_seconds()
            
        if incident.acknowledged_at:
            timeline["time_to_acknowledgment_minutes"] = (
                incident.acknowledged_at - incident.created_at
            ).total_seconds() / 60
            
        return timeline


# Factory functions for creating orchestrator

async def create_slack_orchestrator(
    gateway: EnterpriseMCPGateway,
    slack_client_id: str,
    slack_client_secret: str, 
    slack_bot_token: str,
    slack_workspace_id: str,
    rate_limit_tier: SlackRateLimit = SlackRateLimit.TIER_3
) -> SlackWorkflowOrchestrator:
    """
    Create and initialize Slack workflow orchestrator.
    
    Args:
        gateway: Alpha-2's enterprise MCP gateway instance
        slack_client_id: Slack app client ID
        slack_client_secret: Slack app client secret
        slack_bot_token: Slack bot token
        slack_workspace_id: Target workspace ID
        rate_limit_tier: Slack API rate limit tier
        
    Returns:
        Initialized SlackWorkflowOrchestrator
    """
    # Create Slack configuration
    slack_config = create_slack_config(
        slack_client_id,
        slack_client_secret,
        slack_bot_token,
        slack_workspace_id,
        rate_limit_tier
    )
    
    # Create workflow configuration
    workflow_config = SlackWorkflowConfiguration(
        slack_config=slack_config,
        enable_auto_escalation=True,
        enable_executive_notifications=True,
        enable_war_room_creation=True,
        enable_compliance_logging=True
    )
    
    # Create orchestrator
    orchestrator = SlackWorkflowOrchestrator(gateway, workflow_config)
    
    # Initialize
    success = await orchestrator.initialize()
    if not success:
        raise Exception("Failed to initialize Slack workflow orchestrator")
        
    return orchestrator