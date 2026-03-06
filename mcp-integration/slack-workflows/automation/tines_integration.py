"""
Tines Workflow Integration for SecurityAgents Platform

Advanced workflow orchestration integration with Tines for complex incident 
response automation, executive reporting, and compliance evidence generation.

P0 Deliverable for SecurityAgents Phase 2C Slack Integration
Author: Tiger Team Alpha-3 Slack Workflows Specialist
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import traceback
import httpx

# Import Alpha-2's gateway infrastructure and our components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from gateway.enterprise_mcp_gateway import SecurityEvent, EventSeverity, EventType
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from notifications.incident_manager import IncidentTracker, BusinessImpact, BusinessContext


class TinesWorkflowType(Enum):
    """Types of Tines workflows for security automation."""
    INCIDENT_RESPONSE = "incident_response"
    THREAT_HUNTING = "threat_hunting"
    COMPLIANCE_CHECK = "compliance_check"
    EXECUTIVE_REPORTING = "executive_reporting"
    EVIDENCE_COLLECTION = "evidence_collection"
    STAKEHOLDER_NOTIFICATION = "stakeholder_notification"
    REMEDIATION_AUTOMATION = "remediation_automation"
    RISK_ASSESSMENT = "risk_assessment"


class TinesWorkflowStatus(Enum):
    """Status of Tines workflow executions."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class TinesWorkflowConfig:
    """Configuration for Tines workflow integration."""
    # Tines tenant configuration
    tenant_url: str
    api_token: str
    webhook_secret: str
    
    # Workflow settings
    default_timeout_minutes: int = 30
    max_concurrent_workflows: int = 50
    retry_attempts: int = 3
    
    # Enterprise security
    enable_audit_logging: bool = True
    require_approval_for_destructive: bool = True
    
    # Performance settings
    batch_size: int = 10
    rate_limit_per_minute: int = 100


@dataclass
class TinesWorkflowExecution:
    """Tracking for individual Tines workflow execution."""
    execution_id: str
    workflow_type: TinesWorkflowType
    incident_id: str
    
    # Tines execution data
    story_id: Optional[str] = None
    story_run_id: Optional[str] = None
    
    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    
    # Status and results
    status: TinesWorkflowStatus = TinesWorkflowStatus.PENDING
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    
    # Integration tracking
    slack_thread_ts: Optional[str] = None
    jira_ticket: Optional[str] = None
    evidence_artifacts: List[str] = field(default_factory=list)


class TinesIntegration:
    """
    Tines workflow integration for advanced security automation.
    
    Provides integration with Tines platform for complex multi-step incident
    response workflows, executive reporting automation, and compliance evidence
    generation beyond basic Slack notifications.
    """
    
    def __init__(self, config: TinesWorkflowConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.TinesIntegration")
        
        # HTTP client for Tines API
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            headers={
                "Authorization": f"Bearer {config.api_token}",
                "Content-Type": "application/json",
                "User-Agent": "SecurityAgents-TinesIntegration/1.0"
            }
        )
        
        # Execution tracking
        self.active_executions: Dict[str, TinesWorkflowExecution] = {}
        self.execution_history: List[TinesWorkflowExecution] = []
        
        # Workflow definitions (loaded from Tines tenant)
        self.workflow_definitions: Dict[TinesWorkflowType, Dict[str, Any]] = {}
        
        # Rate limiting
        self.api_calls_per_minute = 0
        self.last_rate_limit_reset = datetime.utcnow()
        
    async def initialize(self) -> bool:
        """
        Initialize Tines integration and load workflow definitions.
        
        Returns:
            bool indicating successful initialization
        """
        try:
            self.logger.info("Initializing Tines integration")
            
            # Test Tines API connectivity
            await self._test_connectivity()
            
            # Load workflow definitions from Tines tenant
            await self._load_workflow_definitions()
            
            self.logger.info("Tines integration initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Tines integration: {str(e)}")
            return False
            
    async def execute_incident_response_workflow(
        self, 
        incident: IncidentTracker,
        business_impact: BusinessImpact,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> TinesWorkflowExecution:
        """
        Execute comprehensive incident response workflow in Tines.
        
        Args:
            incident: IncidentTracker with incident details
            business_impact: Business impact classification
            additional_context: Additional context for workflow
            
        Returns:
            TinesWorkflowExecution tracking workflow progress
        """
        try:
            # Prepare workflow input data
            input_data = await self._prepare_incident_response_input(
                incident, business_impact, additional_context
            )
            
            # Create execution tracking
            execution = TinesWorkflowExecution(
                execution_id=str(uuid.uuid4()),
                workflow_type=TinesWorkflowType.INCIDENT_RESPONSE,
                incident_id=incident.incident_id,
                input_data=input_data,
                slack_thread_ts=incident.slack_thread.thread_ts if incident.slack_thread else None
            )
            
            # Execute workflow
            success = await self._execute_workflow(execution)
            
            if success:
                self.active_executions[execution.execution_id] = execution
                self.logger.info(f"Started incident response workflow for {incident.incident_id}")
            else:
                execution.status = TinesWorkflowStatus.FAILED
                execution.error_message = "Failed to start workflow"
                
            return execution
            
        except Exception as e:
            self.logger.error(f"Failed to execute incident response workflow: {str(e)}")
            execution = TinesWorkflowExecution(
                execution_id=str(uuid.uuid4()),
                workflow_type=TinesWorkflowType.INCIDENT_RESPONSE,
                incident_id=incident.incident_id,
                status=TinesWorkflowStatus.FAILED,
                error_message=str(e)
            )
            return execution
            
    async def execute_executive_reporting_workflow(
        self, 
        time_period: str = "weekly",
        include_incidents: List[str] = None,
        custom_metrics: Dict[str, Any] = None
    ) -> TinesWorkflowExecution:
        """
        Execute executive security reporting workflow.
        
        Args:
            time_period: Reporting period (daily, weekly, monthly)
            include_incidents: Specific incident IDs to include
            custom_metrics: Additional metrics to include
            
        Returns:
            TinesWorkflowExecution tracking report generation
        """
        try:
            # Prepare reporting input data
            input_data = {
                "reporting_period": time_period,
                "start_date": self._calculate_period_start(time_period).isoformat(),
                "end_date": datetime.utcnow().isoformat(),
                "include_incidents": include_incidents or [],
                "custom_metrics": custom_metrics or {},
                "report_type": "executive_summary",
                "delivery_channels": ["slack", "email"],  # TODO: Configure
                "stakeholders": ["ciso", "executive_team"]  # TODO: Configure
            }
            
            execution = TinesWorkflowExecution(
                execution_id=str(uuid.uuid4()),
                workflow_type=TinesWorkflowType.EXECUTIVE_REPORTING,
                incident_id="executive_report",  # Special identifier
                input_data=input_data
            )
            
            success = await self._execute_workflow(execution)
            
            if success:
                self.active_executions[execution.execution_id] = execution
                self.logger.info(f"Started executive reporting workflow for {time_period}")
            else:
                execution.status = TinesWorkflowStatus.FAILED
                
            return execution
            
        except Exception as e:
            self.logger.error(f"Failed to execute executive reporting workflow: {str(e)}")
            return TinesWorkflowExecution(
                execution_id=str(uuid.uuid4()),
                workflow_type=TinesWorkflowType.EXECUTIVE_REPORTING,
                incident_id="executive_report",
                status=TinesWorkflowStatus.FAILED,
                error_message=str(e)
            )
            
    async def execute_compliance_evidence_workflow(
        self, 
        incident_id: str,
        compliance_frameworks: List[str],
        evidence_types: List[str]
    ) -> TinesWorkflowExecution:
        """
        Execute compliance evidence collection workflow.
        
        Args:
            incident_id: Incident requiring compliance evidence
            compliance_frameworks: Applicable frameworks (NIST, ISO, etc.)
            evidence_types: Types of evidence to collect
            
        Returns:
            TinesWorkflowExecution tracking evidence collection
        """
        try:
            input_data = {
                "incident_id": incident_id,
                "compliance_frameworks": compliance_frameworks,
                "evidence_types": evidence_types,
                "collection_timestamp": datetime.utcnow().isoformat(),
                "retention_policy": "7_years",  # TODO: Configure
                "encryption_required": True
            }
            
            execution = TinesWorkflowExecution(
                execution_id=str(uuid.uuid4()),
                workflow_type=TinesWorkflowType.EVIDENCE_COLLECTION,
                incident_id=incident_id,
                input_data=input_data
            )
            
            success = await self._execute_workflow(execution)
            
            if success:
                self.active_executions[execution.execution_id] = execution
                self.logger.info(f"Started compliance evidence workflow for {incident_id}")
            else:
                execution.status = TinesWorkflowStatus.FAILED
                
            return execution
            
        except Exception as e:
            self.logger.error(f"Failed to execute compliance evidence workflow: {str(e)}")
            return TinesWorkflowExecution(
                execution_id=str(uuid.uuid4()),
                workflow_type=TinesWorkflowType.EVIDENCE_COLLECTION,
                incident_id=incident_id,
                status=TinesWorkflowStatus.FAILED,
                error_message=str(e)
            )
            
    async def get_execution_status(self, execution_id: str) -> Optional[TinesWorkflowExecution]:
        """Get current status of Tines workflow execution."""
        try:
            execution = self.active_executions.get(execution_id)
            if not execution:
                return None
                
            # Query Tines for current status if workflow is running
            if (execution.status in [TinesWorkflowStatus.PENDING, TinesWorkflowStatus.RUNNING] and
                execution.story_run_id):
                await self._update_execution_status(execution)
                
            return execution
            
        except Exception as e:
            self.logger.error(f"Failed to get execution status {execution_id}: {str(e)}")
            return None
            
    async def cancel_workflow(self, execution_id: str) -> bool:
        """Cancel running Tines workflow."""
        try:
            execution = self.active_executions.get(execution_id)
            if not execution:
                self.logger.warning(f"Execution not found: {execution_id}")
                return False
                
            if execution.story_run_id:
                # TODO: Implement Tines workflow cancellation API call
                self.logger.info(f"Cancelling Tines workflow {execution.story_run_id}")
                
            execution.status = TinesWorkflowStatus.CANCELLED
            execution.completed_at = datetime.utcnow()
            
            # Remove from active executions
            del self.active_executions[execution_id]
            self.execution_history.append(execution)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to cancel workflow {execution_id}: {str(e)}")
            return False
            
    async def get_workflow_metrics(self) -> Dict[str, Any]:
        """Get Tines workflow execution metrics."""
        try:
            active_count = len(self.active_executions)
            completed_count = len(self.execution_history)
            
            # Calculate success rate
            successful_executions = len([
                ex for ex in self.execution_history 
                if ex.status == TinesWorkflowStatus.SUCCESS
            ])
            
            success_rate = (
                successful_executions / completed_count if completed_count > 0 else 0.0
            )
            
            # Calculate average execution time
            completed_executions = [
                ex for ex in self.execution_history 
                if ex.completed_at and ex.status == TinesWorkflowStatus.SUCCESS
            ]
            
            avg_execution_time = 0.0
            if completed_executions:
                total_time = sum([
                    (ex.completed_at - ex.started_at).total_seconds()
                    for ex in completed_executions
                ])
                avg_execution_time = total_time / len(completed_executions)
                
            # Workflow type distribution
            workflow_types = {}
            for execution in self.execution_history + list(self.active_executions.values()):
                wf_type = execution.workflow_type.value
                workflow_types[wf_type] = workflow_types.get(wf_type, 0) + 1
                
            return {
                "active_workflows": active_count,
                "completed_workflows": completed_count,
                "success_rate": success_rate,
                "average_execution_time_seconds": avg_execution_time,
                "workflow_type_distribution": workflow_types,
                "api_calls_per_minute": self.api_calls_per_minute,
                "last_rate_limit_reset": self.last_rate_limit_reset.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get workflow metrics: {str(e)}")
            return {"error": str(e)}
            
    async def _test_connectivity(self):
        """Test Tines API connectivity and authentication."""
        try:
            response = await self._api_call("GET", "/api/v1/tenant")
            
            if response.status_code != 200:
                raise Exception(f"Tines API test failed: {response.status_code}")
                
            tenant_info = response.json()
            self.logger.info(f"Connected to Tines tenant: {tenant_info.get('name', 'Unknown')}")
            
        except Exception as e:
            self.logger.error(f"Tines connectivity test failed: {str(e)}")
            raise
            
    async def _load_workflow_definitions(self):
        """Load workflow definitions from Tines tenant."""
        try:
            # TODO: Load actual workflow definitions from Tines
            # For now, use placeholder definitions
            self.workflow_definitions = {
                TinesWorkflowType.INCIDENT_RESPONSE: {
                    "story_id": "incident_response_story",
                    "webhook_url": f"{self.config.tenant_url}/webhook/incident_response"
                },
                TinesWorkflowType.EXECUTIVE_REPORTING: {
                    "story_id": "executive_reporting_story", 
                    "webhook_url": f"{self.config.tenant_url}/webhook/executive_reporting"
                },
                TinesWorkflowType.EVIDENCE_COLLECTION: {
                    "story_id": "evidence_collection_story",
                    "webhook_url": f"{self.config.tenant_url}/webhook/evidence_collection"
                }
            }
            
            self.logger.info(f"Loaded {len(self.workflow_definitions)} workflow definitions")
            
        except Exception as e:
            self.logger.error(f"Failed to load workflow definitions: {str(e)}")
            raise
            
    async def _execute_workflow(self, execution: TinesWorkflowExecution) -> bool:
        """Execute Tines workflow via webhook or API."""
        try:
            workflow_def = self.workflow_definitions.get(execution.workflow_type)
            if not workflow_def:
                raise Exception(f"No workflow definition for {execution.workflow_type.value}")
                
            # Rate limiting check
            await self._check_rate_limit()
            
            # Execute via webhook (preferred method)
            webhook_url = workflow_def.get("webhook_url")
            if webhook_url:
                response = await self._trigger_webhook(webhook_url, execution.input_data)
                
                if response.status_code == 200:
                    execution.status = TinesWorkflowStatus.RUNNING
                    execution.story_id = workflow_def.get("story_id")
                    # TODO: Extract story_run_id from response
                    return True
                else:
                    self.logger.error(f"Webhook trigger failed: {response.status_code}")
                    return False
            else:
                # Fallback to API execution
                return await self._execute_via_api(execution, workflow_def)
                
        except Exception as e:
            self.logger.error(f"Failed to execute workflow: {str(e)}")
            execution.error_message = str(e)
            return False
            
    async def _trigger_webhook(self, webhook_url: str, data: Dict[str, Any]) -> httpx.Response:
        """Trigger Tines workflow via webhook."""
        try:
            # Add webhook authentication if configured
            headers = {}
            if self.config.webhook_secret:
                headers["X-Webhook-Secret"] = self.config.webhook_secret
                
            response = await self.http_client.post(
                webhook_url,
                json=data,
                headers=headers
            )
            
            self._track_api_call()
            return response
            
        except Exception as e:
            self.logger.error(f"Failed to trigger webhook {webhook_url}: {str(e)}")
            raise
            
    async def _execute_via_api(
        self, 
        execution: TinesWorkflowExecution, 
        workflow_def: Dict[str, Any]
    ) -> bool:
        """Execute workflow via Tines REST API."""
        try:
            # TODO: Implement Tines API workflow execution
            # This would use the Tines REST API to trigger story execution
            self.logger.info("API-based workflow execution not yet implemented")
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to execute via API: {str(e)}")
            return False
            
    async def _update_execution_status(self, execution: TinesWorkflowExecution):
        """Update execution status by querying Tines."""
        try:
            if not execution.story_run_id:
                return
                
            # TODO: Query Tines API for story run status
            # For now, simulate status update
            elapsed = datetime.utcnow() - execution.started_at
            
            if elapsed > timedelta(minutes=self.config.default_timeout_minutes):
                execution.status = TinesWorkflowStatus.TIMEOUT
                execution.completed_at = datetime.utcnow()
                execution.error_message = "Workflow execution timeout"
                
        except Exception as e:
            self.logger.error(f"Failed to update execution status: {str(e)}")
            
    async def _prepare_incident_response_input(
        self,
        incident: IncidentTracker, 
        business_impact: BusinessImpact,
        additional_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Prepare input data for incident response workflow."""
        input_data = {
            # Incident details
            "incident_id": incident.incident_id,
            "severity": incident.event.severity.value,
            "event_type": incident.event.event_type.value,
            "title": incident.event.title,
            "description": incident.event.description,
            "source_platform": incident.event.source_platform,
            "affected_resources": incident.event.affected_resources,
            
            # Business context
            "business_impact": business_impact.value,
            "asset_criticality": incident.business_context.asset_criticality,
            "revenue_impact": incident.business_context.revenue_impact,
            "customer_impact": incident.business_context.customer_impact,
            "compliance_impact": incident.business_context.compliance_impact,
            
            # Timing
            "incident_start_time": incident.created_at.isoformat(),
            "workflow_trigger_time": datetime.utcnow().isoformat(),
            
            # Integration context
            "slack_thread_ts": incident.slack_thread.thread_ts if incident.slack_thread else None,
            "slack_channel": incident.slack_thread.channel if incident.slack_thread else None,
            "canvas_id": incident.canvas_id,
            "jira_ticket": incident.jira_ticket,
            
            # Workflow configuration
            "enable_automatic_containment": business_impact in [BusinessImpact.CRITICAL, BusinessImpact.HIGH],
            "require_human_approval": True,
            "notification_stakeholders": self._determine_stakeholders(incident, business_impact),
            "escalation_thresholds": self._get_escalation_thresholds(business_impact)
        }
        
        # Add additional context
        if additional_context:
            input_data.update(additional_context)
            
        return input_data
        
    def _determine_stakeholders(
        self, 
        incident: IncidentTracker, 
        business_impact: BusinessImpact
    ) -> List[str]:
        """Determine stakeholders for workflow notifications."""
        stakeholders = ["security_team"]
        
        if business_impact in [BusinessImpact.HIGH, BusinessImpact.CRITICAL]:
            stakeholders.append("security_leadership")
            
        if business_impact == BusinessImpact.CRITICAL:
            stakeholders.extend(["ciso", "executive_team"])
            
        if incident.business_context.regulatory_notification_required:
            stakeholders.extend(["legal_team", "compliance_team"])
            
        if incident.business_context.media_attention_risk:
            stakeholders.append("pr_team")
            
        return stakeholders
        
    def _get_escalation_thresholds(self, business_impact: BusinessImpact) -> Dict[str, int]:
        """Get escalation time thresholds based on business impact."""
        if business_impact == BusinessImpact.CRITICAL:
            return {"leadership_minutes": 15, "executive_minutes": 30}
        elif business_impact == BusinessImpact.HIGH:
            return {"leadership_minutes": 30, "executive_minutes": 60}
        else:
            return {"leadership_minutes": 60, "executive_minutes": 120}
            
    def _calculate_period_start(self, period: str) -> datetime:
        """Calculate start date for reporting period."""
        now = datetime.utcnow()
        
        if period == "daily":
            return now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == "weekly":
            days_since_monday = now.weekday()
            return (now - timedelta(days=days_since_monday)).replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == "monthly":
            return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            return now - timedelta(days=7)  # Default to weekly
            
    async def _api_call(self, method: str, endpoint: str, data: Dict[str, Any] = None) -> httpx.Response:
        """Make authenticated API call to Tines."""
        try:
            url = f"{self.config.tenant_url}{endpoint}"
            
            if method.upper() == "GET":
                response = await self.http_client.get(url, params=data)
            elif method.upper() == "POST":
                response = await self.http_client.post(url, json=data)
            elif method.upper() == "PUT":
                response = await self.http_client.put(url, json=data)
            elif method.upper() == "DELETE":
                response = await self.http_client.delete(url)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
                
            self._track_api_call()
            return response
            
        except Exception as e:
            self.logger.error(f"Tines API call failed {method} {endpoint}: {str(e)}")
            raise
            
    async def _check_rate_limit(self):
        """Check and enforce rate limiting."""
        now = datetime.utcnow()
        
        # Reset counter every minute
        if now - self.last_rate_limit_reset > timedelta(minutes=1):
            self.api_calls_per_minute = 0
            self.last_rate_limit_reset = now
            
        # Check rate limit
        if self.api_calls_per_minute >= self.config.rate_limit_per_minute:
            wait_time = 60 - (now - self.last_rate_limit_reset).seconds
            if wait_time > 0:
                self.logger.warning(f"Rate limit reached, waiting {wait_time} seconds")
                await asyncio.sleep(wait_time)
                
    def _track_api_call(self):
        """Track API call for rate limiting."""
        self.api_calls_per_minute += 1
        
    async def close(self):
        """Close Tines integration and cleanup resources."""
        await self.http_client.aclose()


# Configuration factory

def create_tines_config(
    tenant_url: str,
    api_token: str, 
    webhook_secret: str = None
) -> TinesWorkflowConfig:
    """Create Tines configuration for SecurityAgents integration."""
    return TinesWorkflowConfig(
        tenant_url=tenant_url,
        api_token=api_token,
        webhook_secret=webhook_secret or "",
        default_timeout_minutes=30,
        max_concurrent_workflows=50,
        enable_audit_logging=True,
        require_approval_for_destructive=True
    )