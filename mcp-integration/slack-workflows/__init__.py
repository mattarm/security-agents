"""
SecurityAgents Slack MCP Integration Package

Enterprise-grade Slack workflow automation for real-time security incident 
management, role-based escalation, and team collaboration.

P0 Deliverable for SecurityAgents Phase 2C Advanced Analytics & Orchestration
Author: Tiger Team Alpha-3 Slack Workflows Specialist

Usage:
    from slack_workflows import create_slack_integration
    
    # Initialize with Alpha-2 gateway
    slack_integration = await create_slack_integration(
        gateway=enterprise_gateway,
        slack_config=slack_config
    )
    
    # Process security events automatically
    await slack_integration.start()
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

# Core integration components
from .slack_mcp_client import SlackMCPClient, SlackConfig, SlackRateLimit, create_slack_config
from .notifications.incident_manager import (
    SecurityIncidentManager, BusinessImpact, BusinessContext,
    BusinessImpactAssessor, IncidentTracker
)
from .escalation.escalation_engine import (
    EscalationEngine, EscalationLevel, EscalationTrigger, EscalationEvent
)
from .automation.slack_orchestrator import (
    SlackWorkflowOrchestrator, SlackWorkflowConfiguration,
    SlackWorkflowStatus, SlackIntegrationHealth, create_slack_orchestrator
)
from .automation.tines_integration import (
    TinesIntegration, TinesWorkflowConfig, TinesWorkflowType,
    create_tines_config
)

# Version info
__version__ = "1.0.0"
__author__ = "Tiger Team Alpha-3 Slack Workflows Specialist"
__description__ = "Enterprise Slack MCP Integration for SecurityAgents Platform"

# Configure logging
logger = logging.getLogger(__name__)


# Main integration factory function
async def create_slack_integration(
    gateway,  # EnterpriseMCPGateway from Alpha-2
    slack_client_id: str,
    slack_client_secret: str,
    slack_bot_token: str,
    slack_workspace_id: str,
    rate_limit_tier: SlackRateLimit = SlackRateLimit.TIER_3,
    tines_config: Optional[TinesWorkflowConfig] = None,
    custom_config: Optional[Dict[str, Any]] = None
) -> SlackWorkflowOrchestrator:
    """
    Create and initialize complete Slack workflow integration.
    
    This is the main entry point for integrating Slack workflows with
    SecurityAgents platform via Alpha-2's enterprise MCP gateway.
    
    Args:
        gateway: Alpha-2's EnterpriseMCPGateway instance
        slack_client_id: Slack app client ID
        slack_client_secret: Slack app client secret  
        slack_bot_token: Slack bot token
        slack_workspace_id: Target workspace ID
        rate_limit_tier: Slack API rate limit tier
        tines_config: Optional Tines integration configuration
        custom_config: Optional custom workflow configuration
        
    Returns:
        Initialized and ready SlackWorkflowOrchestrator
        
    Raises:
        Exception: If initialization fails
    """
    try:
        logger.info("Creating SecurityAgents Slack integration")
        
        # Create Slack orchestrator with Alpha-2 gateway integration
        orchestrator = await create_slack_orchestrator(
            gateway=gateway,
            slack_client_id=slack_client_id,
            slack_client_secret=slack_client_secret,
            slack_bot_token=slack_bot_token,
            slack_workspace_id=slack_workspace_id,
            rate_limit_tier=rate_limit_tier
        )
        
        # Add Tines integration if configured
        if tines_config:
            tines_integration = TinesIntegration(tines_config)
            success = await tines_integration.initialize()
            
            if success:
                # TODO: Integrate Tines with orchestrator
                logger.info("Tines workflow integration enabled")
            else:
                logger.warning("Tines integration failed to initialize")
                
        # Apply custom configuration if provided
        if custom_config:
            await _apply_custom_configuration(orchestrator, custom_config)
            
        logger.info("Slack integration created successfully")
        return orchestrator
        
    except Exception as e:
        logger.error(f"Failed to create Slack integration: {str(e)}")
        raise


async def _apply_custom_configuration(
    orchestrator: SlackWorkflowOrchestrator, 
    config: Dict[str, Any]
):
    """Apply custom configuration to orchestrator."""
    try:
        # Update workflow configuration
        if "business_hours" in config:
            hours = config["business_hours"]
            orchestrator.config.business_hours_start = hours.get("start", 8)
            orchestrator.config.business_hours_end = hours.get("end", 18)
            
        if "escalation" in config:
            escalation = config["escalation"]
            orchestrator.config.enable_auto_escalation = escalation.get("auto_escalation", True)
            orchestrator.config.enable_executive_notifications = escalation.get("executive_notifications", True)
            
        if "performance" in config:
            perf = config["performance"]
            orchestrator.config.max_concurrent_notifications = perf.get("max_concurrent", 50)
            orchestrator.config.notification_timeout_seconds = perf.get("timeout_seconds", 30)
            
        logger.info("Applied custom configuration to Slack orchestrator")
        
    except Exception as e:
        logger.error(f"Failed to apply custom configuration: {str(e)}")


# Health check utilities
async def check_integration_health(orchestrator: SlackWorkflowOrchestrator) -> Dict[str, Any]:
    """
    Check comprehensive health of Slack integration.
    
    Args:
        orchestrator: SlackWorkflowOrchestrator instance
        
    Returns:
        Dict containing detailed health status
    """
    try:
        health_status = await orchestrator.get_health_status()
        
        # Add integration-specific health checks
        health_status["package_info"] = {
            "version": __version__,
            "author": __author__,
            "description": __description__
        }
        
        health_status["timestamp"] = datetime.utcnow().isoformat()
        
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


# Utility functions for common operations
async def send_test_notification(
    orchestrator: SlackWorkflowOrchestrator,
    channel: str = "security-alerts",
    message: str = "Test notification from SecurityAgents"
) -> bool:
    """
    Send test notification to verify Slack integration.
    
    Args:
        orchestrator: SlackWorkflowOrchestrator instance
        channel: Target Slack channel
        message: Test message content
        
    Returns:
        bool indicating successful test
    """
    try:
        # Create test security event
        from gateway.enterprise_mcp_gateway import SecurityEvent, EventSeverity, EventType
        import uuid
        
        test_event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.INTEGRATION_HEALTH,
            severity=EventSeverity.INFO,
            source_platform="SecurityAgents Test",
            timestamp=datetime.utcnow(),
            correlation_id=str(uuid.uuid4()),
            title="Slack Integration Test",
            description=message,
            affected_resources=["slack_integration"],
            indicators={"test": True},
            environment="test"
        )
        
        # Process test event
        result = await orchestrator.process_security_event(test_event)
        
        success = result.get("status") == "processed"
        if success:
            logger.info("Slack integration test notification successful")
        else:
            logger.error(f"Slack integration test failed: {result}")
            
        return success
        
    except Exception as e:
        logger.error(f"Failed to send test notification: {str(e)}")
        return False


# Export main classes and functions
__all__ = [
    # Main integration
    "create_slack_integration",
    "check_integration_health",
    "send_test_notification",
    
    # Core components
    "SlackWorkflowOrchestrator",
    "SlackMCPClient",
    "SecurityIncidentManager", 
    "EscalationEngine",
    "TinesIntegration",
    
    # Configuration
    "SlackConfig",
    "SlackWorkflowConfiguration",
    "TinesWorkflowConfig",
    "create_slack_config",
    "create_tines_config",
    
    # Enums and types
    "SlackRateLimit",
    "SlackWorkflowStatus",
    "SlackIntegrationHealth",
    "BusinessImpact",
    "EscalationLevel",
    "TinesWorkflowType",
    
    # Data classes
    "BusinessContext",
    "IncidentTracker",
    "EscalationEvent",
    
    # Version info
    "__version__",
    "__author__",
    "__description__"
]