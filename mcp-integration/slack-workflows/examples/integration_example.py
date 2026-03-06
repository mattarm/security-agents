#!/usr/bin/env python3
"""
SecurityAgents Slack Integration Example

Demonstrates how to integrate Slack MCP workflows with Alpha-2's enterprise 
gateway for real-time security incident management and team collaboration.

P0 Deliverable for SecurityAgents Phase 2C Slack Integration
Author: Tiger Team Alpha-3 Slack Workflows Specialist
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Dict, Any

# Import Alpha-2's gateway infrastructure
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from gateway.enterprise_mcp_gateway import EnterpriseMCPGateway, SecurityEvent, EventSeverity, EventType

# Import our Slack integration
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from slack_workflows import (
    create_slack_integration, check_integration_health, send_test_notification,
    SlackRateLimit, BusinessContext, BusinessImpact, create_tines_config
)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    """Main example demonstrating Slack integration with SecurityAgents platform."""
    try:
        logger.info("🚀 SecurityAgents Slack Integration Example")
        
        # Step 1: Initialize Alpha-2 Enterprise Gateway
        logger.info("1. Initializing Alpha-2 Enterprise MCP Gateway")
        gateway = await initialize_alpha2_gateway()
        
        # Step 2: Configure Slack Integration
        logger.info("2. Configuring Slack MCP Integration")
        slack_config = get_slack_configuration()
        
        # Step 3: Optional Tines Integration
        tines_config = get_tines_configuration()
        
        # Step 4: Create Slack Integration
        logger.info("3. Creating Slack Workflow Orchestrator")
        slack_orchestrator = await create_slack_integration(
            gateway=gateway,
            slack_client_id=slack_config["client_id"],
            slack_client_secret=slack_config["client_secret"],
            slack_bot_token=slack_config["bot_token"],
            slack_workspace_id=slack_config["workspace_id"],
            rate_limit_tier=SlackRateLimit.TIER_3,
            tines_config=tines_config
        )
        
        # Step 5: Health Check
        logger.info("4. Performing Integration Health Check")
        health_status = await check_integration_health(slack_orchestrator)
        logger.info(f"Health Status: {health_status['status']} - {health_status['health']}")
        
        # Step 6: Test Notification
        logger.info("5. Sending Test Notification")
        test_success = await send_test_notification(
            slack_orchestrator,
            channel="security-alerts",
            message="🔧 SecurityAgents Slack integration test successful!"
        )
        
        if test_success:
            logger.info("✅ Test notification sent successfully")
        else:
            logger.error("❌ Test notification failed")
            
        # Step 7: Simulate Security Incidents
        logger.info("6. Simulating Security Incident Workflows")
        await simulate_security_incidents(gateway, slack_orchestrator)
        
        # Step 8: Demonstrate Advanced Features
        logger.info("7. Demonstrating Advanced Features")
        await demonstrate_advanced_features(slack_orchestrator)
        
        # Step 9: Monitor for a while
        logger.info("8. Monitoring Slack Integration (30 seconds)")
        await monitor_integration(slack_orchestrator, duration_seconds=30)
        
        logger.info("🎉 Slack Integration Example Completed Successfully!")
        
    except Exception as e:
        logger.error(f"❌ Example failed: {str(e)}")
        raise
    finally:
        # Cleanup
        if 'slack_orchestrator' in locals():
            await slack_orchestrator.shutdown()
            

async def initialize_alpha2_gateway() -> EnterpriseMCPGateway:
    """Initialize Alpha-2's enterprise MCP gateway."""
    try:
        # Create gateway configuration
        gateway_config = {
            "rate_limit_requests_per_minute": 1000,
            "circuit_breaker_failure_threshold": 5,
            "enable_audit_logging": True,
            "enable_metrics_collection": True
        }
        
        # Initialize gateway
        gateway = EnterpriseMCPGateway(gateway_config)
        await gateway.initialize()
        
        logger.info("✅ Alpha-2 Enterprise Gateway initialized")
        return gateway
        
    except Exception as e:
        logger.error(f"Failed to initialize Alpha-2 gateway: {str(e)}")
        raise


def get_slack_configuration() -> Dict[str, str]:
    """Get Slack configuration from environment variables."""
    config = {
        "client_id": os.getenv("SLACK_CLIENT_ID"),
        "client_secret": os.getenv("SLACK_CLIENT_SECRET"),
        "bot_token": os.getenv("SLACK_BOT_TOKEN"),
        "workspace_id": os.getenv("SLACK_WORKSPACE_ID")
    }
    
    # Check for missing configuration
    missing_config = [key for key, value in config.items() if not value]
    if missing_config:
        logger.warning(f"Missing Slack configuration: {missing_config}")
        # Use example values for demonstration
        config.update({
            "client_id": "example_client_id",
            "client_secret": "example_client_secret", 
            "bot_token": "xoxb-example-bot-token",
            "workspace_id": "example_workspace"
        })
        logger.info("Using example Slack configuration for demo")
        
    return config


def get_tines_configuration():
    """Get optional Tines configuration."""
    tenant_url = os.getenv("TINES_TENANT_URL")
    api_token = os.getenv("TINES_API_TOKEN")
    
    if tenant_url and api_token:
        return create_tines_config(
            tenant_url=tenant_url,
            api_token=api_token,
            webhook_secret=os.getenv("TINES_WEBHOOK_SECRET")
        )
    else:
        logger.info("Tines configuration not provided, skipping advanced automation")
        return None


async def simulate_security_incidents(gateway: EnterpriseMCPGateway, orchestrator):
    """Simulate different types of security incidents."""
    try:
        logger.info("📋 Simulating Security Incident Scenarios")
        
        # Scenario 1: Critical Security Incident
        await simulate_critical_incident(gateway)
        await asyncio.sleep(2)  # Brief delay between scenarios
        
        # Scenario 2: High-Severity Vulnerability
        await simulate_vulnerability_incident(gateway)
        await asyncio.sleep(2)
        
        # Scenario 3: Compliance Violation
        await simulate_compliance_incident(gateway)
        await asyncio.sleep(2)
        
        logger.info("✅ Security incident simulations completed")
        
    except Exception as e:
        logger.error(f"Failed to simulate security incidents: {str(e)}")


async def simulate_critical_incident(gateway: EnterpriseMCPGateway):
    """Simulate critical security incident with business impact."""
    try:
        # Create critical security event
        critical_event = SecurityEvent(
            event_id="CRIT-2026-001",
            event_type=EventType.THREAT_DETECTION,
            severity=EventSeverity.CRITICAL,
            source_platform="CrowdStrike",
            timestamp=datetime.utcnow(),
            correlation_id="correlation-001",
            title="🚨 Advanced Persistent Threat Detected",
            description="Critical APT activity detected on production servers. Immediate containment required.",
            affected_resources=[
                "prod-web-01.company.com",
                "prod-db-01.company.com",
                "prod-api-gateway.company.com"
            ],
            indicators={
                "iocs": ["192.168.1.100", "malware.exe", "suspicious-domain.com"],
                "attack_vectors": ["lateral_movement", "privilege_escalation"],
                "confidence_score": 0.95
            },
            environment="production"
        )
        
        # Create business context
        business_context = BusinessContext(
            asset_criticality="critical",
            asset_classification="confidential",
            revenue_impact=50000.0,  # $50k per hour
            customer_impact=10000,   # 10k customers affected
            compliance_impact=["SOX", "GDPR", "NIST"],
            business_hours=True,
            environment="production",
            geography=["US", "EU"],
            media_attention_risk=True,
            regulatory_notification_required=True,
            customer_notification_required=True
        )
        
        # Process through gateway (which will trigger Slack workflows)
        await gateway.process_security_event(critical_event, {"business_context": business_context})
        
        logger.info("🚨 Critical incident simulation triggered")
        
    except Exception as e:
        logger.error(f"Failed to simulate critical incident: {str(e)}")


async def simulate_vulnerability_incident(gateway: EnterpriseMCPGateway):
    """Simulate high-severity vulnerability discovery."""
    try:
        vuln_event = SecurityEvent(
            event_id="VULN-2026-002",
            event_type=EventType.VULNERABILITY_DISCOVERY,
            severity=EventSeverity.HIGH,
            source_platform="GitHub Security",
            timestamp=datetime.utcnow(),
            correlation_id="correlation-002",
            title="🔍 Critical Vulnerability in Production Code",
            description="High-severity SQL injection vulnerability discovered in user authentication module.",
            affected_resources=[
                "auth-service",
                "user-management-api",
                "customer-portal"
            ],
            indicators={
                "cve_id": "CVE-2026-0001",
                "cvss_score": 8.5,
                "exploit_available": True,
                "patch_available": False
            },
            environment="production"
        )
        
        business_context = BusinessContext(
            asset_criticality="high",
            asset_classification="internal",
            revenue_impact=5000.0,   # $5k per hour
            customer_impact=1000,    # 1k customers
            compliance_impact=["PCI-DSS"],
            business_hours=True,
            environment="production"
        )
        
        await gateway.process_security_event(vuln_event, {"business_context": business_context})
        logger.info("🔍 Vulnerability incident simulation triggered")
        
    except Exception as e:
        logger.error(f"Failed to simulate vulnerability incident: {str(e)}")


async def simulate_compliance_incident(gateway: EnterpriseMCPGateway):
    """Simulate compliance violation incident."""
    try:
        compliance_event = SecurityEvent(
            event_id="COMP-2026-003",
            event_type=EventType.COMPLIANCE_VIOLATION,
            severity=EventSeverity.MEDIUM,
            source_platform="AWS Config",
            timestamp=datetime.utcnow(),
            correlation_id="correlation-003",
            title="⚠️ Compliance Policy Violation Detected", 
            description="S3 bucket with sensitive data configured without encryption at rest.",
            affected_resources=[
                "s3-customer-data-bucket",
                "s3-financial-records"
            ],
            indicators={
                "policy_violated": "encryption_at_rest",
                "compliance_framework": "SOX",
                "risk_level": "medium",
                "remediation_available": True
            },
            environment="production"
        )
        
        business_context = BusinessContext(
            asset_criticality="medium",
            asset_classification="confidential",
            compliance_impact=["SOX", "GDPR"],
            business_hours=True,
            regulatory_notification_required=False
        )
        
        await gateway.process_security_event(compliance_event, {"business_context": business_context})
        logger.info("⚠️ Compliance incident simulation triggered")
        
    except Exception as e:
        logger.error(f"Failed to simulate compliance incident: {str(e)}")


async def demonstrate_advanced_features(orchestrator):
    """Demonstrate advanced Slack integration features."""
    try:
        logger.info("🎯 Demonstrating Advanced Features")
        
        # Feature 1: Manual Escalation
        logger.info("Feature 1: Manual Escalation Simulation")
        await simulate_manual_escalation(orchestrator)
        
        # Feature 2: Incident Status Updates  
        logger.info("Feature 2: Incident Status Updates")
        await simulate_incident_updates(orchestrator)
        
        # Feature 3: War Room Creation
        logger.info("Feature 3: War Room Canvas Creation")
        await simulate_war_room_creation(orchestrator)
        
        # Feature 4: Executive Reporting
        logger.info("Feature 4: Executive Reporting")
        await simulate_executive_reporting(orchestrator)
        
        logger.info("✅ Advanced features demonstration completed")
        
    except Exception as e:
        logger.error(f"Failed to demonstrate advanced features: {str(e)}")


async def simulate_manual_escalation(orchestrator):
    """Simulate manual escalation by security analyst."""
    try:
        # Get an active incident (use the first one for demo)
        active_incidents = list(orchestrator.active_incidents.keys())
        if not active_incidents:
            logger.info("No active incidents for escalation demo")
            return
            
        incident_id = active_incidents[0]
        
        # Trigger manual escalation
        success = await orchestrator.escalation_engine.execute_manual_escalation(
            incident_id=incident_id,
            target_level=EscalationLevel.LEADERSHIP,
            reason="Escalation requested due to complexity and potential business impact",
            requested_by="security_analyst_demo"
        )
        
        if success:
            logger.info(f"✅ Manual escalation triggered for incident {incident_id}")
        else:
            logger.warning("Manual escalation simulation failed")
            
    except Exception as e:
        logger.error(f"Manual escalation simulation failed: {str(e)}")


async def simulate_incident_updates(orchestrator):
    """Simulate incident status updates."""
    try:
        active_incidents = list(orchestrator.active_incidents.keys())
        if not active_incidents:
            logger.info("No active incidents for status update demo")
            return
            
        incident_id = active_incidents[0]
        
        # Simulate acknowledgment
        await orchestrator.incident_manager.update_incident_status(
            incident_id=incident_id,
            status="acknowledged",
            status_message="🔍 Incident acknowledged by SOC analyst. Beginning investigation.",
            analyst="soc_analyst_demo"
        )
        
        await asyncio.sleep(1)
        
        # Simulate investigation progress
        await orchestrator.incident_manager.update_incident_status(
            incident_id=incident_id,
            status="investigating", 
            status_message="🔬 Investigation in progress. Evidence collected from affected systems.",
            analyst="soc_analyst_demo",
            evidence=["system_logs", "network_captures", "memory_dump"]
        )
        
        logger.info(f"✅ Status updates simulated for incident {incident_id}")
        
    except Exception as e:
        logger.error(f"Status update simulation failed: {str(e)}")


async def simulate_war_room_creation(orchestrator):
    """Simulate incident war room canvas creation."""
    try:
        active_incidents = list(orchestrator.active_incidents.keys())
        if not active_incidents:
            logger.info("No active incidents for war room demo")
            return
            
        incident_id = active_incidents[0]
        
        # Create war room canvas
        canvas_content = {
            "incident_id": incident_id,
            "severity": "critical",
            "start_time": datetime.utcnow().isoformat(),
            "description": "Advanced Persistent Threat incident requiring war room coordination"
        }
        
        canvas_id = await orchestrator.slack_client.create_incident_canvas(
            incident_id=incident_id,
            canvas_title=f"🏛️ War Room - {incident_id}",
            initial_content=canvas_content
        )
        
        if canvas_id:
            logger.info(f"✅ War room canvas created: {canvas_id}")
        else:
            logger.warning("War room creation simulation failed")
            
    except Exception as e:
        logger.error(f"War room creation simulation failed: {str(e)}")


async def simulate_executive_reporting(orchestrator):
    """Simulate executive reporting workflow."""
    try:
        # Check if Tines integration is available
        if hasattr(orchestrator, 'tines_integration'):
            execution = await orchestrator.tines_integration.execute_executive_reporting_workflow(
                time_period="daily",
                custom_metrics={"demo_mode": True, "report_type": "simulation"}
            )
            
            if execution.status != "failed":
                logger.info(f"✅ Executive reporting workflow triggered: {execution.execution_id}")
            else:
                logger.warning("Executive reporting simulation failed")
        else:
            logger.info("Executive reporting requires Tines integration (not configured)")
            
    except Exception as e:
        logger.error(f"Executive reporting simulation failed: {str(e)}")


async def monitor_integration(orchestrator, duration_seconds: int = 30):
    """Monitor Slack integration health and metrics."""
    try:
        logger.info(f"📊 Monitoring integration for {duration_seconds} seconds")
        
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < duration_seconds:
            # Get health status
            health = await check_integration_health(orchestrator)
            
            # Log key metrics
            metrics = health.get("metrics", {})
            logger.info(
                f"📈 Metrics - Notifications: {metrics.get('notifications_sent', 0)}, "
                f"Success Rate: {metrics.get('success_rate', 0.0):.2%}, "
                f"Active Threads: {metrics.get('active_threads', 0)}, "
                f"Escalations: {metrics.get('escalations_triggered', 0)}"
            )
            
            # Check for any issues
            if health.get("health") != "healthy":
                logger.warning(f"⚠️ Integration health: {health.get('health')}")
                
            await asyncio.sleep(5)  # Check every 5 seconds
            
        logger.info("✅ Monitoring completed")
        
    except Exception as e:
        logger.error(f"Monitoring failed: {str(e)}")


if __name__ == "__main__":
    """
    Run the SecurityAgents Slack integration example.
    
    Prerequisites:
    1. Set environment variables for Slack configuration:
       - SLACK_CLIENT_ID
       - SLACK_CLIENT_SECRET  
       - SLACK_BOT_TOKEN
       - SLACK_WORKSPACE_ID
       
    2. Optional Tines configuration:
       - TINES_TENANT_URL
       - TINES_API_TOKEN
       - TINES_WEBHOOK_SECRET
       
    3. Ensure Alpha-2 gateway is available and configured
    
    Usage:
        python integration_example.py
    """
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Example interrupted by user")
    except Exception as e:
        logger.error(f"💥 Example failed: {str(e)}")
        exit(1)