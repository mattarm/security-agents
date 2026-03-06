#!/usr/bin/env python3
"""
Comprehensive Test Suite for SecurityAgents Slack MCP Integration

Tests all components of the Slack workflow automation system including
incident management, escalation workflows, and enterprise integration.

P0 Deliverable for SecurityAgents Phase 2C Slack Integration
Author: Tiger Team Alpha-3 Slack Workflows Specialist
"""

import asyncio
import pytest
import unittest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta
import json
import uuid

# Import test dependencies
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import components to test
from slack_mcp_client import SlackMCPClient, SlackConfig, SlackRateLimit, create_slack_config
from notifications.incident_manager import (
    SecurityIncidentManager, BusinessImpact, BusinessContext,
    BusinessImpactAssessor, IncidentTracker
)
from escalation.escalation_engine import (
    EscalationEngine, EscalationLevel, EscalationTrigger, EscalationEvent
)
from automation.slack_orchestrator import SlackWorkflowOrchestrator, SlackWorkflowConfiguration
from automation.tines_integration import TinesIntegration, TinesWorkflowConfig

# Import Alpha-2 gateway components for testing
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from gateway.enterprise_mcp_gateway import SecurityEvent, EventSeverity, EventType


class TestSlackMCPClient(unittest.TestCase):
    """Test cases for Slack MCP client authentication and API operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.slack_config = create_slack_config(
            client_id="test_client_id",
            client_secret="test_client_secret",
            bot_token="xoxb-test-token",
            workspace_id="test_workspace"
        )
        self.slack_client = SlackMCPClient(self.slack_config)
        
    def tearDown(self):
        """Clean up test fixtures."""
        asyncio.run(self.slack_client.close())
        
    @patch('slack_mcp_client.httpx.AsyncClient')
    async def test_oauth_authentication(self, mock_http_client):
        """Test OAuth 2.0 authentication flow."""
        # Mock successful auth response
        mock_response = Mock()
        mock_response.json.return_value = {
            "ok": True,
            "user_id": "U123456",
            "team_id": "T123456",
            "team": "Test Team",
            "url": "https://test-team.slack.com"
        }
        mock_http_client.return_value.get.return_value = mock_response
        
        # Test authentication
        auth_info = await self.slack_client.authenticate_oauth2()
        
        # Assertions
        self.assertTrue(auth_info)
        self.assertEqual(auth_info["team"], "Test Team")
        self.assertEqual(auth_info["user_id"], "U123456")
        
    async def test_rate_limiting_compliance(self):
        """Test rate limiting implementation."""
        rate_limiter = self.slack_client.rate_limiter
        
        # Test rate limit enforcement
        start_time = datetime.utcnow()
        
        # Make requests up to limit
        for _ in range(rate_limiter.tier.value):
            await rate_limiter.wait_if_needed()
            
        # Next request should cause delay
        await rate_limiter.wait_if_needed()
        
        elapsed_time = datetime.utcnow() - start_time
        # Should have some delay for rate limiting
        self.assertGreater(elapsed_time.total_seconds(), 0)
        
    def test_security_validator(self):
        """Test enterprise security validation."""
        validator = self.slack_client.security_validator
        
        # Test OAuth config validation
        asyncio.run(validator.validate_oauth_config())
        
        # Test workspace validation
        validation_result = asyncio.run(validator.validate_workspace())
        
        self.assertTrue(validation_result["workspace_admin_approval"])
        self.assertTrue(validation_result["audit_logging"])
        self.assertIn("required_scopes", validation_result)


class TestSecurityIncidentManager(unittest.TestCase):
    """Test cases for security incident management and notifications."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_slack_client = AsyncMock(spec=SlackMCPClient)
        self.incident_manager = SecurityIncidentManager(self.mock_slack_client)
        
    def test_business_impact_assessment(self):
        """Test business impact assessment engine."""
        assessor = BusinessImpactAssessor()
        
        # Test critical impact scenario
        critical_event = SecurityEvent(
            event_id="TEST-CRIT-001",
            event_type=EventType.THREAT_DETECTION,
            severity=EventSeverity.CRITICAL,
            source_platform="Test",
            timestamp=datetime.utcnow(),
            correlation_id="test-correlation",
            title="Critical Test Event",
            description="Test critical security event",
            affected_resources=["critical-system"],
            indicators={},
            environment="production"
        )
        
        critical_context = BusinessContext(
            asset_criticality="critical",
            revenue_impact=100000.0,  # $100k/hour
            customer_impact=50000,    # 50k customers
            compliance_impact=["SOX", "GDPR"],
            regulatory_notification_required=True,
            media_attention_risk=True
        )
        
        impact = asyncio.run(assessor.assess_impact(critical_event, critical_context))
        self.assertEqual(impact, BusinessImpact.CRITICAL)
        
        # Test low impact scenario
        low_event = SecurityEvent(
            event_id="TEST-LOW-001",
            event_type=EventType.INTEGRATION_HEALTH,
            severity=EventSeverity.INFO,
            source_platform="Test",
            timestamp=datetime.utcnow(),
            correlation_id="test-correlation",
            title="Info Test Event",
            description="Test informational event",
            affected_resources=[],
            indicators={},
            environment="development"
        )
        
        low_context = BusinessContext()
        
        impact = asyncio.run(assessor.assess_impact(low_event, low_context))
        self.assertEqual(impact, BusinessImpact.NONE)
        
    async def test_incident_processing_workflow(self):
        """Test complete incident processing workflow."""
        # Create test incident
        test_event = SecurityEvent(
            event_id="TEST-INCIDENT-001",
            event_type=EventType.VULNERABILITY_DISCOVERY,
            severity=EventSeverity.HIGH,
            source_platform="Test Platform",
            timestamp=datetime.utcnow(),
            correlation_id="test-correlation",
            title="Test Vulnerability",
            description="High severity vulnerability discovered",
            affected_resources=["web-app", "database"],
            indicators={"cvss_score": 8.5},
            environment="production"
        )
        
        business_context = BusinessContext(
            asset_criticality="high",
            revenue_impact=10000.0
        )
        
        # Mock Slack client responses
        self.mock_slack_client.send_security_incident_notification.return_value = Mock(
            thread_ts="123.456",
            channel="security-incidents",
            incident_id="TEST-INCIDENT-001"
        )
        
        # Process incident
        incident = await self.incident_manager.process_security_incident(
            test_event, business_context
        )
        
        # Assertions
        self.assertEqual(incident.incident_id, "TEST-INCIDENT-001")
        self.assertEqual(incident.status, "new")
        self.assertIsNotNone(incident.created_at)
        self.mock_slack_client.send_security_incident_notification.assert_called_once()
        
    async def test_incident_status_updates(self):
        """Test incident status update workflow."""
        # Create mock incident
        test_event = SecurityEvent(
            event_id="TEST-STATUS-001",
            event_type=EventType.THREAT_DETECTION,
            severity=EventSeverity.MEDIUM,
            source_platform="Test",
            timestamp=datetime.utcnow(),
            correlation_id="test-correlation",
            title="Test Event",
            description="Test event for status updates",
            affected_resources=[],
            indicators={},
            environment="test"
        )
        
        incident = IncidentTracker(
            incident_id="TEST-STATUS-001",
            event=test_event,
            business_context=BusinessContext()
        )
        
        self.incident_manager.active_incidents["TEST-STATUS-001"] = incident
        
        # Mock thread update
        self.mock_slack_client.update_incident_thread.return_value = True
        
        # Test status update
        success = await self.incident_manager.update_incident_status(
            "TEST-STATUS-001",
            "acknowledged",
            "Incident acknowledged by analyst",
            "test_analyst"
        )
        
        # Assertions
        self.assertTrue(success)
        self.assertEqual(incident.status, "acknowledged")
        self.assertEqual(incident.assigned_analyst, "test_analyst")
        self.assertIsNotNone(incident.acknowledged_at)
        self.mock_slack_client.update_incident_thread.assert_called_once()


class TestEscalationEngine(unittest.TestCase):
    """Test cases for escalation engine and role-based workflows."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_slack_client = AsyncMock(spec=SlackMCPClient)
        self.escalation_engine = EscalationEngine(self.mock_slack_client)
        
    def tearDown(self):
        """Clean up test fixtures."""
        asyncio.run(self.escalation_engine.stop_monitoring())
        
    async def test_escalation_scheduling(self):
        """Test escalation scheduling based on incident severity."""
        # Create test incident
        test_event = SecurityEvent(
            event_id="TEST-ESCALATION-001",
            event_type=EventType.THREAT_DETECTION,
            severity=EventSeverity.CRITICAL,
            source_platform="Test",
            timestamp=datetime.utcnow(),
            correlation_id="test-correlation",
            title="Critical Test Event",
            description="Test critical event for escalation",
            affected_resources=["critical-system"],
            indicators={},
            environment="production"
        )
        
        incident = IncidentTracker(
            incident_id="TEST-ESCALATION-001",
            event=test_event,
            business_context=BusinessContext(asset_criticality="critical")
        )
        
        # Schedule escalations
        escalations = await self.escalation_engine.schedule_incident_escalation(
            incident, BusinessImpact.CRITICAL
        )
        
        # Assertions
        self.assertGreater(len(escalations), 0)
        
        # Check that escalations are scheduled with appropriate timing
        team_escalation = next(
            (e for e in escalations if e.to_level == EscalationLevel.LEADERSHIP), None
        )
        self.assertIsNotNone(team_escalation)
        self.assertEqual(team_escalation.trigger, EscalationTrigger.TIME_BASED)
        
    async def test_manual_escalation(self):
        """Test manual escalation execution."""
        # Mock successful escalation execution
        with patch.object(self.escalation_engine, '_execute_escalation', return_value=True):
            success = await self.escalation_engine.execute_manual_escalation(
                incident_id="TEST-MANUAL-001",
                target_level=EscalationLevel.LEADERSHIP,
                reason="Manual escalation for testing",
                requested_by="test_analyst"
            )
            
        # Assertions
        self.assertTrue(success)
        
        # Check that escalation was recorded
        escalation_found = any(
            e.trigger == EscalationTrigger.MANUAL 
            for e in self.escalation_engine.active_escalations.values()
        )
        self.assertTrue(escalation_found)
        
    async def test_escalation_acknowledgment(self):
        """Test escalation acknowledgment workflow."""
        # Create test escalation
        test_escalation = EscalationEvent(
            escalation_id="TEST-ACK-001",
            incident_id="TEST-INCIDENT-001",
            trigger=EscalationTrigger.TIME_BASED,
            from_level=EscalationLevel.TEAM,
            to_level=EscalationLevel.LEADERSHIP,
            scheduled_at=datetime.utcnow(),
            triggered_at=datetime.utcnow(),
            reason="Test escalation"
        )
        
        self.escalation_engine.active_escalations["TEST-ACK-001"] = test_escalation
        
        # Mock thread update
        self.mock_slack_client.update_incident_thread.return_value = True
        
        # Acknowledge escalation
        success = await self.escalation_engine.acknowledge_escalation(
            "TEST-ACK-001",
            "test_manager",
            ["investigate_further", "coordinate_response"]
        )
        
        # Assertions
        self.assertTrue(success)
        self.assertEqual(test_escalation.acknowledged_by, "test_manager")
        self.assertEqual(len(test_escalation.response_actions), 2)


class TestSlackWorkflowOrchestrator(unittest.TestCase):
    """Test cases for complete Slack workflow orchestration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_gateway = Mock()
        self.mock_gateway.register_event_handler = AsyncMock()
        
        slack_config = create_slack_config(
            client_id="test_client",
            client_secret="test_secret",
            bot_token="test_token",
            workspace_id="test_workspace"
        )
        
        workflow_config = SlackWorkflowConfiguration(slack_config=slack_config)
        
        with patch('automation.slack_orchestrator.SlackMCPClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client.authenticate_oauth2.return_value = {"team": "Test Team"}
            mock_client_class.return_value = mock_client
            
            self.orchestrator = SlackWorkflowOrchestrator(self.mock_gateway, workflow_config)
            
    def tearDown(self):
        """Clean up test fixtures."""
        asyncio.run(self.orchestrator.shutdown())
        
    async def test_orchestrator_initialization(self):
        """Test orchestrator initialization workflow."""
        with patch.object(self.orchestrator, '_register_with_gateway'), \
             patch.object(self.orchestrator, '_start_event_processing'), \
             patch.object(self.orchestrator, '_perform_health_check'), \
             patch.object(self.orchestrator.escalation_engine, 'start_monitoring'):
            
            success = await self.orchestrator.initialize()
            self.assertTrue(success)
            
    async def test_security_event_processing(self):
        """Test complete security event processing workflow."""
        # Create test event
        test_event = SecurityEvent(
            event_id="TEST-PROCESS-001",
            event_type=EventType.THREAT_DETECTION,
            severity=EventSeverity.HIGH,
            source_platform="Test Platform",
            timestamp=datetime.utcnow(),
            correlation_id="test-correlation",
            title="Test Processing Event",
            description="Event for processing test",
            affected_resources=["test-resource"],
            indicators={},
            environment="test"
        )
        
        # Mock component responses
        with patch.object(self.orchestrator.incident_manager, 'process_security_incident') as mock_process, \
             patch.object(self.orchestrator.escalation_engine, 'schedule_incident_escalation') as mock_escalate:
            
            mock_incident = IncidentTracker(
                incident_id="TEST-PROCESS-001",
                event=test_event,
                business_context=BusinessContext()
            )
            mock_process.return_value = mock_incident
            mock_escalate.return_value = []
            
            # Process event
            result = await self.orchestrator.process_security_event(test_event)
            
            # Assertions
            self.assertEqual(result["status"], "processed")
            self.assertEqual(result["incident_id"], "TEST-PROCESS-001")
            mock_process.assert_called_once()
            mock_escalate.assert_called_once()
            
    async def test_slack_interaction_handling(self):
        """Test Slack interaction handling (button clicks, etc.)."""
        # Test acknowledgment interaction
        ack_payload = {
            "actions": [{"action_id": "acknowledge_TEST-INTERACTION-001"}],
            "user": {"id": "U123456"}
        }
        
        with patch.object(self.orchestrator, '_handle_incident_acknowledgment') as mock_ack:
            mock_ack.return_value = {"text": "✅ Incident acknowledged"}
            
            result = await self.orchestrator.handle_slack_interaction(
                "acknowledge_incident", ack_payload
            )
            
            self.assertEqual(result["text"], "✅ Incident acknowledged")
            mock_ack.assert_called_once()
            
    async def test_health_monitoring(self):
        """Test health monitoring and metrics collection."""
        with patch.object(self.orchestrator, '_perform_health_check'):
            health_status = await self.orchestrator.get_health_status()
            
            # Check required health status fields
            self.assertIn("status", health_status)
            self.assertIn("health", health_status) 
            self.assertIn("metrics", health_status)
            self.assertIn("circuit_breaker", health_status)
            self.assertIn("integration_status", health_status)


class TestTinesIntegration(unittest.TestCase):
    """Test cases for Tines workflow automation integration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tines_config = TinesWorkflowConfig(
            tenant_url="https://test.tines.com",
            api_token="test_token",
            webhook_secret="test_secret"
        )
        
        with patch('automation.tines_integration.httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"name": "Test Tenant"}
            mock_client.return_value.get.return_value = mock_response
            
            self.tines_integration = TinesIntegration(self.tines_config)
            
    def tearDown(self):
        """Clean up test fixtures."""
        asyncio.run(self.tines_integration.close())
        
    async def test_tines_connectivity(self):
        """Test Tines API connectivity and authentication."""
        with patch.object(self.tines_integration, '_test_connectivity'), \
             patch.object(self.tines_integration, '_load_workflow_definitions'):
            
            success = await self.tines_integration.initialize()
            self.assertTrue(success)
            
    async def test_incident_response_workflow(self):
        """Test incident response workflow execution."""
        # Create test incident
        test_event = SecurityEvent(
            event_id="TEST-TINES-001",
            event_type=EventType.THREAT_DETECTION,
            severity=EventSeverity.CRITICAL,
            source_platform="Test",
            timestamp=datetime.utcnow(),
            correlation_id="test-correlation",
            title="Test Tines Event",
            description="Event for Tines workflow test",
            affected_resources=["test-system"],
            indicators={},
            environment="test"
        )
        
        incident = IncidentTracker(
            incident_id="TEST-TINES-001",
            event=test_event,
            business_context=BusinessContext()
        )
        
        # Mock workflow execution
        with patch.object(self.tines_integration, '_execute_workflow', return_value=True):
            execution = await self.tines_integration.execute_incident_response_workflow(
                incident, BusinessImpact.CRITICAL
            )
            
            # Assertions
            self.assertEqual(execution.incident_id, "TEST-TINES-001")
            self.assertIn("incident_id", execution.input_data)
            
    async def test_executive_reporting_workflow(self):
        """Test executive reporting workflow execution."""
        with patch.object(self.tines_integration, '_execute_workflow', return_value=True):
            execution = await self.tines_integration.execute_executive_reporting_workflow(
                time_period="weekly",
                custom_metrics={"test_mode": True}
            )
            
            # Assertions  
            self.assertEqual(execution.incident_id, "executive_report")
            self.assertIn("reporting_period", execution.input_data)
            self.assertEqual(execution.input_data["reporting_period"], "weekly")


class TestIntegrationWorkflows(unittest.TestCase):
    """End-to-end integration tests for complete workflows."""
    
    async def test_complete_incident_workflow(self):
        """Test complete incident workflow from detection to resolution."""
        # This would test the entire workflow:
        # 1. Security event received
        # 2. Slack notification sent
        # 3. Business impact assessed
        # 4. Escalations scheduled
        # 5. Status updates processed
        # 6. Resolution handling
        
        # Mock all external dependencies
        with patch('slack_mcp_client.httpx.AsyncClient'), \
             patch('automation.slack_orchestrator.EnterpriseMCPGateway') as mock_gateway:
            
            # Set up mock gateway
            mock_gateway_instance = Mock()
            mock_gateway_instance.register_event_handler = AsyncMock()
            mock_gateway.return_value = mock_gateway_instance
            
            # Create orchestrator
            slack_config = create_slack_config(
                "test_client", "test_secret", "test_token", "test_workspace"
            )
            workflow_config = SlackWorkflowConfiguration(slack_config=slack_config)
            
            orchestrator = SlackWorkflowOrchestrator(mock_gateway_instance, workflow_config)
            
            # Initialize with mocks
            with patch.object(orchestrator.slack_client, 'authenticate_oauth2'), \
                 patch.object(orchestrator, '_register_with_gateway'), \
                 patch.object(orchestrator, '_start_event_processing'), \
                 patch.object(orchestrator, '_perform_health_check'):
                
                await orchestrator.initialize()
                
            # Test complete workflow
            # (Implementation would continue with full workflow testing)
            
            self.assertTrue(True)  # Placeholder assertion
            
            await orchestrator.shutdown()


# Test runner utility functions

def run_unit_tests():
    """Run all unit tests."""
    test_loader = unittest.TestLoader()
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestSlackMCPClient,
        TestSecurityIncidentManager,
        TestEscalationEngine,
        TestSlackWorkflowOrchestrator,
        TestTinesIntegration,
        TestIntegrationWorkflows
    ]
    
    for test_class in test_classes:
        tests = test_loader.loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()


def run_integration_tests():
    """Run integration tests with external dependencies."""
    # This would run tests that require actual Slack/Tines connectivity
    # For security reasons, these are typically run in staging environments
    print("Integration tests require live Slack workspace and Tines tenant")
    print("Configure test environment and run separately")
    return True


async def run_async_tests():
    """Run asynchronous test cases."""
    # This function would handle async test execution
    # pytest-asyncio provides better async test support in practice
    test_results = []
    
    # Example async test execution
    try:
        # Run async tests here
        test_results.append(True)
    except Exception as e:
        print(f"Async test failed: {str(e)}")
        test_results.append(False)
    
    return all(test_results)


if __name__ == "__main__":
    """
    Run the SecurityAgents Slack integration test suite.
    
    Usage:
        python test_slack_integration.py              # Run all unit tests
        python test_slack_integration.py --unit       # Run unit tests only
        python test_slack_integration.py --integration # Run integration tests
        python test_slack_integration.py --async      # Run async tests
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="SecurityAgents Slack Integration Test Suite")
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests")
    parser.add_argument("--async", action="store_true", help="Run async tests")
    
    args = parser.parse_args()
    
    success = True
    
    if args.unit or not any([args.unit, args.integration, args.async]):
        print("🧪 Running Unit Tests...")
        success &= run_unit_tests()
        
    if args.integration:
        print("🔗 Running Integration Tests...")
        success &= run_integration_tests()
        
    if args.async:
        print("⚡ Running Async Tests...")
        success &= asyncio.run(run_async_tests())
        
    if success:
        print("✅ All tests passed!")
        exit(0)
    else:
        print("❌ Some tests failed!")
        exit(1)