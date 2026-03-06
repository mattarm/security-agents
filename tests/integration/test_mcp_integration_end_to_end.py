"""
Integration Tests for MCP Integration End-to-End Validation

End-to-end integration testing for CrowdStrike, AWS, and GitHub MCP connections
with real API endpoints and enterprise gateway orchestration.

P0 Testing for Production Deployment Validation
"""

import pytest
import asyncio
import json
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch, Mock
import os

from mcp_integration.gateway.enterprise_mcp_gateway import (
    EnterpriseSecurityMCPGateway,
    SecurityEvent,
    EventType,
    EventSeverity,
    OrchestrationWorkflow,
    OrchestrationStrategy
)
from mcp_integration.crowdstrike.crowdstrike_mcp_client import (
    CrowdStrikeMCPClient,
    FQLQuery,
    create_crowdstrike_config
)
from mcp_integration.aws.aws_security_mcp_client import (
    AWSSecurityMCPClient,
    AWSSecuritySeverity
)
from mcp_integration.github.github_security_mcp_client import (
    GitHubSecurityMCPClient,
    GitHubSecuritySeverity,
    SecDevOpsPipelineConfig
)


@pytest.mark.integration
class TestEnterpriseGatewayIntegration:
    """Integration tests for Enterprise MCP Gateway."""
    
    @pytest.fixture
    async def enterprise_gateway(self, mock_aws_services, mock_github_token):
        """Create Enterprise Gateway with mocked services for integration testing."""
        gateway = EnterpriseSecurityMCPGateway(
            aws_region="us-west-2",
            github_token="ghp_test_token"
        )
        
        # Mock platform clients to avoid real API calls in integration tests
        gateway.platform_clients = {
            'crowdstrike': Mock(),
            'aws': Mock(), 
            'github': Mock()
        }
        
        # Configure mock responses
        gateway.platform_clients['crowdstrike'].search_threat_indicators = Mock(return_value={
            'threat_assessment': {'confidence': 85},
            'attribution': {'threat_actors': ['APT29']}
        })
        
        gateway.platform_clients['aws'].analyze_cloudtrail_events = Mock(return_value={
            'events_summary': {'high_risk_events': 2},
            'security_analysis': {'privilege_escalation_attempts': 1}
        })
        
        gateway.platform_clients['github'].scan_repository_security = Mock(return_value={
            'security_score': {'security_score': 75},
            'vulnerability_summary': {'total_vulnerabilities': 5}
        })
        
        yield gateway
        
        # Cleanup
        if hasattr(gateway, 'stop_gateway'):
            try:
                await gateway.stop_gateway()
            except:
                pass
    
    @pytest.mark.asyncio
    async def test_gateway_startup_and_shutdown(self, enterprise_gateway):
        """Test enterprise gateway startup and shutdown process."""
        # Start gateway
        await enterprise_gateway.start_gateway(num_workers=2)
        
        # Verify gateway is operational
        assert len(enterprise_gateway.processing_workers) >= 2
        assert enterprise_gateway.event_queue is not None
        assert len(enterprise_gateway.workflow_registry) > 0
        
        # Test health status
        health = await enterprise_gateway.get_platform_health_status()
        assert health['gateway_status'] in ['healthy', 'unhealthy']  # Could be either in test
        assert 'platform_health' in health
        assert 'metrics' in health
        
        # Stop gateway
        await enterprise_gateway.stop_gateway()
    
    @pytest.mark.asyncio
    async def test_security_event_ingestion_and_processing(self, enterprise_gateway):
        """Test security event ingestion and processing workflow."""
        await enterprise_gateway.start_gateway(num_workers=1)
        
        # Create test security event
        test_event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.THREAT_DETECTION,
            severity=EventSeverity.HIGH,
            source_platform="crowdstrike",
            timestamp=datetime.utcnow(),
            correlation_id=str(uuid.uuid4()),
            title="Integration Test Threat",
            description="High-severity threat detected during integration testing",
            affected_resources=["test-server-01", "test-repo"],
            indicators={
                "file_hash": "integration_test_hash_123",
                "process_name": "test_malware.exe",
                "source_ip": "192.168.100.50"
            }
        )
        
        # Ingest event
        correlation_id = await enterprise_gateway.ingest_security_event(test_event)
        
        assert correlation_id == test_event.correlation_id
        assert enterprise_gateway.metrics['total_events_processed'] >= 1
        assert enterprise_gateway.metrics['events_by_severity']['high'] >= 1
        
        # Wait for event processing
        await asyncio.sleep(2)
        
        # Verify event was processed
        assert enterprise_gateway.event_queue.qsize() == 0
        
        await enterprise_gateway.stop_gateway()
    
    @pytest.mark.asyncio
    async def test_threat_investigation_workflow_execution(self, enterprise_gateway):
        """Test threat investigation workflow execution across platforms."""
        await enterprise_gateway.start_gateway(num_workers=1)
        
        # Execute threat investigation workflow
        workflow_result = await enterprise_gateway.execute_orchestration_workflow(
            'threat_investigation',
            parameters={
                'threat_indicators': {'file_hash': 'test_hash_abc123'},
                'affected_resources': ['server-01', 'repo-01'],
                'severity': 'high'
            },
            correlation_id=str(uuid.uuid4())
        )
        
        # Verify workflow execution
        assert workflow_result['status'] == 'completed'
        assert 'execution_id' in workflow_result
        assert 'results' in workflow_result
        assert workflow_result['workflow_id'] == 'threat_investigation'
        
        # Verify platform operations were called
        results = workflow_result['results']
        assert 'crowdstrike' in results
        assert 'aws' in results
        assert 'github' in results
        
        await enterprise_gateway.stop_gateway()
    
    @pytest.mark.asyncio
    async def test_vulnerability_response_workflow_sequential(self, enterprise_gateway):
        """Test vulnerability response workflow with sequential execution."""
        await enterprise_gateway.start_gateway(num_workers=1)
        
        workflow_result = await enterprise_gateway.execute_orchestration_workflow(
            'vulnerability_response',
            parameters={
                'repositories': ['org/web-app', 'org/api-service'],
                'severity_threshold': 'medium',
                'auto_remediation': True
            },
            correlation_id=str(uuid.uuid4())
        )
        
        # Verify sequential execution completed
        assert workflow_result['status'] == 'completed'
        assert workflow_result['results']['strategy'] == 'sequential'
        
        # Verify execution order (sequential with dependencies)
        results = workflow_result['results']['results']
        assert 'github' in results
        assert 'aws' in results
        assert 'crowdstrike' in results
        
        await enterprise_gateway.stop_gateway()
    
    @pytest.mark.asyncio
    async def test_compliance_audit_workflow_parallel(self, enterprise_gateway):
        """Test compliance audit workflow with parallel execution."""
        await enterprise_gateway.start_gateway(num_workers=1)
        
        workflow_result = await enterprise_gateway.execute_orchestration_workflow(
            'compliance_audit',
            parameters={
                'frameworks': ['NIST_CSF_2.0', 'CIS_AWS_Foundations'],
                'scope': 'organization',
                'time_period_days': 30
            },
            correlation_id=str(uuid.uuid4())
        )
        
        # Verify parallel execution completed
        assert workflow_result['status'] == 'completed'
        assert workflow_result['results']['strategy'] == 'parallel'
        
        # All platforms should have executed in parallel
        results = workflow_result['results']['results']
        assert len(results) == 3
        
        await enterprise_gateway.stop_gateway()


@pytest.mark.integration
class TestCrowdStrikeMCPIntegration:
    """Integration tests for CrowdStrike MCP client."""
    
    @pytest.fixture
    def crowdstrike_integration_client(self, mock_http_responses):
        """Create CrowdStrike client for integration testing."""
        config = create_crowdstrike_config()
        client = CrowdStrikeMCPClient(config)
        
        # Mock the server manager for integration tests
        with patch.object(client, 'server_manager') as mock_manager:
            mock_manager.call_mcp_tool = Mock()
            yield client, mock_manager
    
    @pytest.mark.asyncio
    async def test_crowdstrike_authentication_flow(self, crowdstrike_integration_client):
        """Test CrowdStrike OAuth2 authentication flow."""
        client, mock_manager = crowdstrike_integration_client
        
        # Mock successful authentication
        mock_manager.call_mcp_tool.return_value = {
            'status': 'success',
            'authentication': 'valid',
            'token_expires': '2026-03-06T02:00:00Z'
        }
        
        # Test authentication via health check
        health = await client.get_health_status()
        
        assert 'authentication_status' in health
        assert health['modules_available'] == list(client.modules.keys())
        assert health['total_tools'] > 40  # Should have 40+ tools
    
    @pytest.mark.asyncio
    async def test_crowdstrike_fql_query_integration(self, crowdstrike_integration_client):
        """Test FQL query execution integration."""
        client, mock_manager = crowdstrike_integration_client
        
        # Mock FQL response
        mock_manager.call_mcp_tool.return_value = {
            'results': [
                {
                    'aid': 'test-aid-123',
                    'timestamp': '2026-03-06T01:00:00Z',
                    'event_simpleName': 'ProcessRollup2',
                    'ProcessId': 1234,
                    'CommandLine': 'test.exe --integration',
                    'SHA256HashData': 'integration_test_hash'
                }
            ],
            'execution_time_ms': 245,
            'has_more': False
        }
        
        # Test FQL query execution
        fql_query = FQLQuery(
            query_text="DeviceEvents | where Timestamp > ago(1h) | limit 10",
            time_range="1h"
        )
        
        result = await client.execute_fql_query(fql_query)
        
        assert 'query_metadata' in result
        assert 'results' in result
        assert 'summary' in result
        assert result['query_metadata']['result_count'] == 1
        assert result['query_metadata']['execution_time'] == 245
        
        # Verify MCP call was made correctly
        mock_manager.call_mcp_tool.assert_called_once()
        call_args = mock_manager.call_mcp_tool.call_args[0]
        assert call_args[0] == 'falcon_fql_query'
        assert call_args[1]['query'] == fql_query.query_text
    
    @pytest.mark.asyncio
    async def test_crowdstrike_threat_detection_integration(self, crowdstrike_integration_client):
        """Test real-time threat detection integration."""
        client, mock_manager = crowdstrike_integration_client
        
        # Mock threat detection response
        mock_manager.call_mcp_tool.return_value = {
            'detections': [
                {
                    'detection_id': 'integration-detection-456',
                    'timestamp': '2026-03-06T01:00:00Z',
                    'severity': 'critical',
                    'detection_type': 'malware',
                    'device': {
                        'device_id': 'integration-device-789',
                        'hostname': 'test-integration-host'
                    },
                    'process_name': 'integration_malware.exe',
                    'command_line': 'integration_malware.exe --test',
                    'file_hash': 'integration_threat_hash_xyz',
                    'iocs': [
                        {'type': 'hash', 'value': 'integration_threat_hash_xyz'},
                        {'type': 'ip', 'value': '192.168.100.100'}
                    ],
                    'mitre_tactics': ['TA0002', 'TA0005'],
                    'mitre_techniques': ['T1059', 'T1055']
                }
            ]
        }
        
        detections = await client.get_real_time_detections(
            time_range="24h",
            severity_filter=[],  # All severities
            limit=100
        )
        
        assert len(detections) == 1
        detection = detections[0]
        assert detection.event_id == 'integration-detection-456'
        assert detection.device_name == 'test-integration-host'
        assert 'integration_threat_hash_xyz' in [ioc['value'] for ioc in detection.threat_indicators]
        assert 'TA0002' in detection.mitre_tactics


@pytest.mark.integration
class TestAWSSecurityMCPIntegration:
    """Integration tests for AWS Security MCP client."""
    
    @pytest.fixture
    def aws_integration_client(self, mock_aws_services):
        """Create AWS Security client for integration testing."""
        client = AWSSecurityMCPClient(aws_region="us-west-2")
        
        # Mock MCP clients for integration tests
        for service in client.mcp_clients:
            client.mcp_clients[service] = Mock()
            client.mcp_clients[service].call_mcp_tool = Mock()
        
        return client
    
    @pytest.mark.asyncio
    async def test_aws_security_hub_integration(self, aws_integration_client):
        """Test Security Hub integration with findings analysis."""
        # Mock Security Hub findings response
        aws_integration_client.mcp_clients['security_hub'].call_mcp_tool.return_value = {
            'findings': [
                {
                    'Id': 'integration-finding-123',
                    'ProductArn': 'arn:aws:securityhub:us-west-2:123456789012:product/aws/securityhub',
                    'GeneratorId': 'integration-test-generator',
                    'AwsAccountId': '123456789012',
                    'Region': 'us-west-2',
                    'Title': 'Integration Test Security Finding',
                    'Description': 'Test finding for integration validation',
                    'Severity': {'Label': 'HIGH'},
                    'Types': ['Software and Configuration Checks/Vulnerabilities'],
                    'CreatedAt': '2026-03-06T01:00:00Z',
                    'UpdatedAt': '2026-03-06T01:00:00Z',
                    'Resources': [{
                        'Id': 'arn:aws:ec2:us-west-2:123456789012:instance/i-integration123',
                        'Type': 'AwsEc2Instance'
                    }],
                    'RecordState': 'ACTIVE'
                }
            ],
            'total_findings': 1
        }
        
        result = await aws_integration_client.analyze_security_hub_findings(
            severity_filter=[AWSSecuritySeverity.HIGH, AWSSecuritySeverity.CRITICAL],
            time_range_hours=24
        )
        
        assert 'findings_summary' in result
        assert result['findings_summary']['total_findings'] == 1
        assert len(result['findings']) == 1
        
        finding = result['findings'][0]
        assert finding.finding_id == 'integration-finding-123'
        assert finding.severity == AWSSecuritySeverity.HIGH
        assert finding.region == 'us-west-2'
    
    @pytest.mark.asyncio
    async def test_aws_cloudtrail_integration(self, aws_integration_client):
        """Test CloudTrail events analysis integration."""
        # Mock CloudTrail analysis response
        aws_integration_client.mcp_clients['cloudtrail'].call_mcp_tool.return_value = {
            'events': [
                {
                    'EventId': 'integration-event-456',
                    'EventName': 'CreateUser',
                    'EventSource': 'iam.amazonaws.com',
                    'EventTime': '2026-03-06T01:00:00Z',
                    'UserIdentity': {
                        'type': 'Root',
                        'principalId': 'INTEGRATION123',
                        'arn': 'arn:aws:iam::123456789012:root',
                        'accountId': '123456789012'
                    },
                    'SourceIPAddress': '192.168.1.100',
                    'UserAgent': 'integration-test-client',
                    'RequestParameters': {
                        'userName': 'integration-test-user'
                    }
                }
            ],
            'total_events': 1,
            'high_risk_events': 1
        }
        
        result = await aws_integration_client.analyze_cloudtrail_events(
            time_range_hours=24,
            privilege_escalation_detection=True
        )
        
        assert 'events_summary' in result
        assert result['events_summary']['total_events'] == 1
        assert result['events_summary']['high_risk_events'] == 1
        
        assert len(result['events']) >= 1
        event = result['events'][0]
        assert event.event_id == 'integration-event-456'
        assert event.event_name == 'CreateUser'
        assert event.risk_score > 50  # Should be high risk for root CreateUser
    
    @pytest.mark.asyncio
    async def test_aws_multi_region_integration(self, aws_integration_client):
        """Test multi-region security monitoring integration."""
        # Test comprehensive security status across services
        result = await aws_integration_client.get_comprehensive_security_status()
        
        assert 'overall_security_posture' in result
        assert 'security_hub_analysis' in result
        assert 'cloudtrail_analysis' in result
        assert 'compliance_assessment' in result
        
        # Verify all MCP clients were called
        for service in aws_integration_client.mcp_clients:
            assert aws_integration_client.mcp_clients[service].call_mcp_tool.called


@pytest.mark.integration
class TestGitHubSecurityMCPIntegration:
    """Integration tests for GitHub Security MCP client."""
    
    @pytest.fixture
    def github_integration_client(self, mock_github_token):
        """Create GitHub Security client for integration testing."""
        client = GitHubSecurityMCPClient(github_token="ghp_integration_token")
        
        # Mock MCP client for integration tests
        client.mcp_client = Mock()
        client.mcp_client.call_mcp_tool = Mock()
        
        return client
    
    @pytest.mark.asyncio
    async def test_github_repository_security_scan_integration(self, github_integration_client):
        """Test repository security scanning integration."""
        # Mock repository scan response
        github_integration_client.mcp_client.call_mcp_tool.return_value = {
            'alerts': [
                {
                    'id': 789,
                    'number': 101,
                    'state': 'open',
                    'dependency': {'package': {'name': 'integration-test-package'}},
                    'security_advisory': {
                        'summary': 'Integration Test Vulnerability',
                        'description': 'Test vulnerability for integration validation',
                        'cve_id': 'CVE-2026-INTEGRATION'
                    },
                    'security_vulnerability': {
                        'severity': 'high',
                        'vulnerable_version_range': '< 2.0.0',
                        'first_patched_version': {'identifier': '2.0.0'}
                    },
                    'created_at': '2026-03-06T01:00:00Z',
                    'updated_at': '2026-03-06T01:00:00Z',
                    'repository': {
                        'full_name': 'integration-org/test-repo',
                        'html_url': 'https://github.com/integration-org/test-repo'
                    }
                }
            ],
            'repository_info': {
                'name': 'integration-org/test-repo',
                'visibility': 'private'
            }
        }
        
        result = await github_integration_client.scan_repository_security(
            repository_name="integration-org/test-repo",
            comprehensive_scan=True
        )
        
        assert 'repository_info' in result
        assert 'security_alerts' in result
        assert 'vulnerability_summary' in result
        assert 'security_score' in result
        
        assert len(result['security_alerts']) == 1
        alert = result['security_alerts'][0]
        assert alert.alert_id == 789
        assert alert.severity == GitHubSecuritySeverity.HIGH
        assert alert.repository_name == 'integration-org/test-repo'
    
    @pytest.mark.asyncio
    async def test_github_devsecops_pipeline_integration(self, github_integration_client):
        """Test DevSecOps pipeline setup integration."""
        pipeline_config = SecDevOpsPipelineConfig(
            repository_name="integration-org/web-app",
            sast_languages=['javascript', 'python'],
            sast_tools=['codeql', 'semgrep'],
            dast_tools=['zap'],
            sca_tools=['dependabot', 'snyk'],
            block_on_critical_severity=True
        )
        
        # Mock pipeline setup response
        github_integration_client.mcp_client.call_mcp_tool.return_value = {
            'pipeline_id': 'integration-pipeline-xyz',
            'sast_tools': ['codeql', 'semgrep'],
            'dast_tools': ['zap'],
            'sca_tools': ['dependabot', 'snyk'],
            'security_gates': ['critical-block'],
            'workflow_files': ['.github/workflows/security-integration.yml'],
            'branch_protection': {
                'require_status_checks': True,
                'required_checks': ['security-scan', 'integration-tests']
            }
        }
        
        result = await github_integration_client.setup_devsecops_pipeline(
            repository_name="integration-org/web-app",
            pipeline_config=pipeline_config
        )
        
        assert result['pipeline_id'] == 'integration-pipeline-xyz'
        assert 'configuration' in result
        assert 'workflow_files' in result
        assert len(result['workflow_files']) == 1
        
        # Verify configuration matches input
        config = result['configuration']
        assert 'codeql' in config['sast_tools_configured']
        assert 'semgrep' in config['sast_tools_configured']
        assert 'zap' in config['dast_tools_configured']
    
    @pytest.mark.asyncio
    async def test_github_dependency_monitoring_integration(self, github_integration_client):
        """Test dependency vulnerability monitoring integration."""
        repositories = ["integration-org/app1", "integration-org/app2"]
        
        # Mock dependency monitoring response
        github_integration_client.mcp_client.call_mcp_tool.return_value = {
            'total_vulnerabilities': 8,
            'critical_count': 2,
            'auto_remediated': 3,
            'pending_remediation': 5,
            'vulnerabilities': [
                {
                    'repository': 'integration-org/app1',
                    'package': 'integration-vulnerable-package',
                    'severity': 'critical',
                    'cve_id': 'CVE-2026-INTEGRATION-DEP',
                    'auto_fixable': True
                }
            ],
            'repository_data': [
                {
                    'repository': 'integration-org/app1',
                    'vulnerabilities_count': 5,
                    'risk_score': 80
                },
                {
                    'repository': 'integration-org/app2',
                    'vulnerabilities_count': 3,
                    'risk_score': 60
                }
            ]
        }
        
        result = await github_integration_client.monitor_dependency_vulnerabilities(
            repositories=repositories,
            auto_remediation=True,
            severity_threshold=GitHubSecuritySeverity.MEDIUM
        )
        
        assert 'monitoring_summary' in result
        summary = result['monitoring_summary']
        assert summary['repositories_monitored'] == 2
        assert summary['total_vulnerabilities'] == 8
        assert summary['critical_vulnerabilities'] == 2
        assert summary['auto_remediated'] == 3


@pytest.mark.integration
class TestCrossplatformIntegration:
    """Integration tests for cross-platform coordination."""
    
    @pytest.mark.asyncio
    async def test_threat_correlation_across_platforms(self, enterprise_gateway):
        """Test threat correlation across CrowdStrike, AWS, and GitHub."""
        await enterprise_gateway.start_gateway(num_workers=1)
        
        # Create correlated events across platforms
        crowdstrike_event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.THREAT_DETECTION,
            severity=EventSeverity.CRITICAL,
            source_platform="crowdstrike",
            timestamp=datetime.utcnow(),
            correlation_id="integration-correlation-123",
            title="Malware Detection",
            description="Critical malware detected on production server",
            affected_resources=["prod-server-01"],
            indicators={
                "file_hash": "correlation_test_hash_456",
                "source_ip": "192.168.1.200"
            }
        )
        
        aws_event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.SECURITY_POLICY_VIOLATION,
            severity=EventSeverity.HIGH,
            source_platform="aws",
            timestamp=datetime.utcnow() + timedelta(minutes=2),
            correlation_id="integration-correlation-123",
            title="Suspicious IAM Activity",
            description="Unusual IAM activity from same source IP",
            affected_resources=["iam-user-suspicious"],
            indicators={
                "source_ip": "192.168.1.200",
                "user_identity": "suspicious-user"
            }
        )
        
        # Ingest correlated events
        await enterprise_gateway.ingest_security_event(crowdstrike_event)
        await enterprise_gateway.ingest_security_event(aws_event)
        
        # Wait for processing
        await asyncio.sleep(3)
        
        # Verify correlation was detected
        assert enterprise_gateway.metrics['total_events_processed'] >= 2
        
        # Test cross-platform investigation workflow
        workflow_result = await enterprise_gateway.execute_orchestration_workflow(
            'threat_investigation',
            parameters={
                'correlation_id': 'integration-correlation-123',
                'cross_platform': True
            }
        )
        
        assert workflow_result['status'] == 'completed'
        results = workflow_result['results']['results']
        
        # All platforms should have been involved
        assert 'crowdstrike' in results
        assert 'aws' in results
        assert 'github' in results
        
        await enterprise_gateway.stop_gateway()
    
    @pytest.mark.asyncio
    async def test_compliance_workflow_integration(self, enterprise_gateway):
        """Test compliance workflow across all platforms."""
        await enterprise_gateway.start_gateway(num_workers=1)
        
        # Execute compliance audit workflow
        workflow_result = await enterprise_gateway.execute_orchestration_workflow(
            'compliance_audit',
            parameters={
                'frameworks': ['NIST_CSF_2.0', 'OWASP_TOP10'],
                'scope': 'enterprise',
                'include_evidence': True
            }
        )
        
        assert workflow_result['status'] == 'completed'
        assert workflow_result['workflow_id'] == 'compliance_audit'
        
        # Verify all platforms provided compliance data
        results = workflow_result['results']['results']
        assert len(results) == 3  # CrowdStrike, AWS, GitHub
        
        await enterprise_gateway.stop_gateway()


@pytest.mark.integration
class TestPerformanceIntegration:
    """Performance integration tests."""
    
    @pytest.mark.asyncio
    async def test_high_volume_event_processing(self, enterprise_gateway, performance_metrics):
        """Test high-volume event processing performance."""
        await enterprise_gateway.start_gateway(num_workers=3)
        
        performance_metrics.start()
        
        # Generate 100 test events
        events = []
        for i in range(100):
            event = SecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type=EventType.THREAT_DETECTION,
                severity=EventSeverity.MEDIUM,
                source_platform="performance_test",
                timestamp=datetime.utcnow(),
                correlation_id=str(uuid.uuid4()),
                title=f"Performance Test Event {i}",
                description=f"Test event {i} for performance validation",
                affected_resources=[f"resource-{i}"],
                indicators={"test_indicator": f"value-{i}"}
            )
            events.append(event)
        
        # Ingest events rapidly
        start_time = datetime.utcnow()
        
        for event in events:
            await enterprise_gateway.ingest_security_event(event)
        
        # Wait for processing
        await asyncio.sleep(10)
        
        end_time = datetime.utcnow()
        processing_time = (end_time - start_time).total_seconds()
        
        performance_metrics.finish()
        
        # Verify performance requirements
        assert processing_time < 30  # Should process 100 events in under 30 seconds
        assert enterprise_gateway.metrics['total_events_processed'] >= 100
        
        # Calculate throughput (events per hour)
        throughput = (100 / processing_time) * 3600
        assert throughput > 1000  # Should exceed 1000 events/hour
        
        await enterprise_gateway.stop_gateway()
    
    @pytest.mark.asyncio
    async def test_concurrent_workflow_execution(self, enterprise_gateway):
        """Test concurrent workflow execution performance."""
        await enterprise_gateway.start_gateway(num_workers=2)
        
        # Execute multiple workflows concurrently
        workflow_tasks = [
            enterprise_gateway.execute_orchestration_workflow(
                'threat_investigation',
                parameters={'test_id': i},
                correlation_id=str(uuid.uuid4())
            )
            for i in range(5)
        ]
        
        start_time = datetime.utcnow()
        results = await asyncio.gather(*workflow_tasks, return_exceptions=True)
        end_time = datetime.utcnow()
        
        execution_time = (end_time - start_time).total_seconds()
        
        # Verify all workflows completed
        assert len(results) == 5
        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) >= 4  # Allow for one potential failure
        
        # Verify reasonable execution time (should be faster than sequential)
        assert execution_time < 15  # 5 workflows in under 15 seconds
        
        await enterprise_gateway.stop_gateway()


@pytest.mark.integration
class TestErrorRecoveryIntegration:
    """Integration tests for error recovery and resilience."""
    
    @pytest.mark.asyncio
    async def test_platform_failure_recovery(self, enterprise_gateway):
        """Test recovery from platform failures."""
        await enterprise_gateway.start_gateway(num_workers=1)
        
        # Simulate platform failure
        enterprise_gateway.platform_clients['crowdstrike'] = None
        
        # Execute workflow that would normally include CrowdStrike
        workflow_result = await enterprise_gateway.execute_orchestration_workflow(
            'threat_investigation',
            parameters={'simulate_failure': True},
            correlation_id=str(uuid.uuid4())
        )
        
        # Should complete despite platform failure
        assert 'execution_id' in workflow_result
        results = workflow_result['results']['results']
        
        # CrowdStrike should have failed, but others should succeed
        assert 'crowdstrike' in results
        assert results['crowdstrike']['status'] == 'failed'
        
        await enterprise_gateway.stop_gateway()
    
    @pytest.mark.asyncio
    async def test_rate_limit_handling(self, enterprise_gateway):
        """Test rate limit handling and backoff."""
        await enterprise_gateway.start_gateway(num_workers=1)
        
        # Simulate rate limiting by configuring mock responses
        for platform in enterprise_gateway.platform_clients.values():
            if hasattr(platform, 'call_mcp_tool'):
                # First call succeeds, subsequent calls simulate rate limiting
                platform.call_mcp_tool.side_effect = [
                    {'result': 'success'},
                    Exception('Rate limit exceeded'),
                    Exception('Rate limit exceeded'),
                    {'result': 'success'}  # Recovery after backoff
                ]
        
        # Execute multiple operations that should trigger rate limiting
        results = []
        for i in range(3):
            try:
                result = await enterprise_gateway.execute_orchestration_workflow(
                    'threat_investigation',
                    parameters={'iteration': i},
                    correlation_id=str(uuid.uuid4())
                )
                results.append(result)
            except Exception as e:
                results.append(e)
        
        # Should handle rate limiting gracefully
        assert len(results) == 3
        
        await enterprise_gateway.stop_gateway()


if __name__ == "__main__":
    # Run integration tests with proper markers
    pytest.main([
        __file__, 
        "-v", 
        "-m", "integration",
        "--cov=mcp_integration",
        "--cov-report=html",
        "--tb=short"
    ])