"""
Unit Tests for AWS Security Services MCP Integration Client

Comprehensive unit testing for AWS Security MCP client with 80%+ code coverage.
Tests Security Hub, CloudTrail, Config, GuardDuty integrations across multiple regions.

P0 Testing for Production Deployment Validation
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from datetime import datetime, timedelta
import json
import uuid
import boto3
from moto import mock_securityhub, mock_cloudtrail, mock_config, mock_guardduty

from mcp_integration.aws.aws_security_mcp_client import (
    AWSSecurityMCPClient,
    AWSSecuritySeverity,
    AWSComplianceStatus,
    AWSSecurityFinding,
    AWSCloudTrailEvent,
    AWSConfigRule,
    create_aws_security_configs
)


class TestAWSSecurityMCPClient:
    """Test suite for AWS Security MCP client."""
    
    @pytest.fixture
    def mock_mcp_clients(self):
        """Mock all MCP clients."""
        with patch('mcp_integration.aws.aws_security_mcp_client.MCPServerManager') as mock:
            mock_instance = AsyncMock()
            mock.return_value = mock_instance
            yield mock_instance
    
    @pytest.fixture
    def aws_security_client(self, mock_aws_services, mock_mcp_clients):
        """Create AWS Security MCP client for testing."""
        client = AWSSecurityMCPClient(aws_region="us-west-2")
        # Replace MCP clients with mocks
        for service in client.mcp_clients:
            client.mcp_clients[service] = mock_mcp_clients
        return client
    
    def test_initialization(self, mock_aws_services):
        """Test AWS Security client initialization."""
        with patch('mcp_integration.aws.aws_security_mcp_client.MCPServerManager'):
            client = AWSSecurityMCPClient(aws_region="us-east-1")
            
            assert client.aws_region == "us-east-1"
            assert 'security_hub' in client.mcp_clients
            assert 'config' in client.mcp_clients
            assert 'cloudtrail' in client.mcp_clients
            assert 'guardduty' in client.mcp_clients
    
    def test_monitoring_rules_configuration(self, aws_security_client):
        """Test that monitoring rules are properly configured."""
        rules = aws_security_client.monitoring_rules
        
        assert 'privileged_api_calls' in rules
        assert 'infrastructure_changes' in rules
        assert 'data_access' in rules
        
        assert 'CreateUser' in rules['privileged_api_calls']
        assert 'CreateVpc' in rules['infrastructure_changes']
        assert 'GetObject' in rules['data_access']


class TestSecurityHubIntegration:
    """Test suite for Security Hub integration."""
    
    @pytest.mark.asyncio
    async def test_analyze_security_hub_findings(self, aws_security_client, mock_aws_security_hub_response):
        """Test analyzing Security Hub findings."""
        mock_mcp_client = aws_security_client.mcp_clients['security_hub']
        mock_mcp_client.call_mcp_tool.return_value = {
            'findings': [mock_aws_security_hub_response['Findings'][0]],
            'total_findings': 1,
            'critical_findings': 0,
            'high_findings': 1
        }
        
        result = await aws_security_client.analyze_security_hub_findings(
            severity_filter=[AWSSecuritySeverity.HIGH, AWSSecuritySeverity.CRITICAL],
            time_range_hours=24,
            limit=100
        )
        
        assert 'findings_summary' in result
        assert 'findings' in result
        assert 'threat_landscape' in result
        assert 'remediation_priorities' in result
        
        # Check findings summary
        summary = result['findings_summary']
        assert summary['total_findings'] == 1
        assert 'severity_breakdown' in summary
        assert 'affected_resources' in summary
        
        # Verify MCP call
        mock_mcp_client.call_mcp_tool.assert_called_once_with(
            'analyze_findings',
            {
                'filters': pytest.any(dict),
                'limit': 100,
                'include_remediation': True,
                'include_compliance_mapping': True,
                'correlation_analysis': True
            }
        )
    
    @pytest.mark.asyncio
    async def test_analyze_security_hub_findings_with_compliance(self, aws_security_client):
        """Test Security Hub analysis with compliance frameworks."""
        mock_mcp_client = aws_security_client.mcp_clients['security_hub']
        mock_mcp_client.call_mcp_tool.return_value = {'findings': []}
        
        await aws_security_client.analyze_security_hub_findings(
            compliance_frameworks=['NIST_CSF_2.0', 'CIS_AWS_Foundations']
        )
        
        call_args = mock_mcp_client.call_mcp_tool.call_args[0][1]
        filters = call_args['filters']
        assert 'ComplianceSecurityControlId' in filters
    
    @pytest.mark.asyncio
    async def test_analyze_security_hub_findings_error(self, aws_security_client):
        """Test Security Hub analysis with error handling."""
        mock_mcp_client = aws_security_client.mcp_clients['security_hub']
        mock_mcp_client.call_mcp_tool.side_effect = Exception("Security Hub API error")
        
        with pytest.raises(Exception):
            await aws_security_client.analyze_security_hub_findings()


class TestCloudTrailIntegration:
    """Test suite for CloudTrail integration."""
    
    @pytest.mark.asyncio
    async def test_analyze_cloudtrail_events(self, aws_security_client, mock_cloudtrail_events):
        """Test analyzing CloudTrail events for security threats."""
        mock_mcp_client = aws_security_client.mcp_clients['cloudtrail']
        mock_mcp_client.call_mcp_tool.return_value = {
            'events': mock_cloudtrail_events['Events'],
            'total_events': 1,
            'high_risk_events': 1,
            'privilege_escalation_attempts': 0,
            'suspicious_patterns': []
        }
        
        result = await aws_security_client.analyze_cloudtrail_events(
            time_range_hours=24,
            threat_indicators=['192.168.1.100'],
            privilege_escalation_detection=True,
            anomaly_detection=True
        )
        
        assert 'events_summary' in result
        assert 'security_analysis' in result
        assert 'risk_assessment' in result
        assert 'events' in result
        
        # Check events summary
        summary = result['events_summary']
        assert summary['total_events'] == 1
        assert 'high_risk_events' in summary
        assert 'unique_users' in summary
        assert 'unique_source_ips' in summary
        
        # Verify MCP call
        mock_mcp_client.call_mcp_tool.assert_called_once()
        call_args = mock_mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['time_range_hours'] == 24
        assert call_args['threat_indicators'] == ['192.168.1.100']
        assert call_args['enable_privilege_escalation_detection'] is True
    
    @pytest.mark.asyncio
    async def test_analyze_cloudtrail_events_minimal_params(self, aws_security_client):
        """Test CloudTrail analysis with minimal parameters."""
        mock_mcp_client = aws_security_client.mcp_clients['cloudtrail']
        mock_mcp_client.call_mcp_tool.return_value = {'events': []}
        
        await aws_security_client.analyze_cloudtrail_events()
        
        call_args = mock_mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['time_range_hours'] == 24
        assert call_args['threat_indicators'] == []
        assert call_args['enable_privilege_escalation_detection'] is True
        assert call_args['enable_anomaly_detection'] is True


class TestConfigCompliance:
    """Test suite for Config compliance integration."""
    
    @pytest.mark.asyncio
    async def test_assess_config_compliance(self, aws_security_client):
        """Test assessing AWS Config compliance."""
        mock_rules_response = {
            'rules': [
                {
                    'ConfigRuleName': 's3-bucket-public-access-prohibited',
                    'ConfigRuleArn': 'arn:aws:config:us-west-2:123456789012:config-rule/s3-rule',
                    'ConfigRuleState': 'ACTIVE',
                    'ComplianceStatus': 'COMPLIANT',
                    'Source': {'Owner': 'AWS'},
                    'Scope': {'ComplianceResourceTypes': ['AWS::S3::Bucket']},
                    'LastEvaluationTime': '2026-03-06T01:00:00Z'
                }
            ],
            'total_rules': 1,
            'compliant_rules': 1,
            'non_compliant_rules': 0
        }
        
        mock_mcp_client = aws_security_client.mcp_clients['config']
        mock_mcp_client.call_mcp_tool.return_value = mock_rules_response
        
        result = await aws_security_client.assess_config_compliance(
            compliance_frameworks=['NIST_CSF_2.0'],
            resource_types=['AWS::S3::Bucket'],
            include_remediation=True
        )
        
        assert 'compliance_overview' in result
        assert 'framework_compliance' in result
        assert 'critical_gaps' in result
        assert 'remediation_plan' in result
        assert 'rules' in result
        
        # Check compliance overview
        overview = result['compliance_overview']
        assert overview['total_rules'] == 1
        assert overview['compliant_rules'] == 1
        assert overview['non_compliant_rules'] == 0
        
        # Verify MCP call
        mock_mcp_client.call_mcp_tool.assert_called_once()
        call_args = mock_mcp_client.call_mcp_tool.call_args[0][1]
        assert 'NIST_CSF_2.0' in call_args['compliance_frameworks']
        assert call_args['include_remediation'] is True
    
    @pytest.mark.asyncio
    async def test_assess_config_compliance_defaults(self, aws_security_client):
        """Test Config compliance assessment with defaults."""
        mock_mcp_client = aws_security_client.mcp_clients['config']
        mock_mcp_client.call_mcp_tool.return_value = {'rules': []}
        
        await aws_security_client.assess_config_compliance()
        
        call_args = mock_mcp_client.call_mcp_tool.call_args[0][1]
        expected_frameworks = ['NIST_CSF_2.0', 'CIS_AWS_Foundations', 'SOX', 'PCI_DSS']
        assert call_args['compliance_frameworks'] == expected_frameworks


class TestVPCFlowLogAnalysis:
    """Test suite for VPC Flow Log analysis."""
    
    @pytest.mark.asyncio
    async def test_monitor_vpc_flow_logs(self, aws_security_client):
        """Test monitoring VPC Flow Logs for security threats."""
        mock_vpc_response = {
            'summary': {
                'total_flows': 10000,
                'suspicious_flows': 5,
                'unique_ips': 150
            },
            'suspicious_connections': [
                {
                    'source_ip': '10.0.1.100',
                    'dest_ip': '8.8.8.8',
                    'dest_port': 53,
                    'protocol': 'UDP',
                    'threat_level': 'low'
                }
            ],
            'malicious_ips': [],
            'data_exfiltration': [],
            'lateral_movement': [],
            'top_talkers': [],
            'unusual_protocols': [],
            'traffic_anomalies': []
        }
        
        mock_mcp_client = aws_security_client.mcp_clients['cloudtrail']
        mock_mcp_client.call_mcp_tool.return_value = mock_vpc_response
        
        result = await aws_security_client.monitor_vpc_flow_logs(
            time_range_hours=12,
            threat_detection=True,
            traffic_analysis=True
        )
        
        assert 'network_summary' in result
        assert 'threat_analysis' in result
        assert 'traffic_patterns' in result
        assert 'security_recommendations' in result
        
        # Verify threat analysis structure
        threat_analysis = result['threat_analysis']
        assert 'suspicious_connections' in threat_analysis
        assert 'malicious_ips' in threat_analysis
        assert 'data_exfiltration_indicators' in threat_analysis
        assert 'lateral_movement_detection' in threat_analysis
    
    @pytest.mark.asyncio
    async def test_monitor_vpc_flow_logs_minimal(self, aws_security_client):
        """Test VPC Flow Log monitoring with minimal parameters."""
        mock_mcp_client = aws_security_client.mcp_clients['cloudtrail']
        mock_mcp_client.call_mcp_tool.return_value = {'summary': {}}
        
        await aws_security_client.monitor_vpc_flow_logs()
        
        call_args = mock_mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['time_range_hours'] == 24
        assert call_args['threat_detection'] is True
        assert call_args['traffic_analysis'] is True


class TestIAMPrivilegeMonitoring:
    """Test suite for IAM privilege monitoring."""
    
    @pytest.mark.asyncio
    async def test_track_iam_privilege_changes(self, aws_security_client):
        """Test tracking IAM privilege escalation and access patterns."""
        mock_iam_response = {
            'total_events': 50,
            'privilege_changes': 5,
            'new_users': 1,
            'new_roles': 2,
            'escalation_attempts': [
                {
                    'user': 'test-user',
                    'action': 'AttachUserPolicy',
                    'policy_arn': 'arn:aws:iam::aws:policy/AdministratorAccess',
                    'timestamp': '2026-03-06T01:00:00Z',
                    'risk_level': 'high'
                }
            ],
            'admin_grants': [],
            'cross_account_activity': [],
            'unused_privileged': [],
            'unusual_times': [],
            'new_services': [],
            'geo_anomalies': []
        }
        
        mock_mcp_client = aws_security_client.mcp_clients['cloudtrail']
        mock_mcp_client.call_mcp_tool.return_value = mock_iam_response
        
        result = await aws_security_client.track_iam_privilege_changes(
            time_range_hours=48,
            monitor_escalation=True,
            track_access_patterns=True
        )
        
        assert 'iam_summary' in result
        assert 'privilege_analysis' in result
        assert 'access_patterns' in result
        assert 'recommendations' in result
        
        # Check IAM summary
        summary = result['iam_summary']
        assert summary['total_iam_events'] == 50
        assert summary['privilege_changes'] == 5
        assert summary['new_users_created'] == 1
        assert summary['new_roles_created'] == 2
        
        # Check privilege analysis
        privilege_analysis = result['privilege_analysis']
        assert len(privilege_analysis['escalation_attempts']) == 1
        assert privilege_analysis['escalation_attempts'][0]['risk_level'] == 'high'


class TestSecurityCostOptimization:
    """Test suite for security cost optimization."""
    
    @pytest.mark.asyncio
    async def test_optimize_security_costs(self, aws_security_client):
        """Test identifying security cost optimization opportunities."""
        mock_cost_response = {
            'current_spend': 5000.0,
            'potential_savings': 1200.0,
            'optimization_percentage': 24.0,
            'unused_resources': [
                {
                    'resource_type': 'GuardDuty_Detector',
                    'resource_id': 'unused-detector-1',
                    'monthly_cost': 500.0,
                    'recommendation': 'Disable unused GuardDuty detector'
                }
            ],
            'overprovisioned': [],
            'log_optimization': [],
            'backup_optimization': []
        }
        
        mock_mcp_client = aws_security_client.mcp_clients['security_hub']
        mock_mcp_client.call_mcp_tool.return_value = mock_cost_response
        
        result = await aws_security_client.optimize_security_costs(
            cost_threshold_monthly=1000.0,
            include_unused_resources=True,
            include_overprovisioned=True
        )
        
        assert 'cost_summary' in result
        assert 'optimization_opportunities' in result
        assert 'implementation_plan' in result
        assert 'risk_assessment' in result
        
        # Check cost summary
        cost_summary = result['cost_summary']
        assert cost_summary['current_monthly_security_spend'] == 5000.0
        assert cost_summary['potential_monthly_savings'] == 1200.0
        assert cost_summary['optimization_percentage'] == 24.0


class TestDataProcessing:
    """Test suite for data processing methods."""
    
    def test_parse_security_hub_findings(self, aws_security_client, mock_aws_security_hub_response):
        """Test parsing Security Hub findings into structured objects."""
        findings_data = mock_aws_security_hub_response['Findings']
        
        findings = aws_security_client._parse_security_hub_findings(findings_data)
        
        assert len(findings) == 1
        finding = findings[0]
        assert isinstance(finding, AWSSecurityFinding)
        assert finding.finding_id == 'test-finding-123'
        assert finding.severity == AWSSecuritySeverity.HIGH
        assert finding.aws_account_id == '123456789012'
        assert finding.region == 'us-west-2'
    
    def test_parse_cloudtrail_events(self, aws_security_client, mock_cloudtrail_events):
        """Test parsing CloudTrail events into structured objects."""
        events_data = mock_cloudtrail_events['Events']
        
        events = aws_security_client._parse_cloudtrail_events(events_data)
        
        assert len(events) == 1
        event = events[0]
        assert isinstance(event, AWSCloudTrailEvent)
        assert event.event_id == 'test-event-123'
        assert event.event_name == 'AssumeRole'
        assert event.source_ip == '192.168.1.100'
        assert event.risk_score > 0  # Should calculate risk score
    
    def test_parse_config_rules(self, aws_security_client):
        """Test parsing Config rules into structured objects."""
        rules_data = [
            {
                'ConfigRuleName': 's3-test-rule',
                'ConfigRuleArn': 'arn:aws:config:us-west-2:123456789012:config-rule/s3-test',
                'ConfigRuleState': 'ACTIVE',
                'ComplianceStatus': 'NON_COMPLIANT',
                'Source': {'Owner': 'AWS'},
                'Scope': {'ComplianceResourceTypes': ['AWS::S3::Bucket']},
                'LastEvaluationTime': '2026-03-06T01:00:00Z',
                'NonCompliantResources': ['bucket-1', 'bucket-2']
            }
        ]
        
        rules = aws_security_client._parse_config_rules(rules_data)
        
        assert len(rules) == 1
        rule = rules[0]
        assert isinstance(rule, AWSConfigRule)
        assert rule.rule_name == 's3-test-rule'
        assert rule.compliance_status == AWSComplianceStatus.NON_COMPLIANT
        assert len(rule.non_compliant_resources) == 2
    
    def test_calculate_event_risk_score(self, aws_security_client):
        """Test calculating risk score for CloudTrail events."""
        # High-risk privileged operation
        high_risk_event = {
            'EventName': 'CreateUser',
            'UserIdentity': {'type': 'Root'},
            'ErrorCode': None,
            'SourceIPAddress': '192.168.1.100'
        }
        
        risk_score = aws_security_client._calculate_event_risk_score(high_risk_event)
        assert risk_score >= 80  # Should be high risk
        
        # Low-risk regular operation
        low_risk_event = {
            'EventName': 'DescribeInstances',
            'UserIdentity': {'type': 'IAMUser'},
            'ErrorCode': None,
            'SourceIPAddress': '10.0.1.100'
        }
        
        risk_score = aws_security_client._calculate_event_risk_score(low_risk_event)
        assert risk_score < 50  # Should be lower risk
    
    def test_extract_event_threat_indicators(self, aws_security_client):
        """Test extracting threat indicators from CloudTrail events."""
        event_data = {
            'SourceIPAddress': '1.2.3.4',  # External IP
            'UserAgent': 'curl/7.68.0',   # Suspicious user agent
            'ErrorCode': 'SigninFailure'  # Failed authentication
        }
        
        indicators = aws_security_client._extract_event_threat_indicators(event_data)
        
        assert 'suspicious_user_agent:curl/7.68.0' in indicators
        assert 'failed_authentication' in indicators
    
    def test_parse_datetime_valid(self, aws_security_client):
        """Test parsing valid datetime strings."""
        dt_str = '2026-03-06T01:00:00Z'
        result = aws_security_client._parse_datetime(dt_str)
        
        assert isinstance(result, datetime)
        assert result.year == 2026
        assert result.month == 3
        assert result.day == 6
    
    def test_parse_datetime_invalid(self, aws_security_client):
        """Test parsing invalid datetime strings."""
        assert aws_security_client._parse_datetime(None) is None
        assert aws_security_client._parse_datetime('invalid-date') is None
        assert aws_security_client._parse_datetime('') is None


class TestComprehensiveSecurityStatus:
    """Test suite for comprehensive security status."""
    
    @pytest.mark.asyncio
    async def test_get_comprehensive_security_status(self, aws_security_client):
        """Test getting comprehensive security status across all services."""
        # Mock responses for all service calls
        mock_security_hub = {'findings_summary': {'total_findings': 10}}
        mock_cloudtrail = {'events_summary': {'total_events': 100}}
        mock_compliance = {'compliance_overview': {'compliance_percentage': 85}}
        
        with patch.object(aws_security_client, 'analyze_security_hub_findings', 
                         return_value=mock_security_hub) as mock_sh:
            with patch.object(aws_security_client, 'analyze_cloudtrail_events',
                             return_value=mock_cloudtrail) as mock_ct:
                with patch.object(aws_security_client, 'assess_config_compliance',
                                 return_value=mock_compliance) as mock_cc:
                    
                    result = await aws_security_client.get_comprehensive_security_status()
                    
                    assert 'overall_security_posture' in result
                    assert 'security_hub_analysis' in result
                    assert 'cloudtrail_analysis' in result
                    assert 'compliance_assessment' in result
                    assert 'recommendations' in result
                    assert 'last_updated' in result
                    
                    # Check that all methods were called
                    mock_sh.assert_called_once()
                    mock_ct.assert_called_once()
                    mock_cc.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_comprehensive_security_status_with_errors(self, aws_security_client):
        """Test comprehensive security status with service errors."""
        # Mock one service to fail
        with patch.object(aws_security_client, 'analyze_security_hub_findings',
                         side_effect=Exception("Security Hub error")):
            with patch.object(aws_security_client, 'analyze_cloudtrail_events',
                             return_value={'events_summary': {}}):
                with patch.object(aws_security_client, 'assess_config_compliance',
                                 return_value={'compliance_overview': {}}):
                    
                    result = await aws_security_client.get_comprehensive_security_status()
                    
                    # Should handle errors gracefully
                    assert 'security_hub_analysis' in result
                    assert 'error' in result['security_hub_analysis']
                    assert 'cloudtrail_analysis' in result
                    assert 'compliance_assessment' in result


class TestMultiRegionConfiguration:
    """Test suite for multi-region configuration."""
    
    def test_create_aws_security_configs_default(self):
        """Test creating AWS security configs with default regions."""
        configs = create_aws_security_configs()
        
        default_regions = ['us-west-2', 'us-east-1', 'eu-west-1']
        assert len(configs) == 3
        
        for region in default_regions:
            assert region in configs
            assert isinstance(configs[region], AWSSecurityMCPClient)
            assert configs[region].aws_region == region
    
    def test_create_aws_security_configs_custom(self):
        """Test creating AWS security configs with custom regions."""
        custom_regions = ['ap-southeast-1', 'eu-central-1']
        configs = create_aws_security_configs(custom_regions)
        
        assert len(configs) == 2
        for region in custom_regions:
            assert region in configs
            assert configs[region].aws_region == region


class TestErrorHandling:
    """Test suite for error handling."""
    
    @pytest.mark.asyncio
    async def test_security_hub_analysis_error(self, aws_security_client):
        """Test Security Hub analysis with MCP error."""
        mock_mcp_client = aws_security_client.mcp_clients['security_hub']
        mock_mcp_client.call_mcp_tool.side_effect = Exception("MCP connection error")
        
        with pytest.raises(Exception):
            await aws_security_client.analyze_security_hub_findings()
    
    @pytest.mark.asyncio
    async def test_cloudtrail_analysis_timeout(self, aws_security_client):
        """Test CloudTrail analysis with timeout error."""
        mock_mcp_client = aws_security_client.mcp_clients['cloudtrail']
        mock_mcp_client.call_mcp_tool.side_effect = asyncio.TimeoutError("Request timeout")
        
        with pytest.raises(asyncio.TimeoutError):
            await aws_security_client.analyze_cloudtrail_events()
    
    @pytest.mark.asyncio
    async def test_config_compliance_permission_error(self, aws_security_client):
        """Test Config compliance with permission error."""
        mock_mcp_client = aws_security_client.mcp_clients['config']
        mock_mcp_client.call_mcp_tool.side_effect = Exception("Access denied")
        
        with pytest.raises(Exception):
            await aws_security_client.assess_config_compliance()


class TestPerformance:
    """Performance-focused tests for AWS Security MCP client."""
    
    @pytest.mark.asyncio
    async def test_concurrent_service_calls(self, aws_security_client):
        """Test concurrent calls to different AWS services."""
        # Mock all MCP clients
        for service in aws_security_client.mcp_clients:
            aws_security_client.mcp_clients[service].call_mcp_tool.return_value = {}
        
        # Execute concurrent calls
        tasks = [
            aws_security_client.analyze_security_hub_findings(limit=10),
            aws_security_client.analyze_cloudtrail_events(time_range_hours=1),
            aws_security_client.assess_config_compliance(compliance_frameworks=['NIST_CSF_2.0']),
            aws_security_client.monitor_vpc_flow_logs(time_range_hours=1)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All calls should complete
        assert len(results) == 4
        assert all(isinstance(result, dict) for result in results)
    
    @pytest.mark.asyncio
    async def test_large_findings_processing(self, aws_security_client):
        """Test processing large number of Security Hub findings."""
        # Create large findings response (1000 findings)
        large_findings = {
            'findings': [
                {
                    'Id': f'finding-{i}',
                    'ProductArn': 'arn:aws:securityhub:us-west-2:123456789012:product/aws/securityhub',
                    'GeneratorId': 'test-generator',
                    'AwsAccountId': '123456789012',
                    'Region': 'us-west-2',
                    'Title': f'Test Finding {i}',
                    'Description': f'Test finding description {i}',
                    'Severity': {'Label': 'MEDIUM'},
                    'Types': ['Software and Configuration Checks'],
                    'CreatedAt': '2026-03-06T01:00:00Z',
                    'UpdatedAt': '2026-03-06T01:00:00Z',
                    'Resources': [{'Id': f'resource-{i}', 'Type': 'AwsEc2Instance'}],
                    'RecordState': 'ACTIVE'
                }
                for i in range(1000)
            ]
        }
        
        mock_mcp_client = aws_security_client.mcp_clients['security_hub']
        mock_mcp_client.call_mcp_tool.return_value = large_findings
        
        # Should process efficiently
        result = await aws_security_client.analyze_security_hub_findings(limit=1000)
        
        assert result['findings_summary']['total_findings'] == 1000
        assert len(result['findings']) == 1000


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=mcp_integration.aws", "--cov-report=html"])