"""
SecurityAgents MCP Integration Testing Configuration

Enterprise testing framework configuration for comprehensive test coverage
of CrowdStrike, AWS, and GitHub MCP integrations.

P0 Testing Infrastructure for Production Deployment Validation
"""

import asyncio
import json
import pytest
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Generator, AsyncGenerator
from unittest.mock import AsyncMock, Mock, patch

import boto3
import aioresponses
import requests_mock
from moto import mock_dynamodb, mock_s3, mock_ssm, mock_sns, mock_cloudwatch

# Test fixtures for MCP integration testing
from mcp_integration.gateway.mcp_server_manager import MCPServerConfig, MCPServerManager
from mcp_integration.gateway.enterprise_mcp_gateway import (
    SecurityEvent, EventType, EventSeverity, EnterpriseSecurityMCPGateway
)


# Pytest configuration
pytest_plugins = ['pytest_asyncio']


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_aws_credentials():
    """Mock AWS credentials for testing."""
    with patch.dict('os.environ', {
        'AWS_ACCESS_KEY_ID': 'testing',
        'AWS_SECRET_ACCESS_KEY': 'testing',
        'AWS_SECURITY_TOKEN': 'testing',
        'AWS_SESSION_TOKEN': 'testing',
        'AWS_DEFAULT_REGION': 'us-west-2'
    }):
        yield


@pytest.fixture
def mock_github_token():
    """Mock GitHub token for testing."""
    with patch.dict('os.environ', {
        'GITHUB_TOKEN': 'ghp_test_token_1234567890abcdef'
    }):
        yield


@pytest.fixture
def mock_crowdstrike_credentials():
    """Mock CrowdStrike credentials for testing."""
    return {
        'client_id': 'test_client_id',
        'client_secret': 'test_client_secret',
        'token_url': 'https://api.crowdstrike.com/oauth2/token'
    }


@pytest.fixture
def sample_security_event():
    """Create a sample security event for testing."""
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        event_type=EventType.THREAT_DETECTION,
        severity=EventSeverity.HIGH,
        source_platform="crowdstrike",
        timestamp=datetime.utcnow(),
        correlation_id=str(uuid.uuid4()),
        title="Test Threat Detection",
        description="Sample threat detection for testing",
        affected_resources=["test-resource-01", "test-resource-02"],
        indicators={
            "file_hash": "a1b2c3d4e5f6789012345678901234567890abcd",
            "process_name": "test_malware.exe",
            "source_ip": "192.168.1.100"
        },
        environment="test"
    )


@pytest.fixture
def crowdstrike_config():
    """Create CrowdStrike MCP configuration for testing."""
    return MCPServerConfig(
        server_name="crowdstrike_falcon_test",
        server_url="https://api.crowdstrike.com/mcp",
        auth_type="oauth2",
        max_requests_per_minute=30,
        max_requests_per_hour=1000,
        burst_limit=5,
        request_timeout=30,
        auth_config={
            'token_url': 'https://api.crowdstrike.com/oauth2/token',
            'scope': 'falcon-intel:read falcon-devices:read'
        }
    )


@pytest.fixture
def aws_config():
    """Create AWS MCP configuration for testing."""
    return MCPServerConfig(
        server_name="aws_security_test",
        server_url="mcp://aws-security-hub",
        auth_type="iam",
        aws_region="us-west-2"
    )


@pytest.fixture
def github_config():
    """Create GitHub MCP configuration for testing."""
    return MCPServerConfig(
        server_name="github_security_test",
        server_url="mcp://github-security",
        auth_type="api_key",
        auth_config={'token': 'ghp_test_token'}
    )


@pytest.fixture
def mock_crowdstrike_fql_response():
    """Mock CrowdStrike FQL query response."""
    return {
        'meta': {
            'query_time': 0.123,
            'powered_by': 'falcon-data-replicator',
            'trace_id': 'test-trace-123'
        },
        'data': [
            {
                'aid': 'test-aid-123',
                'cid': 'test-cid-456',
                'timestamp': '2026-03-06T01:00:00Z',
                'event_simpleName': 'ProcessRollup2',
                'ProcessId': 1234,
                'ParentProcessId': 5678,
                'CommandLine': 'test.exe --arg',
                'ImageFileName': 'test.exe',
                'SHA256HashData': 'a1b2c3d4e5f6789012345678901234567890abcd'
            }
        ],
        'errors': [],
        'pagination': {
            'offset': 0,
            'limit': 1000,
            'total': 1
        }
    }


@pytest.fixture
def mock_aws_security_hub_response():
    """Mock AWS Security Hub findings response."""
    return {
        'Findings': [
            {
                'Id': 'test-finding-123',
                'ProductArn': 'arn:aws:securityhub:us-west-2:123456789012:product/aws/securityhub',
                'GeneratorId': 'test-generator',
                'AwsAccountId': '123456789012',
                'Region': 'us-west-2',
                'Title': 'Test Security Finding',
                'Description': 'Test security finding for unit testing',
                'Severity': {
                    'Label': 'HIGH',
                    'Normalized': 70
                },
                'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
                'CreatedAt': '2026-03-06T01:00:00Z',
                'UpdatedAt': '2026-03-06T01:00:00Z',
                'Resources': [
                    {
                        'Id': 'arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0',
                        'Type': 'AwsEc2Instance',
                        'Region': 'us-west-2'
                    }
                ],
                'RecordState': 'ACTIVE',
                'WorkflowState': 'NEW'
            }
        ]
    }


@pytest.fixture
def mock_github_security_alerts_response():
    """Mock GitHub security alerts response."""
    return [
        {
            'id': 123,
            'number': 456,
            'state': 'open',
            'dependency': {
                'package': {
                    'name': 'lodash'
                }
            },
            'security_advisory': {
                'summary': 'Prototype Pollution in lodash',
                'description': 'Test vulnerability description',
                'cve_id': 'CVE-2021-23337',
                'cvss': {
                    'score': 7.3
                }
            },
            'security_vulnerability': {
                'severity': 'high',
                'vulnerable_version_range': '< 4.17.12',
                'first_patched_version': {
                    'identifier': '4.17.12'
                }
            },
            'created_at': '2026-03-06T01:00:00Z',
            'updated_at': '2026-03-06T01:00:00Z',
            'repository': {
                'full_name': 'test-org/test-repo',
                'html_url': 'https://github.com/test-org/test-repo'
            }
        }
    ]


@pytest.fixture
def mock_cloudtrail_events():
    """Mock AWS CloudTrail events for testing."""
    return {
        'Events': [
            {
                'EventId': 'test-event-123',
                'EventName': 'AssumeRole',
                'EventSource': 'sts.amazonaws.com',
                'EventTime': datetime.utcnow(),
                'UserIdentity': {
                    'type': 'AssumedRole',
                    'principalId': 'AIDAI23HZ27SI6FQMGNQ2',
                    'arn': 'arn:aws:sts::123456789012:assumed-role/test-role/test-session',
                    'accountId': '123456789012',
                    'userName': 'test-user'
                },
                'SourceIPAddress': '192.168.1.100',
                'UserAgent': 'aws-cli/2.1.0',
                'RequestParameters': {
                    'roleArn': 'arn:aws:iam::123456789012:role/test-role',
                    'roleSessionName': 'test-session'
                },
                'ResponseElements': {
                    'credentials': {
                        'accessKeyId': 'ASIAX...',
                        'sessionToken': 'token...'
                    }
                }
            }
        ]
    }


@pytest.fixture
def mock_http_responses():
    """Mock HTTP responses for external API calls."""
    with aioresponses.aioresponses() as m:
        # CrowdStrike OAuth token endpoint
        m.post(
            'https://api.crowdstrike.com/oauth2/token',
            payload={
                'access_token': 'test_access_token',
                'token_type': 'bearer',
                'expires_in': 3600
            }
        )
        
        # CrowdStrike MCP endpoints
        m.post(
            'https://api.crowdstrike.com/mcp',
            payload={'status': 'success', 'result': 'test_result'}
        )
        
        # GitHub API endpoints
        m.post(
            'mcp://github-security',
            payload={'status': 'success', 'result': 'github_test_result'}
        )
        
        yield m


@pytest.fixture
def mock_aws_services(mock_aws_credentials):
    """Mock AWS services using moto."""
    with mock_dynamodb(), mock_s3(), mock_ssm(), mock_sns(), mock_cloudwatch():
        # Create test SSM parameters
        ssm = boto3.client('ssm', region_name='us-west-2')
        ssm.put_parameter(
            Name='/secops/crowdstrike/client_id',
            Value='test_client_id',
            Type='SecureString'
        )
        ssm.put_parameter(
            Name='/secops/crowdstrike/client_secret',
            Value='test_client_secret',
            Type='SecureString'
        )
        ssm.put_parameter(
            Name='/secops/github/token',
            Value='ghp_test_token',
            Type='SecureString'
        )
        
        # Create test DynamoDB table
        dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
        table = dynamodb.create_table(
            TableName='secops-events',
            KeySchema=[
                {'AttributeName': 'event_id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'event_id', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        
        # Create test SNS topics
        sns = boto3.client('sns', region_name='us-west-2')
        sns.create_topic(Name='secops-critical')
        sns.create_topic(Name='secops-high')
        
        yield


@pytest.fixture
async def enterprise_gateway(mock_aws_services, mock_github_token):
    """Create Enterprise MCP Gateway for testing."""
    gateway = EnterpriseSecurityMCPGateway(
        aws_region="us-west-2",
        github_token="ghp_test_token"
    )
    
    # Mock the platform clients to avoid real API calls
    gateway.platform_clients = {
        'crowdstrike': AsyncMock(),
        'aws': AsyncMock(),
        'github': AsyncMock()
    }
    
    yield gateway
    
    # Cleanup
    if hasattr(gateway, 'stop_gateway'):
        await gateway.stop_gateway()


@pytest.fixture
def performance_test_events():
    """Generate events for performance testing."""
    events = []
    event_types = list(EventType)
    severities = list(EventSeverity)
    
    for i in range(1000):
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_types[i % len(event_types)],
            severity=severities[i % len(severities)],
            source_platform="test",
            timestamp=datetime.utcnow(),
            correlation_id=str(uuid.uuid4()),
            title=f"Test Event {i}",
            description=f"Performance test event number {i}",
            affected_resources=[f"resource-{i}"],
            indicators={"test_indicator": f"value-{i}"}
        )
        events.append(event)
    
    return events


@pytest.fixture
def mock_rate_limiter():
    """Mock rate limiter for testing."""
    with patch('mcp_integration.gateway.mcp_server_manager.RateLimiter') as mock:
        mock_instance = Mock()
        mock_instance.acquire = AsyncMock(return_value=True)
        mock_instance.get_wait_time = Mock(return_value=0)
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_circuit_breaker():
    """Mock circuit breaker for testing."""
    with patch('mcp_integration.gateway.mcp_server_manager.CircuitBreaker') as mock:
        mock_instance = Mock()
        mock_instance.can_request = Mock(return_value=True)
        mock_instance.record_success = Mock()
        mock_instance.record_failure = Mock()
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def test_data_dir(tmp_path):
    """Create temporary directory for test data."""
    data_dir = tmp_path / "test_data"
    data_dir.mkdir()
    return data_dir


@pytest.fixture
def load_test_config():
    """Configuration for load testing."""
    return {
        'users': 50,
        'spawn_rate': 10,
        'run_time': '60s',
        'target_rps': 100,
        'max_response_time': 5.0
    }


# Utility functions for testing
def create_test_event(event_type: EventType = EventType.THREAT_DETECTION,
                     severity: EventSeverity = EventSeverity.HIGH) -> SecurityEvent:
    """Create a test security event."""
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        severity=severity,
        source_platform="test",
        timestamp=datetime.utcnow(),
        correlation_id=str(uuid.uuid4()),
        title="Test Event",
        description="Test security event",
        affected_resources=["test-resource"],
        indicators={"test": "indicator"}
    )


def assert_security_event_valid(event: SecurityEvent):
    """Assert that a security event is valid."""
    assert event.event_id
    assert event.event_type in EventType
    assert event.severity in EventSeverity
    assert event.source_platform
    assert event.timestamp
    assert event.correlation_id
    assert event.title
    assert event.description


# Performance testing utilities
class PerformanceMetrics:
    """Collect and analyze performance metrics during testing."""
    
    def __init__(self):
        self.response_times = []
        self.error_count = 0
        self.success_count = 0
        self.start_time = None
        self.end_time = None
    
    def start(self):
        self.start_time = datetime.utcnow()
    
    def record_response(self, response_time: float, success: bool = True):
        self.response_times.append(response_time)
        if success:
            self.success_count += 1
        else:
            self.error_count += 1
    
    def finish(self):
        self.end_time = datetime.utcnow()
    
    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def throughput(self) -> float:
        if self.duration > 0:
            return (self.success_count + self.error_count) / self.duration
        return 0.0
    
    @property
    def average_response_time(self) -> float:
        if self.response_times:
            return sum(self.response_times) / len(self.response_times)
        return 0.0
    
    @property
    def error_rate(self) -> float:
        total = self.success_count + self.error_count
        if total > 0:
            return self.error_count / total
        return 0.0


@pytest.fixture
def performance_metrics():
    """Performance metrics collector for testing."""
    return PerformanceMetrics()