"""
Unit Tests for GitHub Security MCP Integration Client

Comprehensive unit testing for GitHub Security MCP client with 80%+ code coverage.
Tests DevSecOps pipelines, secret scanning, dependency monitoring, and compliance.

P0 Testing for Production Deployment Validation
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime, timedelta
import json
import uuid
import os

from mcp_integration.github.github_security_mcp_client import (
    GitHubSecurityMCPClient,
    GitHubSecuritySeverity,
    VulnerabilityType,
    ComplianceFramework,
    GitHubSecurityAlert,
    RepositorySecurityProfile,
    SecDevOpsPipelineConfig,
    create_github_security_config,
    create_devsecops_pipeline_config
)


class TestGitHubSecurityMCPClient:
    """Test suite for GitHub Security MCP client."""
    
    @pytest.fixture
    def mock_mcp_server_manager(self):
        """Mock MCP server manager."""
        with patch('mcp_integration.github.github_security_mcp_client.MCPServerManager') as mock:
            mock_instance = AsyncMock()
            mock.return_value = mock_instance
            yield mock_instance
    
    @pytest.fixture
    def github_client(self, mock_github_token, mock_mcp_server_manager):
        """Create GitHub Security MCP client for testing."""
        client = GitHubSecurityMCPClient(github_token="ghp_test_token")
        client.mcp_client = mock_mcp_server_manager
        return client
    
    def test_initialization(self, mock_github_token):
        """Test GitHub client initialization."""
        with patch('mcp_integration.github.github_security_mcp_client.MCPServerManager'):
            client = GitHubSecurityMCPClient(github_token="test_token")
            
            assert client.github_token == "test_token"
            assert client.enterprise_url is None
            assert len(client.security_patterns) == 3
            assert 'secrets' in client.security_patterns
            assert 'injection_vulnerabilities' in client.security_patterns
            assert 'insecure_functions' in client.security_patterns
    
    def test_initialization_with_enterprise_url(self):
        """Test GitHub client initialization with enterprise URL."""
        with patch('mcp_integration.github.github_security_mcp_client.MCPServerManager'):
            client = GitHubSecurityMCPClient(
                github_token="test_token",
                enterprise_url="https://github.enterprise.com"
            )
            
            assert client.enterprise_url == "https://github.enterprise.com"
    
    def test_security_patterns_configuration(self, github_client):
        """Test that security patterns are properly configured."""
        patterns = github_client.security_patterns
        
        # Check secrets patterns
        assert len(patterns['secrets']) >= 5
        assert any('password' in pattern.lower() for pattern in patterns['secrets'])
        assert any('api' in pattern.lower() for pattern in patterns['secrets'])
        
        # Check injection patterns
        assert len(patterns['injection_vulnerabilities']) >= 5
        assert any('eval' in pattern.lower() for pattern in patterns['injection_vulnerabilities'])
        assert any('select' in pattern.lower() for pattern in patterns['injection_vulnerabilities'])
        
        # Check insecure function patterns
        assert len(patterns['insecure_functions']) >= 5
        assert any('md5' in pattern.lower() for pattern in patterns['insecure_functions'])


class TestRepositorySecurityScanning:
    """Test suite for repository security scanning."""
    
    @pytest.mark.asyncio
    async def test_scan_repository_security_comprehensive(self, github_client, mock_github_security_alerts_response):
        """Test comprehensive repository security scanning."""
        mock_response = {
            'alerts': mock_github_security_alerts_response,
            'repository_info': {
                'name': 'test-org/test-repo',
                'visibility': 'private',
                'default_branch': 'main'
            },
            'security_features': {
                'dependency_graph_enabled': True,
                'vulnerability_alerts_enabled': True,
                'secret_scanning_enabled': True
            }
        }
        
        github_client.mcp_client.call_mcp_tool.return_value = mock_response
        
        result = await github_client.scan_repository_security(
            repository_name="test-org/test-repo",
            comprehensive_scan=True,
            include_dependencies=True,
            include_secrets=True,
            include_code_analysis=True
        )
        
        assert 'repository_info' in result
        assert 'security_alerts' in result
        assert 'vulnerability_summary' in result
        assert 'compliance_assessment' in result
        assert 'security_score' in result
        assert 'remediation_plan' in result
        
        # Verify MCP call
        github_client.mcp_client.call_mcp_tool.assert_called_once()
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['repository'] == "test-org/test-repo"
        assert call_args['scan_types']['dependency_vulnerabilities'] is True
        assert call_args['scan_types']['secret_scanning'] is True
        assert call_args['scan_types']['code_scanning'] is True
    
    @pytest.mark.asyncio
    async def test_scan_repository_security_minimal(self, github_client):
        """Test repository security scanning with minimal options."""
        github_client.mcp_client.call_mcp_tool.return_value = {'alerts': []}
        
        result = await github_client.scan_repository_security(
            repository_name="test-org/simple-repo",
            comprehensive_scan=False,
            include_dependencies=True,
            include_secrets=False,
            include_code_analysis=False
        )
        
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['scan_types']['dependency_vulnerabilities'] is True
        assert call_args['scan_types']['secret_scanning'] is False
        assert call_args['scan_types']['code_scanning'] is False
    
    @pytest.mark.asyncio
    async def test_scan_repository_security_error(self, github_client):
        """Test repository scanning with error handling."""
        github_client.mcp_client.call_mcp_tool.side_effect = Exception("Repository not found")
        
        with pytest.raises(Exception):
            await github_client.scan_repository_security("nonexistent/repo")


class TestDevSecOpsPipelineSetup:
    """Test suite for DevSecOps pipeline setup."""
    
    @pytest.fixture
    def sample_pipeline_config(self):
        """Create sample pipeline configuration."""
        return SecDevOpsPipelineConfig(
            repository_name="test-org/web-app",
            sast_languages=['javascript', 'python'],
            sast_tools=['codeql', 'semgrep'],
            dast_tools=['zap', 'nuclei'],
            sca_tools=['dependabot', 'snyk'],
            block_on_high_severity=True,
            block_on_critical_severity=True,
            required_compliance_frameworks=[ComplianceFramework.OWASP_TOP10]
        )
    
    @pytest.mark.asyncio
    async def test_setup_devsecops_pipeline(self, github_client, sample_pipeline_config):
        """Test setting up comprehensive DevSecOps pipeline."""
        mock_response = {
            'pipeline_id': 'pipeline-123',
            'sast_tools': ['codeql', 'semgrep'],
            'dast_tools': ['zap', 'nuclei'],
            'sca_tools': ['dependabot', 'snyk'],
            'security_gates': ['critical-block', 'high-block'],
            'workflow_files': ['.github/workflows/security.yml'],
            'branch_protection': {
                'require_status_checks': True,
                'required_checks': ['security-scan']
            },
            'webhooks': {
                'push_protection': True,
                'pr_checks': True
            },
            'monitoring': {
                'alerts_enabled': True,
                'notification_channels': ['slack']
            }
        }
        
        github_client.mcp_client.call_mcp_tool.return_value = mock_response
        
        result = await github_client.setup_devsecops_pipeline(
            repository_name="test-org/web-app",
            pipeline_config=sample_pipeline_config
        )
        
        assert 'pipeline_id' in result
        assert 'configuration' in result
        assert 'workflow_files' in result
        assert 'branch_protection_rules' in result
        assert 'next_steps' in result
        assert result['pipeline_id'] == 'pipeline-123'
        
        # Verify MCP call configuration
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['repository'] == "test-org/web-app"
        assert call_args['sast_config']['enabled'] is True
        assert 'codeql' in call_args['sast_config']['tools']
        assert call_args['security_gates']['block_critical_severity'] is True
    
    @pytest.mark.asyncio
    async def test_setup_devsecops_pipeline_minimal_config(self, github_client):
        """Test DevSecOps pipeline setup with minimal configuration."""
        minimal_config = SecDevOpsPipelineConfig(
            repository_name="test-org/simple-app",
            sast_enabled=False,
            dast_enabled=False,
            sca_enabled=True
        )
        
        github_client.mcp_client.call_mcp_tool.return_value = {'pipeline_id': 'minimal-123'}
        
        await github_client.setup_devsecops_pipeline(
            repository_name="test-org/simple-app",
            pipeline_config=minimal_config
        )
        
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['sast_config']['enabled'] is False
        assert call_args['dast_config']['enabled'] is False
        assert call_args['sca_config']['enabled'] is True


class TestDependencyVulnerabilityMonitoring:
    """Test suite for dependency vulnerability monitoring."""
    
    @pytest.mark.asyncio
    async def test_monitor_dependency_vulnerabilities(self, github_client):
        """Test monitoring dependency vulnerabilities across repositories."""
        repositories = ["org/repo1", "org/repo2", "org/repo3"]
        
        mock_response = {
            'total_vulnerabilities': 15,
            'critical_count': 2,
            'auto_remediated': 5,
            'pending_remediation': 10,
            'vulnerabilities': [
                {
                    'repository': 'org/repo1',
                    'package': 'lodash',
                    'severity': 'high',
                    'cve_id': 'CVE-2021-23337',
                    'auto_fixable': True
                }
            ],
            'repository_data': [
                {
                    'repository': 'org/repo1',
                    'vulnerabilities_count': 5,
                    'risk_score': 75
                }
            ],
            'remediation_actions': [
                {
                    'action': 'update_dependency',
                    'package': 'lodash',
                    'target_version': '4.17.21'
                }
            ],
            'trends': {
                'new_vulnerabilities_last_week': 3,
                'resolved_last_week': 8
            }
        }
        
        github_client.mcp_client.call_mcp_tool.return_value = mock_response
        
        result = await github_client.monitor_dependency_vulnerabilities(
            repositories=repositories,
            auto_remediation=True,
            severity_threshold=GitHubSecuritySeverity.MEDIUM
        )
        
        assert 'monitoring_summary' in result
        assert 'vulnerability_breakdown' in result
        assert 'repository_risk_scores' in result
        assert 'remediation_actions' in result
        assert 'trending_analysis' in result
        
        # Check monitoring summary
        summary = result['monitoring_summary']
        assert summary['repositories_monitored'] == 3
        assert summary['total_vulnerabilities'] == 15
        assert summary['critical_vulnerabilities'] == 2
        assert summary['auto_remediated'] == 5
        
        # Verify MCP call
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['repositories'] == repositories
        assert call_args['monitoring_config']['auto_remediation'] is True
        assert call_args['monitoring_config']['severity_threshold'] == 'medium'
    
    @pytest.mark.asyncio
    async def test_monitor_dependency_vulnerabilities_no_auto_remediation(self, github_client):
        """Test dependency monitoring without auto-remediation."""
        github_client.mcp_client.call_mcp_tool.return_value = {
            'total_vulnerabilities': 0,
            'vulnerabilities': [],
            'repository_data': [],
            'remediation_actions': []
        }
        
        await github_client.monitor_dependency_vulnerabilities(
            repositories=["org/secure-repo"],
            auto_remediation=False,
            severity_threshold=GitHubSecuritySeverity.HIGH
        )
        
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['monitoring_config']['auto_remediation'] is False
        assert call_args['monitoring_config']['severity_threshold'] == 'high'
        assert call_args['remediation_options']['auto_merge_security_updates'] is False


class TestSecurityPolicyEnforcement:
    """Test suite for security policy enforcement."""
    
    @pytest.mark.asyncio
    async def test_enforce_security_policies(self, github_client):
        """Test enforcing enterprise GitHub security policies."""
        organization = "enterprise-org"
        policy_config = {
            'require_pr_reviews': True,
            'min_reviewers': 2,
            'require_2fa': True,
            'require_sso': False,
            'enforcement_level': 'strict',
            'compliance_frameworks': ['owasp_top10', 'nist_csf']
        }
        
        mock_response = {
            'applied_policies': ['branch_protection', 'security_features', 'access_control'],
            'repositories_affected': 25,
            'compliance_score': 85,
            'successful': [
                {
                    'repository': 'enterprise-org/web-app',
                    'policies_applied': ['branch_protection', 'secret_scanning']
                }
            ],
            'failed': [
                {
                    'repository': 'enterprise-org/legacy-app',
                    'error': 'Insufficient permissions'
                }
            ],
            'exceptions': [],
            'manual_review': [
                {
                    'repository': 'enterprise-org/critical-app',
                    'reason': 'Custom security requirements'
                }
            ]
        }
        
        github_client.mcp_client.call_mcp_tool.return_value = mock_response
        
        result = await github_client.enforce_security_policies(
            organization=organization,
            policy_config=policy_config
        )
        
        assert 'policy_summary' in result
        assert 'enforcement_details' in result
        assert 'compliance_gaps' in result
        assert 'remediation_actions' in result
        
        # Check policy summary
        summary = result['policy_summary']
        assert summary['organization'] == organization
        assert summary['policies_applied'] == 3
        assert summary['repositories_affected'] == 25
        assert summary['compliance_score'] == 85
        
        # Verify MCP call
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['organization'] == organization
        assert call_args['policies']['branch_protection']['require_pull_request_reviews'] is True
        assert call_args['policies']['access_control']['two_factor_required'] is True
        assert call_args['enforcement_level'] == 'strict'
    
    @pytest.mark.asyncio
    async def test_enforce_security_policies_with_exceptions(self, github_client):
        """Test security policy enforcement with exceptions."""
        policy_config = {
            'enforcement_level': 'permissive',
            'policy_exceptions': ['legacy-repo', 'archived-project']
        }
        
        github_client.mcp_client.call_mcp_tool.return_value = {
            'applied_policies': [],
            'repositories_affected': 0,
            'exceptions': ['legacy-repo', 'archived-project']
        }
        
        await github_client.enforce_security_policies(
            organization="test-org",
            policy_config=policy_config
        )
        
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['enforcement_level'] == 'permissive'
        assert call_args['exceptions'] == ['legacy-repo', 'archived-project']


class TestComplianceReporting:
    """Test suite for compliance reporting."""
    
    @pytest.mark.asyncio
    async def test_generate_compliance_report_repository(self, github_client):
        """Test generating compliance report for repository scope."""
        mock_response = {
            'report_id': 'report-123',
            'overall_score': 88,
            'critical_findings': 2,
            'improvement_areas': ['secret_management', 'code_scanning'],
            'trend': 'improving',
            'frameworks': {
                'owasp_top10': {
                    'score': 85,
                    'compliant_controls': 8,
                    'total_controls': 10
                },
                'nist_csf': {
                    'score': 90,
                    'compliant_controls': 18,
                    'total_controls': 20
                }
            },
            'vulnerability_metrics': {
                'critical': 1,
                'high': 3,
                'medium': 8
            },
            'evidence': {
                'security_policies_enabled': True,
                'branch_protection_configured': True,
                'secret_scanning_active': True
            }
        }
        
        github_client.mcp_client.call_mcp_tool.return_value = mock_response
        
        result = await github_client.generate_compliance_report(
            scope="repository",
            target="org/secure-app",
            frameworks=[ComplianceFramework.OWASP_TOP10, ComplianceFramework.NIST_CSF],
            time_period_days=30
        )
        
        assert 'report_metadata' in result
        assert 'executive_summary' in result
        assert 'framework_assessments' in result
        assert 'security_metrics' in result
        assert 'evidence_collection' in result
        assert 'recommendations' in result
        assert 'action_plan' in result
        
        # Check report metadata
        metadata = result['report_metadata']
        assert metadata['scope'] == "repository"
        assert metadata['target'] == "org/secure-app"
        assert metadata['report_period'] == "30 days"
        
        # Check executive summary
        summary = result['executive_summary']
        assert summary['overall_compliance_score'] == 88
        assert summary['critical_findings'] == 2
        
        # Verify MCP call
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['scope'] == "repository"
        assert call_args['target'] == "org/secure-app"
        assert 'owasp_top10' in call_args['frameworks']
        assert 'nist_csf' in call_args['frameworks']
        assert call_args['time_period_days'] == 30
    
    @pytest.mark.asyncio
    async def test_generate_compliance_report_organization(self, github_client):
        """Test generating compliance report for organization scope."""
        github_client.mcp_client.call_mcp_tool.return_value = {
            'report_id': 'org-report-456',
            'overall_score': 75,
            'frameworks': {}
        }
        
        await github_client.generate_compliance_report(
            scope="organization",
            target="enterprise-org",
            frameworks=[ComplianceFramework.NIST_CSF],
            time_period_days=90
        )
        
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['scope'] == "organization"
        assert call_args['target'] == "enterprise-org"
        assert call_args['time_period_days'] == 90


class TestSecretScanningAndRemediation:
    """Test suite for secret scanning and remediation."""
    
    @pytest.mark.asyncio
    async def test_automate_secret_remediation(self, github_client):
        """Test automated secret scanning and remediation."""
        repositories = ["org/app1", "org/app2"]
        
        mock_response = {
            'total_secrets': 8,
            'high_confidence': 5,
            'auto_revoked': 2,
            'manual_review': 6,
            'secrets': [
                {
                    'repository': 'org/app1',
                    'secret_type': 'github_token',
                    'file_path': 'config/secrets.py',
                    'confidence': 'high',
                    'auto_revoked': True
                },
                {
                    'repository': 'org/app2',
                    'secret_type': 'aws_access_key',
                    'file_path': '.env',
                    'confidence': 'medium',
                    'auto_revoked': False
                }
            ],
            'remediation_actions': [
                {
                    'action': 'revoke_token',
                    'secret_id': 'secret-123',
                    'status': 'completed'
                },
                {
                    'action': 'create_issue',
                    'repository': 'org/app2',
                    'issue_url': 'https://github.com/org/app2/issues/42'
                }
            ],
            'monitoring_configuration': {
                'push_protection_enabled': True,
                'real_time_scanning': True
            }
        }
        
        github_client.mcp_client.call_mcp_tool.return_value = mock_response
        
        result = await github_client.automate_secret_remediation(
            repositories=repositories,
            auto_revoke=True,
            notification_channels=["slack", "email"]
        )
        
        assert 'scanning_summary' in result
        assert 'secret_breakdown' in result
        assert 'remediation_actions' in result
        assert 'prevention_measures' in result
        assert 'monitoring_setup' in result
        
        # Check scanning summary
        summary = result['scanning_summary']
        assert summary['repositories_scanned'] == 2
        assert summary['secrets_detected'] == 8
        assert summary['high_confidence_secrets'] == 5
        assert summary['auto_revoked'] == 2
        
        # Verify MCP call
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['repositories'] == repositories
        assert call_args['remediation_config']['auto_revoke_tokens'] is True
        assert call_args['notification_config']['channels'] == ["slack", "email"]
    
    @pytest.mark.asyncio
    async def test_automate_secret_remediation_no_auto_revoke(self, github_client):
        """Test secret remediation without auto-revoke."""
        github_client.mcp_client.call_mcp_tool.return_value = {
            'total_secrets': 3,
            'auto_revoked': 0,
            'secrets': [],
            'remediation_actions': []
        }
        
        await github_client.automate_secret_remediation(
            repositories=["org/safe-repo"],
            auto_revoke=False
        )
        
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['remediation_config']['auto_revoke_tokens'] is False
        assert call_args['notification_config']['channels'] == []


class TestDataProcessing:
    """Test suite for data processing methods."""
    
    def test_parse_security_alerts(self, github_client, mock_github_security_alerts_response):
        """Test parsing GitHub security alerts into structured objects."""
        alerts = github_client._parse_security_alerts(mock_github_security_alerts_response)
        
        assert len(alerts) == 1
        alert = alerts[0]
        assert isinstance(alert, GitHubSecurityAlert)
        assert alert.alert_id == 123
        assert alert.alert_number == 456
        assert alert.severity == GitHubSecuritySeverity.HIGH
        assert alert.package_name == 'lodash'
        assert alert.cve_id == 'CVE-2021-23337'
    
    def test_parse_security_alerts_invalid_data(self, github_client):
        """Test parsing security alerts with invalid data."""
        invalid_alerts = [
            {
                'id': 999,
                # Missing required fields
            }
        ]
        
        with patch.object(github_client.logger, 'warning'):
            alerts = github_client._parse_security_alerts(invalid_alerts)
            assert len(alerts) == 0  # Invalid alert filtered out
    
    def test_generate_vulnerability_summary(self, github_client):
        """Test generating vulnerability summary from alerts."""
        mock_alerts = [
            {
                'security_vulnerability': {'severity': 'critical'},
                'alert_type': 'dependency'
            },
            {
                'security_vulnerability': {'severity': 'high'},
                'alert_type': 'code_scanning'
            },
            {
                'security_vulnerability': {'severity': 'medium'},
                'alert_type': 'dependency'
            }
        ]
        
        summary = github_client._generate_vulnerability_summary(mock_alerts)
        
        assert summary['total_vulnerabilities'] == 3
        assert summary['severity_breakdown']['critical'] == 1
        assert summary['severity_breakdown']['high'] == 1
        assert summary['severity_breakdown']['medium'] == 1
        assert summary['vulnerability_types']['dependency'] == 2
        assert summary['vulnerability_types']['code_scanning'] == 1
    
    def test_calculate_security_score(self, github_client):
        """Test calculating security score for repository."""
        # High-severity alerts should reduce score significantly
        high_severity_alerts = [
            {'security_vulnerability': {'severity': 'critical'}},
            {'security_vulnerability': {'severity': 'critical'}},
            {'security_vulnerability': {'severity': 'high'}}
        ]
        
        score_result = github_client._calculate_security_score(high_severity_alerts)
        assert score_result['security_score'] < 60  # Should be low due to critical issues
        assert score_result['grade'] in ['F', 'D', 'C']
        
        # No alerts should give high score
        no_alerts_score = github_client._calculate_security_score([])
        assert no_alerts_score['security_score'] == 100
        assert no_alerts_score['grade'] == 'A'
    
    def test_generate_remediation_plan(self, github_client):
        """Test generating prioritized remediation plan."""
        mock_alerts = [
            {
                'id': 'alert-1',
                'security_vulnerability': {'severity': 'critical'},
                'auto_fixable': True,
                'dependency': {'package': {'name': 'critical-package'}}
            },
            {
                'id': 'alert-2', 
                'security_vulnerability': {'severity': 'medium'},
                'auto_fixable': False,
                'dependency': {'package': {'name': 'medium-package'}}
            },
            {
                'id': 'alert-3',
                'security_vulnerability': {'severity': 'high'},
                'auto_fixable': True,
                'dependency': {'package': {'name': 'high-package'}}
            }
        ]
        
        plan = github_client._generate_remediation_plan(mock_alerts)
        
        assert plan['total_items'] == 3
        assert plan['immediate_action_required'] == 1  # Critical alerts
        assert plan['auto_fixable_items'] == 2
        assert len(plan['prioritized_remediation']) <= 20  # Limited to top 20
        
        # Check that critical items are prioritized
        first_item = plan['prioritized_remediation'][0]
        assert first_item['severity'] == 'critical'
        assert first_item['action'] == 'Auto-update'
    
    def test_assess_compliance(self, github_client):
        """Test assessing compliance against security frameworks."""
        mock_alerts = [
            {
                'security_vulnerability': {'severity': 'high'},
                'alert_type': 'dependency'
            }
        ]
        
        compliance = github_client._assess_compliance(mock_alerts, "test-repo")
        
        assert 'overall_compliance_score' in compliance
        assert 'framework_scores' in compliance
        assert 'compliance_trend' in compliance
        
        # Should have scores for all frameworks
        for framework in ComplianceFramework:
            assert framework.value in compliance['framework_scores']
            framework_score = compliance['framework_scores'][framework.value]
            assert 'score' in framework_score
            assert 'status' in framework_score
            assert framework_score['status'] in ['compliant', 'non_compliant']


class TestOrganizationSecurityOverview:
    """Test suite for organization security overview."""
    
    @pytest.mark.asyncio
    async def test_get_organization_security_overview(self, github_client):
        """Test getting comprehensive organization security overview."""
        organization = "enterprise-org"
        
        mock_response = {
            'repository_count': 150,
            'member_count': 45,
            'org_security_score': 82,
            'compliance_status': 'mostly_compliant',
            'vulnerable_repos': 12,
            'total_alerts': 35,
            'critical_alerts': 3,
            'secrets_count': 8,
            'branch_protection_coverage': 85,
            'two_factor_enabled': True,
            'security_features': {
                'dependency_graph_enabled': True,
                'vulnerability_alerts_enabled': True,
                'secret_scanning_enabled': True
            },
            'compliance_data': {
                'overall_score': 82,
                'framework_scores': {
                    'owasp_top10': 85,
                    'nist_csf': 78
                }
            },
            'recommendations': [
                'Enable secret scanning on all repositories',
                'Increase branch protection coverage to 95%'
            ],
            'trends': {
                'security_score_change': 5,
                'vulnerability_trend': 'decreasing'
            }
        }
        
        github_client.mcp_client.call_mcp_tool.return_value = mock_response
        
        result = await github_client.get_organization_security_overview(organization)
        
        assert 'organization_summary' in result
        assert 'security_posture' in result
        assert 'policy_enforcement' in result
        assert 'compliance_assessment' in result
        assert 'recommendations' in result
        assert 'trend_analysis' in result
        
        # Check organization summary
        summary = result['organization_summary']
        assert summary['name'] == organization
        assert summary['total_repositories'] == 150
        assert summary['active_members'] == 45
        assert summary['security_score'] == 82
        
        # Check security posture
        posture = result['security_posture']
        assert posture['repositories_with_vulnerabilities'] == 12
        assert posture['total_security_alerts'] == 35
        assert posture['critical_alerts'] == 3
        
        # Verify MCP call
        call_args = github_client.mcp_client.call_mcp_tool.call_args[0][1]
        assert call_args['organization'] == organization
        assert call_args['include_repositories'] is True
        assert call_args['include_compliance'] is True


class TestConfigurationFactories:
    """Test suite for configuration factory functions."""
    
    def test_create_github_security_config(self):
        """Test creating GitHub security config."""
        client = create_github_security_config(
            github_token="test_token",
            enterprise_url="https://github.enterprise.com"
        )
        
        assert isinstance(client, GitHubSecurityMCPClient)
        assert client.github_token == "test_token"
        assert client.enterprise_url == "https://github.enterprise.com"
    
    def test_create_devsecops_pipeline_config_javascript(self):
        """Test creating DevSecOps config for JavaScript project."""
        config = create_devsecops_pipeline_config(
            repository_name="org/js-app",
            languages=['javascript', 'typescript'],
            security_level="high"
        )
        
        assert isinstance(config, SecDevOpsPipelineConfig)
        assert config.repository_name == "org/js-app"
        assert 'javascript' in config.sast_languages
        assert 'typescript' in config.sast_languages
        assert 'semgrep' in config.sast_tools
        assert 'npm-audit' in config.sca_tools
        assert config.block_on_high_severity is True
        assert config.block_on_critical_severity is True
        assert config.allow_security_exceptions is False
    
    def test_create_devsecops_pipeline_config_python(self):
        """Test creating DevSecOps config for Python project."""
        config = create_devsecops_pipeline_config(
            repository_name="org/python-api",
            languages=['python'],
            security_level="medium"
        )
        
        assert 'safety' in config.sca_tools
        assert config.block_on_high_severity is True
        assert config.allow_security_exceptions is True
    
    def test_create_devsecops_pipeline_config_low_security(self):
        """Test creating DevSecOps config with low security level."""
        config = create_devsecops_pipeline_config(
            repository_name="org/demo-app",
            languages=['java'],
            security_level="low"
        )
        
        assert config.block_on_high_severity is False
        assert config.block_on_critical_severity is True
        assert config.allow_security_exceptions is True


class TestErrorHandling:
    """Test suite for error handling."""
    
    @pytest.mark.asyncio
    async def test_repository_scan_permission_error(self, github_client):
        """Test repository scanning with permission error."""
        github_client.mcp_client.call_mcp_tool.side_effect = Exception("Permission denied")
        
        with pytest.raises(Exception):
            await github_client.scan_repository_security("private/repo")
    
    @pytest.mark.asyncio
    async def test_dependency_monitoring_rate_limit_error(self, github_client):
        """Test dependency monitoring with rate limit error."""
        github_client.mcp_client.call_mcp_tool.side_effect = Exception("Rate limit exceeded")
        
        with pytest.raises(Exception):
            await github_client.monitor_dependency_vulnerabilities(["org/repo"])
    
    @pytest.mark.asyncio
    async def test_policy_enforcement_insufficient_permissions(self, github_client):
        """Test policy enforcement with insufficient permissions."""
        github_client.mcp_client.call_mcp_tool.side_effect = Exception("Organization admin required")
        
        with pytest.raises(Exception):
            await github_client.enforce_security_policies("restricted-org", {})


class TestPerformance:
    """Performance-focused tests for GitHub Security MCP client."""
    
    @pytest.mark.asyncio
    async def test_concurrent_repository_scans(self, github_client):
        """Test concurrent repository security scans."""
        repositories = [f"org/repo-{i}" for i in range(10)]
        
        github_client.mcp_client.call_mcp_tool.return_value = {'alerts': []}
        
        # Execute concurrent scans
        tasks = [
            github_client.scan_repository_security(repo, comprehensive_scan=False)
            for repo in repositories
        ]
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 10
        assert github_client.mcp_client.call_mcp_tool.call_count == 10
    
    @pytest.mark.asyncio
    async def test_large_alert_processing(self, github_client):
        """Test processing large number of security alerts."""
        # Create large alert response (500 alerts)
        large_alerts = [
            {
                'id': i,
                'number': i + 1000,
                'state': 'open',
                'dependency': {'package': {'name': f'package-{i}'}},
                'security_advisory': {
                    'summary': f'Vulnerability {i}',
                    'description': f'Test vulnerability {i}',
                    'cve_id': f'CVE-2023-{i:04d}'
                },
                'security_vulnerability': {
                    'severity': 'medium',
                    'vulnerable_version_range': '< 1.0.0'
                },
                'created_at': '2026-03-06T01:00:00Z',
                'updated_at': '2026-03-06T01:00:00Z',
                'repository': {
                    'full_name': 'org/large-repo',
                    'html_url': 'https://github.com/org/large-repo'
                }
            }
            for i in range(500)
        ]
        
        github_client.mcp_client.call_mcp_tool.return_value = {'alerts': large_alerts}
        
        # Should process efficiently
        result = await github_client.scan_repository_security("org/large-repo")
        
        assert result['vulnerability_summary']['total_vulnerabilities'] == 500
        assert len(result['security_alerts']) == 500


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=mcp_integration.github", "--cov-report=html"])