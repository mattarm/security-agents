"""
GitHub Security MCP Integration Client

Implements enterprise DevSecOps integration with GitHub security MCP server for 
SAST/DAST/SCA pipeline integration, dependency vulnerability scanning automation,
secret scanning, and compliance reporting for development workflows.

P0 Deliverable for SecurityAgents Phase 2B Enterprise Integration
Author: Tiger Team Alpha-2 Integration Specialist
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Set
from dataclasses import dataclass, field
from enum import Enum
import subprocess
import os

from ..gateway.mcp_server_manager import MCPServerManager, MCPServerConfig


class GitHubSecuritySeverity(Enum):
    """GitHub security alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VulnerabilityType(Enum):
    """Types of security vulnerabilities."""
    DEPENDENCY = "dependency"
    CODE_SCANNING = "code_scanning"
    SECRET_SCANNING = "secret_scanning"
    INFRASTRUCTURE = "infrastructure"


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    NIST_CSF = "nist_csf"
    OWASP_TOP10 = "owasp_top10"
    CWE = "cwe"
    SANS_TOP25 = "sans_top25"
    PCI_DSS = "pci_dss"


@dataclass
class GitHubSecurityAlert:
    """Structured GitHub security alert."""
    alert_id: int
    alert_number: int
    repository_name: str
    repository_url: str
    alert_type: VulnerabilityType
    severity: GitHubSecuritySeverity
    state: str
    title: str
    description: str
    created_at: datetime
    updated_at: datetime
    dismissed_at: Optional[datetime] = None
    fixed_at: Optional[datetime] = None
    
    # Vulnerability details
    package_name: Optional[str] = None
    vulnerable_version_range: Optional[str] = None
    patched_version: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    
    # Code scanning specific
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    
    # Secret scanning specific
    secret_type: Optional[str] = None
    secret_url: Optional[str] = None
    
    # Remediation
    remediation_guidance: Optional[str] = None
    auto_fixable: bool = False
    
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RepositorySecurityProfile:
    """Security profile for a repository."""
    repository_name: str
    repository_url: str
    visibility: str
    default_branch: str
    
    # Security features
    security_advisories_enabled: bool = False
    dependency_graph_enabled: bool = False
    vulnerability_alerts_enabled: bool = False
    code_scanning_enabled: bool = False
    secret_scanning_enabled: bool = False
    
    # Branch protection
    branch_protection_enabled: bool = False
    required_status_checks: List[str] = field(default_factory=list)
    required_pull_request_reviews: bool = False
    dismiss_stale_reviews: bool = False
    require_code_owner_reviews: bool = False
    
    # Security metrics
    open_security_alerts: int = 0
    resolved_alerts_last_30_days: int = 0
    mean_time_to_remediation: Optional[float] = None
    
    # Compliance
    compliance_score: float = 0.0
    framework_compliance: Dict[str, float] = field(default_factory=dict)
    
    last_security_scan: Optional[datetime] = None


@dataclass
class SecDevOpsPipelineConfig:
    """Configuration for DevSecOps pipeline security."""
    repository_name: str
    
    # SAST Configuration
    sast_enabled: bool = True
    sast_tools: List[str] = field(default_factory=lambda: ['codeql', 'semgrep'])
    sast_languages: List[str] = field(default_factory=list)
    
    # DAST Configuration  
    dast_enabled: bool = True
    dast_tools: List[str] = field(default_factory=lambda: ['zap', 'nuclei'])
    dast_target_urls: List[str] = field(default_factory=list)
    
    # SCA Configuration
    sca_enabled: bool = True
    sca_tools: List[str] = field(default_factory=lambda: ['dependabot', 'snyk'])
    package_managers: List[str] = field(default_factory=list)
    
    # Security gates
    block_on_high_severity: bool = True
    block_on_critical_severity: bool = True
    allow_security_exceptions: bool = False
    
    # Compliance requirements
    required_compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)


class GitHubSecurityMCPClient:
    """
    Enterprise GitHub Security MCP integration client.
    
    Provides comprehensive DevSecOps integration with automated security scanning,
    vulnerability management, and compliance reporting across development workflows.
    """
    
    def __init__(self, github_token: Optional[str] = None, enterprise_url: Optional[str] = None):
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        self.enterprise_url = enterprise_url
        self.logger = logging.getLogger("github_security_mcp")
        
        # Initialize GitHub MCP client
        github_config = MCPServerConfig(
            server_name="github_security",
            server_url="mcp://github-security",
            auth_type="api_key",
            max_requests_per_minute=5000,  # GitHub API rate limits
            max_requests_per_hour=50000,
            auth_config={
                'token': self.github_token
            }
        )
        self.mcp_client = MCPServerManager(github_config)
        
        # Security analysis patterns
        self.security_patterns = {
            'secrets': [
                r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']',
                r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']+["\']',
                r'(?i)(secret|token)\s*[=:]\s*["\'][^"\']+["\']',
                r'(?i)(access[_-]?token)\s*[=:]\s*["\'][^"\']+["\']',
                r'(?i)(private[_-]?key)\s*[=:]\s*["\'][^"\']+["\']'
            ],
            'injection_vulnerabilities': [
                r'(?i)(eval|exec|system|shell_exec)\s*\(',
                r'(?i)(select|insert|update|delete)\s+.*\$',
                r'(?i)(script|javascript:)',
                r'(?i)(<script[^>]*>)',
                r'(?i)(on\w+\s*=)'
            ],
            'insecure_functions': [
                r'(?i)(md5|sha1)\s*\(',
                r'(?i)(http://)(?!localhost|127\.0\.0\.1)',
                r'(?i)(rand|mt_rand)\s*\(',
                r'(?i)(serialize|unserialize)\s*\(',
                r'(?i)(file_get_contents|fopen|fread)\s*\([^)]*\$'
            ]
        }
        
        # Compliance mappings
        self.compliance_mappings = {
            ComplianceFramework.OWASP_TOP10: {
                'injection': ['sql_injection', 'command_injection', 'ldap_injection'],
                'broken_auth': ['weak_passwords', 'session_management'],
                'sensitive_data': ['crypto_failures', 'data_exposure'],
                'xxe': ['xml_external_entities'],
                'broken_access': ['access_control_failures'],
                'security_misconfig': ['security_misconfiguration'],
                'xss': ['cross_site_scripting'],
                'deserialization': ['insecure_deserialization'],
                'components': ['vulnerable_components'],
                'logging': ['insufficient_logging']
            },
            ComplianceFramework.NIST_CSF: {
                'identify': ['asset_management', 'risk_assessment'],
                'protect': ['access_control', 'data_security', 'maintenance'],
                'detect': ['anomalies_events', 'monitoring'],
                'respond': ['response_planning', 'communications', 'analysis'],
                'recover': ['recovery_planning', 'improvements']
            }
        }
    
    async def scan_repository_security(
        self,
        repository_name: str,
        comprehensive_scan: bool = True,
        include_dependencies: bool = True,
        include_secrets: bool = True,
        include_code_analysis: bool = True
    ) -> Dict[str, Any]:
        """
        Perform comprehensive security scan of a GitHub repository.
        
        Args:
            repository_name: Repository to scan (owner/repo)
            comprehensive_scan: Enable all available security scans
            include_dependencies: Scan for dependency vulnerabilities
            include_secrets: Scan for exposed secrets
            include_code_analysis: Perform static code analysis
            
        Returns:
            Comprehensive security assessment of the repository
        """
        
        try:
            self.logger.info(f"Starting security scan for repository: {repository_name}")
            
            # Execute MCP call for comprehensive repository scan
            response = await self.mcp_client.call_mcp_tool(
                'scan_repository_security',
                {
                    'repository': repository_name,
                    'scan_types': {
                        'dependency_vulnerabilities': include_dependencies,
                        'secret_scanning': include_secrets,
                        'code_scanning': include_code_analysis,
                        'infrastructure_scanning': comprehensive_scan,
                        'license_compliance': comprehensive_scan
                    },
                    'include_historical_data': True,
                    'include_remediation_guidance': True,
                    'compliance_frameworks': ['owasp_top10', 'nist_csf', 'cwe']
                }
            )
            
            # Process scan results
            scan_results = {
                'repository_info': {
                    'name': repository_name,
                    'scan_timestamp': datetime.utcnow(),
                    'scan_type': 'comprehensive' if comprehensive_scan else 'targeted'
                },
                'security_alerts': self._parse_security_alerts(response.get('alerts', [])),
                'vulnerability_summary': self._generate_vulnerability_summary(response.get('alerts', [])),
                'compliance_assessment': self._assess_compliance(response.get('alerts', []), repository_name),
                'security_score': self._calculate_security_score(response.get('alerts', [])),
                'remediation_plan': self._generate_remediation_plan(response.get('alerts', [])),
                'trend_analysis': self._analyze_security_trends(response.get('historical_data', [])),
                'recommendations': self._generate_security_recommendations(response)
            }
            
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Repository security scan failed for {repository_name}: {e}")
            raise
    
    async def setup_devsecops_pipeline(
        self,
        repository_name: str,
        pipeline_config: SecDevOpsPipelineConfig
    ) -> Dict[str, Any]:
        """
        Set up comprehensive DevSecOps security pipeline.
        
        Args:
            repository_name: Target repository
            pipeline_config: Pipeline configuration settings
            
        Returns:
            Pipeline setup results and configuration
        """
        
        try:
            self.logger.info(f"Setting up DevSecOps pipeline for {repository_name}")
            
            response = await self.mcp_client.call_mcp_tool(
                'setup_devsecops_pipeline',
                {
                    'repository': repository_name,
                    'sast_config': {
                        'enabled': pipeline_config.sast_enabled,
                        'tools': pipeline_config.sast_tools,
                        'languages': pipeline_config.sast_languages,
                        'custom_rules': True,
                        'baseline_scan': True
                    },
                    'dast_config': {
                        'enabled': pipeline_config.dast_enabled,
                        'tools': pipeline_config.dast_tools,
                        'target_urls': pipeline_config.dast_target_urls,
                        'authentication': True,
                        'api_testing': True
                    },
                    'sca_config': {
                        'enabled': pipeline_config.sca_enabled,
                        'tools': pipeline_config.sca_tools,
                        'package_managers': pipeline_config.package_managers,
                        'license_checking': True,
                        'auto_updates': True
                    },
                    'security_gates': {
                        'block_high_severity': pipeline_config.block_on_high_severity,
                        'block_critical_severity': pipeline_config.block_on_critical_severity,
                        'allow_exceptions': pipeline_config.allow_security_exceptions,
                        'require_review': True
                    },
                    'compliance_requirements': [f.value for f in pipeline_config.required_compliance_frameworks]
                }
            )
            
            pipeline_setup = {
                'pipeline_id': response.get('pipeline_id'),
                'repository': repository_name,
                'configuration': {
                    'sast_tools_configured': response.get('sast_tools', []),
                    'dast_tools_configured': response.get('dast_tools', []),
                    'sca_tools_configured': response.get('sca_tools', []),
                    'security_gates_enabled': response.get('security_gates', [])
                },
                'workflow_files': response.get('workflow_files', []),
                'branch_protection_rules': response.get('branch_protection', {}),
                'webhook_configuration': response.get('webhooks', {}),
                'monitoring_setup': response.get('monitoring', {}),
                'next_steps': self._generate_pipeline_next_steps(response)
            }
            
            return pipeline_setup
            
        except Exception as e:
            self.logger.error(f"DevSecOps pipeline setup failed for {repository_name}: {e}")
            raise
    
    async def monitor_dependency_vulnerabilities(
        self,
        repositories: List[str],
        auto_remediation: bool = False,
        severity_threshold: GitHubSecuritySeverity = GitHubSecuritySeverity.MEDIUM
    ) -> Dict[str, Any]:
        """
        Monitor dependency vulnerabilities across multiple repositories.
        
        Args:
            repositories: List of repositories to monitor
            auto_remediation: Enable automatic remediation where possible
            severity_threshold: Minimum severity level to report
            
        Returns:
            Dependency vulnerability monitoring results
        """
        
        try:
            response = await self.mcp_client.call_mcp_tool(
                'monitor_dependencies',
                {
                    'repositories': repositories,
                    'monitoring_config': {
                        'auto_remediation': auto_remediation,
                        'severity_threshold': severity_threshold.value,
                        'package_managers': ['npm', 'pip', 'maven', 'gradle', 'composer', 'go', 'nuget'],
                        'include_dev_dependencies': True,
                        'license_compliance': True
                    },
                    'alerting': {
                        'real_time_alerts': True,
                        'daily_summaries': True,
                        'monthly_reports': True
                    },
                    'remediation_options': {
                        'auto_merge_security_updates': auto_remediation,
                        'create_pull_requests': True,
                        'notify_maintainers': True
                    }
                }
            )
            
            monitoring_results = {
                'monitoring_summary': {
                    'repositories_monitored': len(repositories),
                    'total_vulnerabilities': response.get('total_vulnerabilities', 0),
                    'critical_vulnerabilities': response.get('critical_count', 0),
                    'auto_remediated': response.get('auto_remediated', 0),
                    'pending_remediation': response.get('pending_remediation', 0)
                },
                'vulnerability_breakdown': self._categorize_vulnerabilities(response.get('vulnerabilities', [])),
                'repository_risk_scores': self._calculate_repository_risks(response.get('repository_data', [])),
                'remediation_actions': response.get('remediation_actions', []),
                'compliance_status': self._assess_dependency_compliance(response),
                'trending_analysis': self._analyze_vulnerability_trends(response.get('trends', {}))
            }
            
            return monitoring_results
            
        except Exception as e:
            self.logger.error(f"Dependency vulnerability monitoring failed: {e}")
            raise
    
    async def enforce_security_policies(
        self,
        organization: str,
        policy_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enforce enterprise GitHub security policies across organization.
        
        Args:
            organization: GitHub organization name
            policy_config: Security policy configuration
            
        Returns:
            Policy enforcement results and compliance status
        """
        
        try:
            response = await self.mcp_client.call_mcp_tool(
                'enforce_security_policies',
                {
                    'organization': organization,
                    'policies': {
                        'branch_protection': {
                            'require_pull_request_reviews': policy_config.get('require_pr_reviews', True),
                            'required_approving_review_count': policy_config.get('min_reviewers', 2),
                            'dismiss_stale_reviews': policy_config.get('dismiss_stale', True),
                            'require_code_owner_reviews': policy_config.get('require_codeowners', True),
                            'require_status_checks': policy_config.get('require_status_checks', True),
                            'restrict_pushes': policy_config.get('restrict_pushes', True)
                        },
                        'security_features': {
                            'dependency_graph_enabled': True,
                            'vulnerability_alerts_enabled': True,
                            'security_advisories_enabled': True,
                            'secret_scanning_enabled': True,
                            'push_protection_enabled': True
                        },
                        'access_control': {
                            'two_factor_required': policy_config.get('require_2fa', True),
                            'saml_sso_required': policy_config.get('require_sso', False),
                            'base_permissions': policy_config.get('base_permissions', 'read'),
                            'member_privileges': policy_config.get('member_privileges', 'restricted')
                        },
                        'compliance_requirements': policy_config.get('compliance_frameworks', [])
                    },
                    'enforcement_level': policy_config.get('enforcement_level', 'strict'),
                    'exceptions': policy_config.get('policy_exceptions', []),
                    'audit_logging': True
                }
            )
            
            enforcement_results = {
                'policy_summary': {
                    'organization': organization,
                    'policies_applied': len(response.get('applied_policies', [])),
                    'repositories_affected': response.get('repositories_affected', 0),
                    'compliance_score': response.get('compliance_score', 0)
                },
                'enforcement_details': {
                    'successful_applications': response.get('successful', []),
                    'failed_applications': response.get('failed', []),
                    'exceptions_granted': response.get('exceptions', []),
                    'manual_review_required': response.get('manual_review', [])
                },
                'compliance_gaps': self._identify_compliance_gaps(response),
                'remediation_actions': self._generate_policy_remediation_actions(response),
                'monitoring_setup': response.get('monitoring_configuration', {})
            }
            
            return enforcement_results
            
        except Exception as e:
            self.logger.error(f"Security policy enforcement failed for {organization}: {e}")
            raise
    
    async def generate_compliance_report(
        self,
        scope: str,  # 'repository', 'organization', or 'enterprise'
        target: str,
        frameworks: List[ComplianceFramework],
        time_period_days: int = 30
    ) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report for development workflows.
        
        Args:
            scope: Scope of the report (repository/organization/enterprise)
            target: Target name (repo name, org name, or enterprise name)
            frameworks: Compliance frameworks to assess
            time_period_days: Time period for the report
            
        Returns:
            Detailed compliance report with evidence and recommendations
        """
        
        try:
            response = await self.mcp_client.call_mcp_tool(
                'generate_compliance_report',
                {
                    'scope': scope,
                    'target': target,
                    'frameworks': [f.value for f in frameworks],
                    'time_period_days': time_period_days,
                    'include_evidence': True,
                    'include_remediation': True,
                    'include_trends': True,
                    'export_formats': ['json', 'pdf', 'csv']
                }
            )
            
            compliance_report = {
                'report_metadata': {
                    'scope': scope,
                    'target': target,
                    'frameworks_assessed': [f.value for f in frameworks],
                    'report_period': f"{time_period_days} days",
                    'generated_at': datetime.utcnow(),
                    'report_id': response.get('report_id')
                },
                'executive_summary': {
                    'overall_compliance_score': response.get('overall_score', 0),
                    'critical_findings': response.get('critical_findings', 0),
                    'improvement_areas': response.get('improvement_areas', []),
                    'compliance_trend': response.get('trend', 'stable')
                },
                'framework_assessments': self._process_framework_assessments(response.get('frameworks', {})),
                'security_metrics': {
                    'vulnerabilities_by_severity': response.get('vulnerability_metrics', {}),
                    'remediation_times': response.get('remediation_metrics', {}),
                    'security_coverage': response.get('coverage_metrics', {})
                },
                'evidence_collection': response.get('evidence', {}),
                'recommendations': self._prioritize_compliance_recommendations(response),
                'action_plan': self._generate_compliance_action_plan(response)
            }
            
            return compliance_report
            
        except Exception as e:
            self.logger.error(f"Compliance report generation failed: {e}")
            raise
    
    async def automate_secret_remediation(
        self,
        repositories: List[str],
        auto_revoke: bool = False,
        notification_channels: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Automate secret scanning and remediation across repositories.
        
        Args:
            repositories: List of repositories to scan
            auto_revoke: Automatically revoke detected secrets where possible
            notification_channels: Channels to notify about secret findings
            
        Returns:
            Secret scanning and remediation results
        """
        
        try:
            response = await self.mcp_client.call_mcp_tool(
                'automate_secret_remediation',
                {
                    'repositories': repositories,
                    'scanning_config': {
                        'scan_entire_history': True,
                        'custom_patterns': True,
                        'exclude_paths': ['.git', 'node_modules', 'vendor', '.env.example'],
                        'include_archived_repos': False
                    },
                    'remediation_config': {
                        'auto_revoke_tokens': auto_revoke,
                        'create_issues': True,
                        'notify_owners': True,
                        'block_pushes': True,
                        'generate_replacement_suggestions': True
                    },
                    'notification_config': {
                        'channels': notification_channels or [],
                        'severity_threshold': 'medium',
                        'real_time_alerts': True
                    }
                }
            )
            
            remediation_results = {
                'scanning_summary': {
                    'repositories_scanned': len(repositories),
                    'secrets_detected': response.get('total_secrets', 0),
                    'high_confidence_secrets': response.get('high_confidence', 0),
                    'auto_revoked': response.get('auto_revoked', 0),
                    'manual_review_required': response.get('manual_review', 0)
                },
                'secret_breakdown': self._categorize_secrets(response.get('secrets', [])),
                'remediation_actions': response.get('remediation_actions', []),
                'prevention_measures': self._generate_secret_prevention_measures(response),
                'monitoring_setup': response.get('monitoring_configuration', {}),
                'compliance_impact': self._assess_secret_compliance_impact(response)
            }
            
            return remediation_results
            
        except Exception as e:
            self.logger.error(f"Secret remediation automation failed: {e}")
            raise
    
    def _parse_security_alerts(self, alerts_data: List[Dict[str, Any]]) -> List[GitHubSecurityAlert]:
        """Parse GitHub security alerts into structured objects."""
        
        alerts = []
        
        for alert_data in alerts_data:
            try:
                alert = GitHubSecurityAlert(
                    alert_id=alert_data['id'],
                    alert_number=alert_data['number'],
                    repository_name=alert_data['repository']['full_name'],
                    repository_url=alert_data['repository']['html_url'],
                    alert_type=VulnerabilityType(alert_data['alert_type']),
                    severity=GitHubSecuritySeverity(alert_data['security_vulnerability']['severity']),
                    state=alert_data['state'],
                    title=alert_data['security_advisory']['summary'],
                    description=alert_data['security_advisory']['description'],
                    created_at=self._parse_datetime(alert_data['created_at']),
                    updated_at=self._parse_datetime(alert_data['updated_at']),
                    dismissed_at=self._parse_datetime(alert_data.get('dismissed_at')),
                    fixed_at=self._parse_datetime(alert_data.get('fixed_at')),
                    package_name=alert_data['dependency']['package']['name'],
                    vulnerable_version_range=alert_data['security_vulnerability']['vulnerable_version_range'],
                    patched_version=alert_data['security_vulnerability']['first_patched_version']['identifier'],
                    cvss_score=alert_data['security_advisory'].get('cvss', {}).get('score'),
                    cve_id=alert_data['security_advisory'].get('cve_id'),
                    cwe_ids=alert_data['security_advisory'].get('cwe_ids', []),
                    remediation_guidance=self._generate_remediation_guidance(alert_data),
                    auto_fixable=alert_data.get('auto_fixable', False),
                    raw_data=alert_data
                )
                alerts.append(alert)
                
            except Exception as e:
                self.logger.warning(f"Failed to parse security alert: {e}")
                continue
        
        return alerts
    
    def _generate_vulnerability_summary(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of vulnerability findings."""
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        type_counts = {'dependency': 0, 'code_scanning': 0, 'secret_scanning': 0, 'infrastructure': 0}
        
        for alert in alerts:
            severity = alert.get('security_vulnerability', {}).get('severity', 'low')
            alert_type = alert.get('alert_type', 'dependency')
            
            if severity in severity_counts:
                severity_counts[severity] += 1
            if alert_type in type_counts:
                type_counts[alert_type] += 1
        
        return {
            'total_vulnerabilities': len(alerts),
            'severity_breakdown': severity_counts,
            'vulnerability_types': type_counts,
            'risk_score': self._calculate_risk_score(severity_counts),
            'top_vulnerable_packages': self._extract_top_vulnerable_packages(alerts),
            'remediation_priority': self._prioritize_vulnerabilities(alerts)
        }
    
    def _assess_compliance(self, alerts: List[Dict[str, Any]], repository_name: str) -> Dict[str, Any]:
        """Assess compliance against security frameworks."""
        
        compliance_scores = {}
        
        for framework in ComplianceFramework:
            framework_score = self._calculate_framework_compliance(alerts, framework)
            compliance_scores[framework.value] = {
                'score': framework_score,
                'status': 'compliant' if framework_score >= 80 else 'non_compliant',
                'gaps': self._identify_framework_gaps(alerts, framework),
                'recommendations': self._get_framework_recommendations(framework)
            }
        
        return {
            'overall_compliance_score': sum(s['score'] for s in compliance_scores.values()) / len(compliance_scores),
            'framework_scores': compliance_scores,
            'compliance_trend': 'improving',  # Would calculate from historical data
            'critical_gaps': self._extract_critical_compliance_gaps(compliance_scores)
        }
    
    def _calculate_security_score(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall security score for repository."""
        
        base_score = 100
        
        # Deduct points for vulnerabilities
        for alert in alerts:
            severity = alert.get('security_vulnerability', {}).get('severity', 'low')
            if severity == 'critical':
                base_score -= 20
            elif severity == 'high':
                base_score -= 10
            elif severity == 'medium':
                base_score -= 5
            elif severity == 'low':
                base_score -= 2
        
        final_score = max(0, base_score)
        
        return {
            'security_score': final_score,
            'grade': self._get_security_grade(final_score),
            'factors': {
                'vulnerability_count': len(alerts),
                'critical_vulnerabilities': sum(1 for a in alerts if a.get('security_vulnerability', {}).get('severity') == 'critical'),
                'remediation_coverage': 0  # Would calculate from remediation status
            },
            'improvement_areas': self._identify_improvement_areas(alerts, final_score)
        }
    
    def _generate_remediation_plan(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate prioritized remediation plan."""
        
        prioritized_alerts = sorted(
            alerts,
            key=lambda x: (
                {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(
                    x.get('security_vulnerability', {}).get('severity', 'low'), 1
                ),
                x.get('auto_fixable', False)
            ),
            reverse=True
        )
        
        return {
            'total_items': len(alerts),
            'immediate_action_required': len([a for a in alerts if a.get('security_vulnerability', {}).get('severity') == 'critical']),
            'auto_fixable_items': len([a for a in alerts if a.get('auto_fixable', False)]),
            'prioritized_remediation': [
                {
                    'priority': i + 1,
                    'alert_id': alert['id'],
                    'package': alert.get('dependency', {}).get('package', {}).get('name', 'Unknown'),
                    'severity': alert.get('security_vulnerability', {}).get('severity', 'low'),
                    'action': 'Auto-update' if alert.get('auto_fixable') else 'Manual review',
                    'estimated_effort': self._estimate_remediation_effort(alert)
                }
                for i, alert in enumerate(prioritized_alerts[:20])  # Top 20
            ],
            'timeline_estimate': self._estimate_remediation_timeline(prioritized_alerts)
        }
    
    def _parse_datetime(self, datetime_str: Optional[str]) -> Optional[datetime]:
        """Parse datetime string safely."""
        if not datetime_str:
            return None
        try:
            return datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
        except:
            return None
    
    async def get_organization_security_overview(self, organization: str) -> Dict[str, Any]:
        """Get comprehensive security overview for an organization."""
        
        try:
            response = await self.mcp_client.call_mcp_tool(
                'get_organization_security_overview',
                {
                    'organization': organization,
                    'include_repositories': True,
                    'include_members': True,
                    'include_policies': True,
                    'include_compliance': True
                }
            )
            
            overview = {
                'organization_summary': {
                    'name': organization,
                    'total_repositories': response.get('repository_count', 0),
                    'active_members': response.get('member_count', 0),
                    'security_score': response.get('org_security_score', 0),
                    'compliance_status': response.get('compliance_status', 'unknown')
                },
                'security_posture': {
                    'repositories_with_vulnerabilities': response.get('vulnerable_repos', 0),
                    'total_security_alerts': response.get('total_alerts', 0),
                    'critical_alerts': response.get('critical_alerts', 0),
                    'secrets_detected': response.get('secrets_count', 0)
                },
                'policy_enforcement': {
                    'branch_protection_coverage': response.get('branch_protection_coverage', 0),
                    'two_factor_enforcement': response.get('two_factor_enabled', False),
                    'security_features_enabled': response.get('security_features', {})
                },
                'compliance_assessment': response.get('compliance_data', {}),
                'recommendations': response.get('recommendations', []),
                'trend_analysis': response.get('trends', {})
            }
            
            return overview
            
        except Exception as e:
            self.logger.error(f"Organization security overview failed for {organization}: {e}")
            raise


# Configuration helpers for GitHub Security MCP
def create_github_security_config(
    github_token: Optional[str] = None,
    enterprise_url: Optional[str] = None
) -> GitHubSecurityMCPClient:
    """Create GitHub Security MCP client with proper configuration."""
    
    return GitHubSecurityMCPClient(
        github_token=github_token,
        enterprise_url=enterprise_url
    )


def create_devsecops_pipeline_config(
    repository_name: str,
    languages: List[str],
    security_level: str = "high"
) -> SecDevOpsPipelineConfig:
    """Create DevSecOps pipeline configuration based on repository characteristics."""
    
    # Determine tools based on languages
    sast_tools = ['codeql']
    if any(lang in ['python', 'javascript', 'typescript'] for lang in languages):
        sast_tools.append('semgrep')
    if any(lang in ['java', 'scala', 'kotlin'] for lang in languages):
        sast_tools.append('spotbugs')
    
    sca_tools = ['dependabot']
    if 'javascript' in languages or 'typescript' in languages:
        sca_tools.append('npm-audit')
    if 'python' in languages:
        sca_tools.append('safety')
    
    # Security level configuration
    security_configs = {
        'low': {
            'block_high': False,
            'block_critical': True,
            'allow_exceptions': True
        },
        'medium': {
            'block_high': True,
            'block_critical': True,
            'allow_exceptions': True
        },
        'high': {
            'block_high': True,
            'block_critical': True,
            'allow_exceptions': False
        }
    }
    
    config = security_configs.get(security_level, security_configs['medium'])
    
    return SecDevOpsPipelineConfig(
        repository_name=repository_name,
        sast_languages=languages,
        sast_tools=sast_tools,
        sca_tools=sca_tools,
        block_on_high_severity=config['block_high'],
        block_on_critical_severity=config['block_critical'],
        allow_security_exceptions=config['allow_exceptions'],
        required_compliance_frameworks=[
            ComplianceFramework.OWASP_TOP10,
            ComplianceFramework.NIST_CSF
        ]
    )


# Example enterprise DevSecOps setup
async def example_enterprise_devsecops_setup():
    """Example enterprise DevSecOps setup workflow."""
    
    # Initialize GitHub Security client
    github_client = create_github_security_config()
    
    organization = "enterprise-org"
    repositories = [
        "enterprise-org/web-application",
        "enterprise-org/api-service",
        "enterprise-org/mobile-app"
    ]
    
    try:
        # 1. Get organization security overview
        overview = await github_client.get_organization_security_overview(organization)
        print(f"📊 Organization Security Score: {overview['organization_summary']['security_score']}/100")
        
        # 2. Set up DevSecOps pipelines for each repository
        for repo in repositories:
            # Determine languages (would query GitHub API)
            languages = ['javascript', 'python', 'go']  # Example
            
            pipeline_config = create_devsecops_pipeline_config(
                repository_name=repo,
                languages=languages,
                security_level="high"
            )
            
            pipeline_result = await github_client.setup_devsecops_pipeline(repo, pipeline_config)
            print(f"✅ {repo}: DevSecOps pipeline configured")
        
        # 3. Monitor dependency vulnerabilities
        dependency_monitoring = await github_client.monitor_dependency_vulnerabilities(
            repositories=repositories,
            auto_remediation=True,
            severity_threshold=GitHubSecuritySeverity.MEDIUM
        )
        
        print(f"🔍 Monitoring {dependency_monitoring['monitoring_summary']['repositories_monitored']} repositories")
        print(f"🚨 Found {dependency_monitoring['monitoring_summary']['total_vulnerabilities']} vulnerabilities")
        
        # 4. Enforce security policies
        policy_config = {
            'require_pr_reviews': True,
            'min_reviewers': 2,
            'require_2fa': True,
            'enforcement_level': 'strict',
            'compliance_frameworks': ['nist_csf', 'owasp_top10']
        }
        
        policy_results = await github_client.enforce_security_policies(organization, policy_config)
        print(f"📋 Applied policies to {policy_results['policy_summary']['repositories_affected']} repositories")
        
        # 5. Generate compliance report
        compliance_report = await github_client.generate_compliance_report(
            scope="organization",
            target=organization,
            frameworks=[ComplianceFramework.OWASP_TOP10, ComplianceFramework.NIST_CSF],
            time_period_days=30
        )
        
        print(f"📄 Compliance Score: {compliance_report['executive_summary']['overall_compliance_score']}/100")
        
    except Exception as e:
        print(f"Enterprise DevSecOps setup failed: {e}")


if __name__ == "__main__":
    # Would be run in async context with proper GitHub token
    # asyncio.run(example_enterprise_devsecops_setup())
    pass