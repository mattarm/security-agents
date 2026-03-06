"""
AWS Security Services MCP Integration Client

Implements enterprise integration with AWS MCP ecosystem (66+ servers) for 
comprehensive cloud security monitoring, including CloudTrail analysis, 
Security Hub findings, Config compliance, and infrastructure monitoring.

P0 Deliverable for SecurityAgents Phase 2B Enterprise Integration  
Author: Tiger Team Alpha-2 Integration Specialist
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import boto3
from botocore.exceptions import ClientError

from ..gateway.mcp_server_manager import MCPServerManager, MCPServerConfig


class AWSSecuritySeverity(Enum):
    """AWS Security finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH" 
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class AWSComplianceStatus(Enum):
    """AWS Config compliance statuses."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


@dataclass
class AWSSecurityFinding:
    """Structured AWS Security Hub finding."""
    finding_id: str
    aws_account_id: str
    region: str
    severity: AWSSecuritySeverity
    finding_type: str
    resource_type: str
    resource_id: str
    resource_arn: str
    title: str
    description: str
    remediation: Dict[str, Any]
    compliance_frameworks: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass 
class AWSCloudTrailEvent:
    """Structured CloudTrail security event."""
    event_id: str
    event_time: datetime
    event_name: str
    event_source: str
    user_identity: Dict[str, Any]
    source_ip: str
    user_agent: str
    aws_region: str
    request_parameters: Dict[str, Any]
    response_elements: Dict[str, Any]
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    risk_score: int = 0
    threat_indicators: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AWSConfigRule:
    """AWS Config compliance rule."""
    rule_name: str
    rule_arn: str
    config_rule_state: str
    compliance_status: AWSComplianceStatus
    source: str
    scope: Dict[str, Any]
    last_evaluation: Optional[datetime] = None
    non_compliant_resources: List[str] = field(default_factory=list)
    remediation_configuration: Dict[str, Any] = field(default_factory=dict)


class AWSSecurityMCPClient:
    """
    Enterprise AWS Security Services MCP integration client.
    
    Integrates with AWS MCP ecosystem (66+ servers) for comprehensive 
    security monitoring and automation across multiple AWS services.
    """
    
    def __init__(self, aws_region: str = "us-west-2"):
        self.aws_region = aws_region
        self.logger = logging.getLogger(f"aws_security_mcp.{aws_region}")
        
        # Initialize multiple AWS MCP clients for different services
        self.mcp_clients = {}
        self._init_mcp_clients()
        
        # AWS service clients for direct integration
        self.security_hub_client = boto3.client('securityhub', region_name=aws_region)
        self.config_client = boto3.client('config', region_name=aws_region)
        self.cloudtrail_client = boto3.client('cloudtrail', region_name=aws_region)
        self.guardduty_client = boto3.client('guardduty', region_name=aws_region)
        
        # Security monitoring configurations
        self.monitoring_rules = {
            'privileged_api_calls': [
                'CreateUser', 'CreateRole', 'AttachUserPolicy', 'AttachRolePolicy',
                'CreateAccessKey', 'DeleteRole', 'DeleteUser', 'PutUserPolicy'
            ],
            'infrastructure_changes': [
                'CreateVpc', 'DeleteVpc', 'CreateSecurityGroup', 'AuthorizeSecurityGroupIngress',
                'CreateInstance', 'TerminateInstances', 'ModifyInstanceAttribute'
            ],
            'data_access': [
                'GetObject', 'PutObject', 'DeleteObject', 'GetBucketPolicy',
                'PutBucketPolicy', 'GetItem', 'PutItem', 'DeleteItem'
            ]
        }
    
    def _init_mcp_clients(self):
        """Initialize MCP clients for different AWS services."""
        
        # Security Hub MCP configuration
        security_hub_config = MCPServerConfig(
            server_name="aws_security_hub",
            server_url="mcp://aws-security-hub",
            auth_type="iam",
            aws_region=self.aws_region,
            parameter_store_prefix="/secops/aws/security-hub"
        )
        self.mcp_clients['security_hub'] = MCPServerManager(security_hub_config)
        
        # Config MCP configuration
        config_config = MCPServerConfig(
            server_name="aws_config",
            server_url="mcp://aws-config",
            auth_type="iam", 
            aws_region=self.aws_region,
            parameter_store_prefix="/secops/aws/config"
        )
        self.mcp_clients['config'] = MCPServerManager(config_config)
        
        # CloudTrail MCP configuration
        cloudtrail_config = MCPServerConfig(
            server_name="aws_cloudtrail",
            server_url="mcp://aws-cloudtrail",
            auth_type="iam",
            aws_region=self.aws_region,
            parameter_store_prefix="/secops/aws/cloudtrail"
        )
        self.mcp_clients['cloudtrail'] = MCPServerManager(cloudtrail_config)
        
        # GuardDuty MCP configuration
        guardduty_config = MCPServerConfig(
            server_name="aws_guardduty",
            server_url="mcp://aws-guardduty", 
            auth_type="iam",
            aws_region=self.aws_region,
            parameter_store_prefix="/secops/aws/guardduty"
        )
        self.mcp_clients['guardduty'] = MCPServerManager(guardduty_config)
    
    async def analyze_security_hub_findings(
        self,
        severity_filter: Optional[List[AWSSecuritySeverity]] = None,
        compliance_frameworks: Optional[List[str]] = None,
        time_range_hours: int = 24,
        limit: int = 500
    ) -> Dict[str, Any]:
        """
        Analyze Security Hub findings with intelligent filtering and correlation.
        
        Args:
            severity_filter: List of severity levels to include
            compliance_frameworks: Specific frameworks to check (NIST, CIS, etc.)
            time_range_hours: Hours to look back for findings
            limit: Maximum findings to analyze
            
        Returns:
            Comprehensive analysis of security findings
        """
        
        try:
            # Prepare filters
            filters = {
                'UpdatedAt': [
                    {
                        'Start': datetime.utcnow() - timedelta(hours=time_range_hours),
                        'End': datetime.utcnow()
                    }
                ]
            }
            
            if severity_filter:
                filters['SeverityLabel'] = [
                    {'Value': sev.value, 'Comparison': 'EQUALS'} 
                    for sev in severity_filter
                ]
            
            if compliance_frameworks:
                filters['ComplianceSecurityControlId'] = [
                    {'Value': framework, 'Comparison': 'PREFIX'} 
                    for framework in compliance_frameworks
                ]
            
            # Execute MCP call for Security Hub analysis
            response = await self.mcp_clients['security_hub'].call_mcp_tool(
                'analyze_findings',
                {
                    'filters': filters,
                    'limit': limit,
                    'include_remediation': True,
                    'include_compliance_mapping': True,
                    'correlation_analysis': True
                }
            )
            
            # Process findings into structured format
            findings = self._parse_security_hub_findings(response.get('findings', []))
            
            # Generate comprehensive analysis
            analysis = {
                'findings_summary': {
                    'total_findings': len(findings),
                    'severity_breakdown': self._calculate_severity_breakdown(findings),
                    'affected_resources': self._extract_affected_resources(findings),
                    'compliance_gaps': self._identify_compliance_gaps(findings)
                },
                'findings': findings,
                'threat_landscape': self._analyze_threat_patterns(findings),
                'remediation_priorities': self._prioritize_remediation(findings),
                'cost_optimization': self._identify_cost_security_opportunities(findings)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Security Hub analysis failed: {e}")
            raise
    
    async def analyze_cloudtrail_events(
        self,
        time_range_hours: int = 24,
        threat_indicators: Optional[List[str]] = None,
        privilege_escalation_detection: bool = True,
        anomaly_detection: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze CloudTrail events for security threats and anomalies.
        
        Args:
            time_range_hours: Hours to analyze
            threat_indicators: Known IOCs to search for
            privilege_escalation_detection: Enable privilege escalation detection
            anomaly_detection: Enable behavioral anomaly detection
            
        Returns:
            Security analysis of CloudTrail events
        """
        
        try:
            # Query CloudTrail via MCP
            response = await self.mcp_clients['cloudtrail'].call_mcp_tool(
                'analyze_security_events',
                {
                    'time_range_hours': time_range_hours,
                    'event_categories': [
                        'privileged_operations',
                        'infrastructure_changes', 
                        'data_access',
                        'authentication_events'
                    ],
                    'threat_indicators': threat_indicators or [],
                    'enable_privilege_escalation_detection': privilege_escalation_detection,
                    'enable_anomaly_detection': anomaly_detection,
                    'include_geolocation': True,
                    'include_user_behavior_analysis': True
                }
            )
            
            # Parse CloudTrail events
            events = self._parse_cloudtrail_events(response.get('events', []))
            
            # Perform security analysis
            analysis = {
                'events_summary': {
                    'total_events': len(events),
                    'high_risk_events': self._count_high_risk_events(events),
                    'unique_users': len(set(e.user_identity.get('userName', '') for e in events)),
                    'unique_source_ips': len(set(e.source_ip for e in events if e.source_ip))
                },
                'security_analysis': {
                    'privilege_escalation_attempts': self._detect_privilege_escalation(events),
                    'suspicious_api_patterns': self._analyze_api_patterns(events),
                    'anomalous_behavior': self._detect_behavioral_anomalies(events),
                    'threat_actor_ttps': self._map_threat_tactics(events)
                },
                'risk_assessment': {
                    'overall_risk_score': self._calculate_environment_risk(events),
                    'critical_findings': self._extract_critical_findings(events),
                    'recommended_actions': self._generate_response_recommendations(events)
                },
                'events': events[:100]  # Limit returned events for performance
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"CloudTrail analysis failed: {e}")
            raise
    
    async def assess_config_compliance(
        self,
        compliance_frameworks: Optional[List[str]] = None,
        resource_types: Optional[List[str]] = None,
        include_remediation: bool = True
    ) -> Dict[str, Any]:
        """
        Assess AWS Config compliance across security frameworks.
        
        Args:
            compliance_frameworks: Frameworks to assess (NIST, CIS, SOX, etc.)
            resource_types: Specific resource types to check
            include_remediation: Include automated remediation options
            
        Returns:
            Comprehensive compliance assessment
        """
        
        try:
            response = await self.mcp_clients['config'].call_mcp_tool(
                'assess_compliance',
                {
                    'compliance_frameworks': compliance_frameworks or [
                        'NIST_CSF_2.0', 'CIS_AWS_Foundations', 'SOX', 'PCI_DSS'
                    ],
                    'resource_types': resource_types or [],
                    'include_remediation': include_remediation,
                    'include_cost_impact': True,
                    'include_risk_assessment': True
                }
            )
            
            # Parse compliance data
            compliance_rules = self._parse_config_rules(response.get('rules', []))
            
            assessment = {
                'compliance_overview': {
                    'total_rules': len(compliance_rules),
                    'compliant_rules': sum(1 for r in compliance_rules if r.compliance_status == AWSComplianceStatus.COMPLIANT),
                    'non_compliant_rules': sum(1 for r in compliance_rules if r.compliance_status == AWSComplianceStatus.NON_COMPLIANT),
                    'compliance_percentage': self._calculate_compliance_percentage(compliance_rules)
                },
                'framework_compliance': self._assess_framework_compliance(compliance_rules, compliance_frameworks),
                'critical_gaps': self._identify_critical_compliance_gaps(compliance_rules),
                'remediation_plan': self._generate_remediation_plan(compliance_rules) if include_remediation else {},
                'rules': compliance_rules
            }
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Config compliance assessment failed: {e}")
            raise
    
    async def monitor_vpc_flow_logs(
        self,
        time_range_hours: int = 24,
        threat_detection: bool = True,
        traffic_analysis: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze VPC Flow Logs for network security threats.
        
        Args:
            time_range_hours: Hours of logs to analyze
            threat_detection: Enable threat detection analysis
            traffic_analysis: Enable traffic pattern analysis
            
        Returns:
            Network security analysis from VPC Flow Logs
        """
        
        try:
            response = await self.mcp_clients['cloudtrail'].call_mcp_tool(
                'analyze_vpc_flow_logs',
                {
                    'time_range_hours': time_range_hours,
                    'threat_detection': threat_detection,
                    'traffic_analysis': traffic_analysis,
                    'include_geolocation': True,
                    'include_threat_intelligence': True,
                    'anomaly_detection': True
                }
            )
            
            analysis = {
                'network_summary': response.get('summary', {}),
                'threat_analysis': {
                    'suspicious_connections': response.get('suspicious_connections', []),
                    'malicious_ips': response.get('malicious_ips', []),
                    'data_exfiltration_indicators': response.get('data_exfiltration', []),
                    'lateral_movement_detection': response.get('lateral_movement', [])
                },
                'traffic_patterns': {
                    'top_talkers': response.get('top_talkers', []),
                    'unusual_protocols': response.get('unusual_protocols', []),
                    'traffic_anomalies': response.get('traffic_anomalies', [])
                },
                'security_recommendations': self._generate_network_recommendations(response)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"VPC Flow Log analysis failed: {e}")
            raise
    
    async def track_iam_privilege_changes(
        self,
        time_range_hours: int = 24,
        monitor_escalation: bool = True,
        track_access_patterns: bool = True
    ) -> Dict[str, Any]:
        """
        Monitor IAM privilege escalation and access pattern changes.
        
        Args:
            time_range_hours: Hours to monitor
            monitor_escalation: Enable privilege escalation detection
            track_access_patterns: Enable access pattern analysis
            
        Returns:
            IAM security analysis and privilege monitoring
        """
        
        try:
            response = await self.mcp_clients['cloudtrail'].call_mcp_tool(
                'analyze_iam_activity',
                {
                    'time_range_hours': time_range_hours,
                    'privilege_escalation_detection': monitor_escalation,
                    'access_pattern_analysis': track_access_patterns,
                    'include_cross_account_activity': True,
                    'include_service_linked_roles': False,
                    'anomaly_detection': True
                }
            )
            
            analysis = {
                'iam_summary': {
                    'total_iam_events': response.get('total_events', 0),
                    'privilege_changes': response.get('privilege_changes', 0),
                    'new_users_created': response.get('new_users', 0),
                    'new_roles_created': response.get('new_roles', 0)
                },
                'privilege_analysis': {
                    'escalation_attempts': response.get('escalation_attempts', []),
                    'admin_access_grants': response.get('admin_grants', []),
                    'cross_account_assume_role': response.get('cross_account_activity', []),
                    'unused_high_privilege_accounts': response.get('unused_privileged', [])
                },
                'access_patterns': {
                    'unusual_access_times': response.get('unusual_times', []),
                    'new_service_usage': response.get('new_services', []),
                    'geographic_anomalies': response.get('geo_anomalies', [])
                },
                'recommendations': self._generate_iam_recommendations(response)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"IAM privilege monitoring failed: {e}")
            raise
    
    async def optimize_security_costs(
        self,
        cost_threshold_monthly: float = 1000.0,
        include_unused_resources: bool = True,
        include_overprovisioned: bool = True
    ) -> Dict[str, Any]:
        """
        Identify security cost optimization opportunities.
        
        Args:
            cost_threshold_monthly: Monthly cost threshold for recommendations
            include_unused_resources: Include unused security resources
            include_overprovisioned: Include overprovisioned resources
            
        Returns:
            Security cost optimization recommendations
        """
        
        try:
            response = await self.mcp_clients['security_hub'].call_mcp_tool(
                'analyze_security_costs',
                {
                    'cost_threshold': cost_threshold_monthly,
                    'include_unused': include_unused_resources,
                    'include_overprovisioned': include_overprovisioned,
                    'analyze_log_retention': True,
                    'analyze_backup_costs': True,
                    'include_compliance_costs': True
                }
            )
            
            optimization = {
                'cost_summary': {
                    'current_monthly_security_spend': response.get('current_spend', 0),
                    'potential_monthly_savings': response.get('potential_savings', 0),
                    'optimization_percentage': response.get('optimization_percentage', 0)
                },
                'optimization_opportunities': {
                    'unused_resources': response.get('unused_resources', []),
                    'overprovisioned_services': response.get('overprovisioned', []),
                    'log_optimization': response.get('log_optimization', []),
                    'backup_optimization': response.get('backup_optimization', [])
                },
                'implementation_plan': self._generate_cost_optimization_plan(response),
                'risk_assessment': self._assess_cost_optimization_risks(response)
            }
            
            return optimization
            
        except Exception as e:
            self.logger.error(f"Security cost optimization failed: {e}")
            raise
    
    def _parse_security_hub_findings(self, findings_data: List[Dict[str, Any]]) -> List[AWSSecurityFinding]:
        """Parse Security Hub findings into structured objects."""
        
        findings = []
        
        for finding_data in findings_data:
            try:
                finding = AWSSecurityFinding(
                    finding_id=finding_data['Id'],
                    aws_account_id=finding_data['AwsAccountId'],
                    region=finding_data['Region'],
                    severity=AWSSecuritySeverity(finding_data['Severity']['Label']),
                    finding_type=finding_data['Types'][0] if finding_data['Types'] else 'Unknown',
                    resource_type=finding_data['Resources'][0]['Type'] if finding_data['Resources'] else 'Unknown',
                    resource_id=finding_data['Resources'][0]['Id'] if finding_data['Resources'] else 'Unknown',
                    resource_arn=finding_data['Resources'][0]['Id'] if finding_data['Resources'] else 'Unknown',
                    title=finding_data['Title'],
                    description=finding_data['Description'],
                    remediation=finding_data.get('Remediation', {}),
                    compliance_frameworks=self._extract_compliance_frameworks(finding_data),
                    first_observed=self._parse_datetime(finding_data.get('FirstObservedAt')),
                    last_observed=self._parse_datetime(finding_data.get('LastObservedAt')),
                    raw_data=finding_data
                )
                findings.append(finding)
                
            except Exception as e:
                self.logger.warning(f"Failed to parse Security Hub finding: {e}")
                continue
        
        return findings
    
    def _parse_cloudtrail_events(self, events_data: List[Dict[str, Any]]) -> List[AWSCloudTrailEvent]:
        """Parse CloudTrail events into structured objects."""
        
        events = []
        
        for event_data in events_data:
            try:
                event = AWSCloudTrailEvent(
                    event_id=event_data['EventId'],
                    event_time=self._parse_datetime(event_data['EventTime']),
                    event_name=event_data['EventName'],
                    event_source=event_data['EventSource'],
                    user_identity=event_data.get('UserIdentity', {}),
                    source_ip=event_data.get('SourceIPAddress', ''),
                    user_agent=event_data.get('UserAgent', ''),
                    aws_region=event_data.get('AwsRegion', ''),
                    request_parameters=event_data.get('RequestParameters', {}),
                    response_elements=event_data.get('ResponseElements', {}),
                    error_code=event_data.get('ErrorCode'),
                    error_message=event_data.get('ErrorMessage'),
                    risk_score=self._calculate_event_risk_score(event_data),
                    threat_indicators=self._extract_event_threat_indicators(event_data),
                    raw_data=event_data
                )
                events.append(event)
                
            except Exception as e:
                self.logger.warning(f"Failed to parse CloudTrail event: {e}")
                continue
        
        return events
    
    def _parse_config_rules(self, rules_data: List[Dict[str, Any]]) -> List[AWSConfigRule]:
        """Parse Config rules into structured objects."""
        
        rules = []
        
        for rule_data in rules_data:
            try:
                rule = AWSConfigRule(
                    rule_name=rule_data['ConfigRuleName'],
                    rule_arn=rule_data['ConfigRuleArn'],
                    config_rule_state=rule_data['ConfigRuleState'],
                    compliance_status=AWSComplianceStatus(rule_data.get('ComplianceStatus', 'INSUFFICIENT_DATA')),
                    source=rule_data['Source']['Owner'],
                    scope=rule_data.get('Scope', {}),
                    last_evaluation=self._parse_datetime(rule_data.get('LastEvaluationTime')),
                    non_compliant_resources=rule_data.get('NonCompliantResources', []),
                    remediation_configuration=rule_data.get('RemediationConfiguration', {})
                )
                rules.append(rule)
                
            except Exception as e:
                self.logger.warning(f"Failed to parse Config rule: {e}")
                continue
        
        return rules
    
    def _calculate_event_risk_score(self, event_data: Dict[str, Any]) -> int:
        """Calculate risk score for CloudTrail event."""
        
        base_score = 10
        
        # High-risk operations
        if event_data['EventName'] in self.monitoring_rules['privileged_api_calls']:
            base_score += 40
        
        # Infrastructure changes
        if event_data['EventName'] in self.monitoring_rules['infrastructure_changes']:
            base_score += 30
        
        # Error events
        if event_data.get('ErrorCode'):
            base_score += 20
        
        # Root user activity
        user_identity = event_data.get('UserIdentity', {})
        if user_identity.get('type') == 'Root':
            base_score += 30
        
        # Cross-account activity
        if 'AssumeRole' in event_data['EventName']:
            base_score += 15
        
        return min(100, base_score)
    
    def _extract_event_threat_indicators(self, event_data: Dict[str, Any]) -> List[str]:
        """Extract threat indicators from CloudTrail event."""
        
        indicators = []
        
        # Suspicious IP patterns
        source_ip = event_data.get('SourceIPAddress', '')
        if source_ip and self._is_suspicious_ip(source_ip):
            indicators.append(f"suspicious_ip:{source_ip}")
        
        # Suspicious user agents
        user_agent = event_data.get('UserAgent', '')
        if user_agent and 'aws-cli' not in user_agent.lower():
            if any(pattern in user_agent.lower() for pattern in ['curl', 'wget', 'python', 'boto']):
                indicators.append(f"suspicious_user_agent:{user_agent}")
        
        # Failed authentication attempts
        if event_data.get('ErrorCode') in ['SigninFailure', 'InvalidUserID.NotFound']:
            indicators.append("failed_authentication")
        
        return indicators
    
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address appears suspicious."""
        # This would integrate with threat intelligence feeds
        # For now, basic checks
        return False
    
    def _parse_datetime(self, datetime_str: Optional[str]) -> Optional[datetime]:
        """Parse datetime string safely."""
        if not datetime_str:
            return None
        try:
            return datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
        except:
            return None
    
    async def get_comprehensive_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status across all AWS services."""
        
        try:
            # Parallel execution of all security checks
            security_hub_task = self.analyze_security_hub_findings(
                severity_filter=[AWSSecuritySeverity.CRITICAL, AWSSecuritySeverity.HIGH],
                time_range_hours=24
            )
            
            cloudtrail_task = self.analyze_cloudtrail_events(
                time_range_hours=24,
                privilege_escalation_detection=True
            )
            
            compliance_task = self.assess_config_compliance(
                compliance_frameworks=['NIST_CSF_2.0', 'CIS_AWS_Foundations']
            )
            
            # Execute all tasks concurrently
            security_hub_results, cloudtrail_results, compliance_results = await asyncio.gather(
                security_hub_task,
                cloudtrail_task, 
                compliance_task,
                return_exceptions=True
            )
            
            comprehensive_status = {
                'overall_security_posture': {
                    'risk_level': self._calculate_overall_risk_level([
                        security_hub_results, cloudtrail_results, compliance_results
                    ]),
                    'critical_findings_count': self._count_critical_findings([
                        security_hub_results, cloudtrail_results, compliance_results
                    ]),
                    'compliance_score': compliance_results.get('compliance_overview', {}).get('compliance_percentage', 0) if not isinstance(compliance_results, Exception) else 0
                },
                'security_hub_analysis': security_hub_results if not isinstance(security_hub_results, Exception) else {'error': str(security_hub_results)},
                'cloudtrail_analysis': cloudtrail_results if not isinstance(cloudtrail_results, Exception) else {'error': str(cloudtrail_results)},
                'compliance_assessment': compliance_results if not isinstance(compliance_results, Exception) else {'error': str(compliance_results)},
                'recommendations': self._generate_comprehensive_recommendations([
                    security_hub_results, cloudtrail_results, compliance_results
                ]),
                'last_updated': datetime.utcnow().isoformat()
            }
            
            return comprehensive_status
            
        except Exception as e:
            self.logger.error(f"Comprehensive security status failed: {e}")
            raise


# Configuration helpers for AWS MCP integration
def create_aws_security_configs(regions: List[str] = None) -> Dict[str, AWSSecurityMCPClient]:
    """Create AWS Security MCP clients for multiple regions."""
    
    if regions is None:
        regions = ['us-west-2', 'us-east-1', 'eu-west-1']
    
    clients = {}
    for region in regions:
        clients[region] = AWSSecurityMCPClient(aws_region=region)
    
    return clients


# Example multi-region security monitoring
async def example_multi_region_monitoring():
    """Example multi-region security monitoring workflow."""
    
    regions = ['us-west-2', 'us-east-1', 'eu-west-1']
    clients = create_aws_security_configs(regions)
    
    try:
        # Monitor all regions concurrently
        monitoring_tasks = []
        for region, client in clients.items():
            task = client.get_comprehensive_security_status()
            monitoring_tasks.append((region, task))
        
        # Execute all monitoring tasks
        results = {}
        for region, task in monitoring_tasks:
            try:
                results[region] = await task
                print(f"✅ {region}: Security monitoring complete")
            except Exception as e:
                print(f"❌ {region}: Security monitoring failed - {e}")
                results[region] = {'error': str(e)}
        
        # Global security summary
        global_summary = {
            'total_regions_monitored': len(results),
            'successful_regions': sum(1 for r in results.values() if 'error' not in r),
            'overall_risk_level': 'medium',  # Would calculate from all regions
            'cross_region_threats': [],  # Would correlate threats across regions
            'regional_results': results
        }
        
        print(f"Global Security Summary: {global_summary}")
        
    except Exception as e:
        print(f"Multi-region monitoring failed: {e}")


if __name__ == "__main__":
    # Would be run in async context with proper AWS credentials
    # asyncio.run(example_multi_region_monitoring())
    pass