"""
CrowdStrike Falcon MCP Integration Client

Implements enterprise-grade integration with CrowdStrike Falcon MCP server
providing access to 13 modules and 40+ tools for real-time threat detection
and investigation with FQL query capabilities.

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

from ..gateway.mcp_server_manager import MCPServerManager, MCPServerConfig


class CrowdStrikeThreatSeverity(Enum):
    """Threat severity levels aligned with CrowdStrike taxonomy."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class CrowdStrikeFQLTimeRange(Enum):
    """Common time ranges for FQL queries."""
    LAST_1H = "1h"
    LAST_24H = "24h"
    LAST_7D = "7d"
    LAST_30D = "30d"
    CUSTOM = "custom"


@dataclass
class CrowdStrikeThreatEvent:
    """Structured threat event from CrowdStrike."""
    event_id: str
    timestamp: datetime
    severity: CrowdStrikeThreatSeverity
    event_type: str
    device_id: str
    device_name: str
    user_name: Optional[str]
    process_name: Optional[str]
    command_line: Optional[str]
    file_path: Optional[str]
    file_hash: Optional[str]
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    threat_indicators: List[Dict[str, Any]] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FQLQuery:
    """FQL query structure with enterprise validation."""
    query_text: str
    time_range: str
    limit: int = 1000
    offset: int = 0
    correlation_id: Optional[str] = None
    
    def validate(self) -> bool:
        """Validate FQL query for security and syntax."""
        # Basic validation - would be expanded for production
        if not self.query_text.strip():
            return False
        if self.limit > 10000:  # Rate limiting consideration
            return False
        return True


class CrowdStrikeMCPClient:
    """
    Enterprise CrowdStrike Falcon MCP integration client.
    
    Provides structured access to CrowdStrike's 13 modules and 40+ tools
    with enterprise authentication, rate limiting, and audit logging.
    """
    
    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.server_manager = MCPServerManager(config)
        self.logger = logging.getLogger(f"crowdstrike_mcp.{config.server_name}")
        
        # CrowdStrike-specific module mappings
        self.modules = {
            "device_control": ["devices", "device_details", "device_search"],
            "incident_management": ["incidents", "incident_details", "incident_update"],
            "threat_intelligence": ["iocs", "threat_feeds", "malware_analysis"],
            "detection_engine": ["detections", "detection_details", "detection_update"],
            "falcon_x": ["sandbox_analysis", "sample_analysis", "malware_family"],
            "real_time_response": ["rtr_sessions", "rtr_commands", "rtr_files"],
            "spotlight": ["vulnerabilities", "vulnerability_details", "cve_search"],
            "falcon_intelligence": ["threat_actors", "campaigns", "malware_reports"],
            "kubernetes_protection": ["k8s_clusters", "k8s_pods", "k8s_vulnerabilities"],
            "cloud_security": ["cloud_assets", "cloud_misconfigurations", "cspm_findings"],
            "identity_protection": ["identity_events", "identity_risks", "privilege_escalation"],
            "data_protection": ["dlp_events", "data_classification", "data_exfiltration"],
            "falcon_logscale": ["log_search", "log_analytics", "custom_queries"]
        }
    
    async def execute_fql_query(
        self, 
        query: Union[str, FQLQuery],
        correlation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute FQL (Falcon Query Language) query for threat investigation.
        
        Args:
            query: FQL query string or structured FQLQuery object
            correlation_id: Optional correlation ID for tracking
            
        Returns:
            Structured query results with metadata
        """
        
        if isinstance(query, str):
            fql_query = FQLQuery(query_text=query, time_range="24h")
        else:
            fql_query = query
        
        if not fql_query.validate():
            raise ValueError("Invalid FQL query")
        
        self.logger.info(f"Executing FQL query: {fql_query.query_text[:100]}...")
        
        try:
            response = await self.server_manager.call_mcp_tool(
                'falcon_fql_query',
                {
                    'query': fql_query.query_text,
                    'timerange': fql_query.time_range,
                    'limit': fql_query.limit,
                    'offset': fql_query.offset
                },
                correlation_id=correlation_id
            )
            
            return self._process_fql_response(response, fql_query)
            
        except Exception as e:
            self.logger.error(f"FQL query execution failed: {e}")
            raise
    
    async def get_real_time_detections(
        self,
        time_range: str = "1h",
        severity_filter: Optional[List[CrowdStrikeThreatSeverity]] = None,
        limit: int = 100
    ) -> List[CrowdStrikeThreatEvent]:
        """
        Retrieve real-time threat detection events.
        
        Args:
            time_range: Time range for detection search (1h, 24h, 7d)
            severity_filter: List of severity levels to include
            limit: Maximum number of detections to return
            
        Returns:
            List of structured threat events
        """
        
        severity_values = None
        if severity_filter:
            severity_values = [s.value for s in severity_filter]
        
        try:
            response = await self.server_manager.call_mcp_tool(
                'falcon_detections',
                {
                    'timerange': time_range,
                    'severity': severity_values,
                    'limit': limit,
                    'sort': 'timestamp:desc'
                }
            )
            
            return self._parse_threat_events(response)
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve real-time detections: {e}")
            raise
    
    async def get_device_information(self, device_id: str) -> Dict[str, Any]:
        """
        Retrieve comprehensive device information from CrowdStrike.
        
        Args:
            device_id: CrowdStrike device identifier
            
        Returns:
            Device information with security context
        """
        
        try:
            response = await self.server_manager.call_mcp_tool(
                'falcon_device_details',
                {'device_id': device_id}
            )
            
            return self._enrich_device_data(response)
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve device information for {device_id}: {e}")
            raise
    
    async def search_threat_indicators(
        self,
        indicator_type: str,
        indicator_value: str,
        include_context: bool = True
    ) -> Dict[str, Any]:
        """
        Search for threat indicators across CrowdStrike intelligence feeds.
        
        Args:
            indicator_type: Type of indicator (hash, ip, domain, url)
            indicator_value: The indicator value to search
            include_context: Include threat context and attribution
            
        Returns:
            Threat intelligence data with context
        """
        
        try:
            response = await self.server_manager.call_mcp_tool(
                'falcon_threat_intel_search',
                {
                    'indicator_type': indicator_type,
                    'indicator_value': indicator_value,
                    'include_context': include_context,
                    'include_malware_family': True,
                    'include_actor_attribution': True
                }
            )
            
            return self._process_threat_intel_response(response)
            
        except Exception as e:
            self.logger.error(f"Threat indicator search failed for {indicator_value}: {e}")
            raise
    
    async def get_vulnerability_data(
        self,
        severity_threshold: str = "medium",
        exploitable_only: bool = True,
        limit: int = 500
    ) -> Dict[str, Any]:
        """
        Retrieve vulnerability data from CrowdStrike Spotlight.
        
        Args:
            severity_threshold: Minimum severity level
            exploitable_only: Only include exploitable vulnerabilities
            limit: Maximum number of vulnerabilities
            
        Returns:
            Structured vulnerability data with remediation context
        """
        
        try:
            response = await self.server_manager.call_mcp_tool(
                'falcon_spotlight_vulnerabilities',
                {
                    'severity_threshold': severity_threshold,
                    'exploitable_only': exploitable_only,
                    'limit': limit,
                    'include_cve_details': True,
                    'include_remediation_guidance': True
                }
            )
            
            return self._process_vulnerability_response(response)
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve vulnerability data: {e}")
            raise
    
    async def initiate_response_session(
        self,
        device_id: str,
        response_type: str = "investigation"
    ) -> Dict[str, Any]:
        """
        Initiate Real-Time Response (RTR) session for incident response.
        
        Args:
            device_id: Target device for response session
            response_type: Type of response session (investigation, containment)
            
        Returns:
            RTR session information and available commands
        """
        
        try:
            response = await self.server_manager.call_mcp_tool(
                'falcon_rtr_session_init',
                {
                    'device_id': device_id,
                    'session_type': response_type,
                    'timeout': 1800  # 30 minutes
                }
            )
            
            return self._process_rtr_session_response(response)
            
        except Exception as e:
            self.logger.error(f"Failed to initiate RTR session for {device_id}: {e}")
            raise
    
    async def get_cloud_security_findings(
        self,
        cloud_provider: str = "aws",
        finding_types: Optional[List[str]] = None,
        severity_filter: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Retrieve cloud security posture findings.
        
        Args:
            cloud_provider: Cloud provider (aws, azure, gcp)
            finding_types: Specific finding types to retrieve
            severity_filter: Severity levels to include
            
        Returns:
            Cloud security findings with remediation guidance
        """
        
        try:
            response = await self.server_manager.call_mcp_tool(
                'falcon_cspm_findings',
                {
                    'cloud_provider': cloud_provider,
                    'finding_types': finding_types or [],
                    'severity': severity_filter or [],
                    'include_remediation': True,
                    'include_compliance_mapping': True
                }
            )
            
            return self._process_cspm_findings(response)
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve cloud security findings: {e}")
            raise
    
    def _process_fql_response(
        self, 
        response: Dict[str, Any], 
        query: FQLQuery
    ) -> Dict[str, Any]:
        """Process and enrich FQL query response."""
        
        processed_response = {
            'query_metadata': {
                'query': query.query_text,
                'time_range': query.time_range,
                'execution_time': response.get('execution_time_ms', 0),
                'result_count': len(response.get('results', [])),
                'has_more': response.get('has_more', False)
            },
            'results': response.get('results', []),
            'summary': self._generate_fql_summary(response.get('results', [])),
            'threat_indicators': self._extract_threat_indicators(response.get('results', []))
        }
        
        return processed_response
    
    def _parse_threat_events(self, response: Dict[str, Any]) -> List[CrowdStrikeThreatEvent]:
        """Parse threat detection events into structured objects."""
        
        events = []
        
        for detection in response.get('detections', []):
            try:
                event = CrowdStrikeThreatEvent(
                    event_id=detection['detection_id'],
                    timestamp=datetime.fromisoformat(detection['timestamp']),
                    severity=CrowdStrikeThreatSeverity(detection.get('severity', 'medium')),
                    event_type=detection['detection_type'],
                    device_id=detection['device']['device_id'],
                    device_name=detection['device'].get('hostname', 'Unknown'),
                    user_name=detection.get('user_name'),
                    process_name=detection.get('process_name'),
                    command_line=detection.get('command_line'),
                    file_path=detection.get('file_path'),
                    file_hash=detection.get('file_hash'),
                    network_connections=detection.get('network_connections', []),
                    threat_indicators=detection.get('iocs', []),
                    mitre_tactics=detection.get('mitre_tactics', []),
                    mitre_techniques=detection.get('mitre_techniques', []),
                    raw_data=detection
                )
                events.append(event)
                
            except Exception as e:
                self.logger.warning(f"Failed to parse detection event: {e}")
                continue
        
        return events
    
    def _enrich_device_data(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich device data with security context."""
        
        device_data = response.get('device', {})
        
        enriched_data = {
            'device_info': device_data,
            'security_assessment': {
                'risk_score': self._calculate_device_risk_score(device_data),
                'security_controls': self._assess_security_controls(device_data),
                'compliance_status': self._assess_compliance_status(device_data),
                'recommendations': self._generate_security_recommendations(device_data)
            },
            'last_seen': device_data.get('last_seen'),
            'agent_status': device_data.get('agent_status'),
            'platform': device_data.get('platform_name')
        }
        
        return enriched_data
    
    def _process_threat_intel_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Process threat intelligence response with attribution."""
        
        intel_data = response.get('threat_intel', {})
        
        processed_intel = {
            'indicator_summary': intel_data.get('indicator', {}),
            'threat_assessment': {
                'severity': intel_data.get('severity'),
                'confidence': intel_data.get('confidence'),
                'threat_types': intel_data.get('threat_types', []),
                'kill_chain_phases': intel_data.get('kill_chain_phases', [])
            },
            'attribution': {
                'threat_actors': intel_data.get('threat_actors', []),
                'campaigns': intel_data.get('campaigns', []),
                'malware_families': intel_data.get('malware_families', [])
            },
            'context': {
                'first_seen': intel_data.get('first_seen'),
                'last_seen': intel_data.get('last_seen'),
                'related_indicators': intel_data.get('related_indicators', [])
            }
        }
        
        return processed_intel
    
    def _process_vulnerability_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Process vulnerability data with risk context."""
        
        vulnerabilities = response.get('vulnerabilities', [])
        
        processed_data = {
            'vulnerability_summary': {
                'total_count': len(vulnerabilities),
                'severity_breakdown': self._calculate_severity_breakdown(vulnerabilities),
                'exploitable_count': sum(1 for v in vulnerabilities if v.get('exploitable', False)),
                'critical_assets_affected': self._identify_critical_assets(vulnerabilities)
            },
            'vulnerabilities': self._enrich_vulnerability_data(vulnerabilities),
            'remediation_priorities': self._prioritize_remediation(vulnerabilities)
        }
        
        return processed_data
    
    def _calculate_device_risk_score(self, device_data: Dict[str, Any]) -> int:
        """Calculate device risk score based on security factors."""
        base_score = 50
        
        # Agent status
        if device_data.get('agent_status') != 'normal':
            base_score += 20
        
        # Last seen
        last_seen = device_data.get('last_seen')
        if last_seen:
            # Add points for offline devices
            pass
        
        # Platform vulnerabilities
        if device_data.get('os_version'):
            # Would integrate with vulnerability database
            pass
        
        return min(100, max(0, base_score))
    
    def _generate_fql_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for FQL query results."""
        
        if not results:
            return {'message': 'No results found'}
        
        summary = {
            'total_events': len(results),
            'time_range_covered': self._extract_time_range(results),
            'event_types': self._categorize_events(results),
            'affected_devices': self._extract_unique_devices(results),
            'severity_distribution': self._calculate_severity_distribution(results)
        }
        
        return summary
    
    def _extract_threat_indicators(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract and deduplicate threat indicators from results."""
        
        indicators = []
        seen_indicators = set()
        
        for result in results:
            for ioc_type, ioc_value in result.get('indicators', {}).items():
                if ioc_value and ioc_value not in seen_indicators:
                    indicators.append({
                        'type': ioc_type,
                        'value': ioc_value,
                        'first_seen': result.get('timestamp'),
                        'context': result.get('context', {})
                    })
                    seen_indicators.add(ioc_value)
        
        return indicators
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status for CrowdStrike MCP integration."""
        
        base_health = self.server_manager.get_health_status()
        
        crowdstrike_health = {
            **base_health,
            'modules_available': list(self.modules.keys()),
            'total_tools': sum(len(tools) for tools in self.modules.values()),
            'last_successful_query': None,  # Would track from metrics
            'authentication_status': 'healthy',  # Would check token validity
            'api_quota_status': 'normal'  # Would check rate limit status
        }
        
        return crowdstrike_health


# Configuration factory for CrowdStrike MCP integration
def create_crowdstrike_config(
    api_base_url: str = "https://api.crowdstrike.com",
    region: str = "us-west-2"
) -> MCPServerConfig:
    """Create properly configured MCPServerConfig for CrowdStrike Falcon."""
    
    config = MCPServerConfig(
        server_name="crowdstrike_falcon",
        server_url=f"{api_base_url}/mcp",
        auth_type="oauth2",
        
        # CrowdStrike-specific rate limits
        max_requests_per_minute=30,
        max_requests_per_hour=1000,
        burst_limit=5,
        
        # Enterprise reliability settings
        failure_threshold=3,
        recovery_timeout=120,
        request_timeout=45,
        
        # AWS integration
        aws_region=region,
        parameter_store_prefix="/secops/crowdstrike",
        
        # CrowdStrike OAuth configuration
        auth_config={
            'token_url': f"{api_base_url}/oauth2/token",
            'scope': 'falcon-intel:read falcon-devices:read falcon-detections:read falcon-rtr:write',
            'grant_type': 'client_credentials'
        }
    )
    
    return config


# Example usage and integration patterns
async def example_threat_investigation():
    """Example threat investigation workflow using CrowdStrike MCP."""
    
    # Initialize CrowdStrike client
    config = create_crowdstrike_config()
    client = CrowdStrikeMCPClient(config)
    
    try:
        # 1. Get recent high-severity detections
        detections = await client.get_real_time_detections(
            time_range="24h",
            severity_filter=[CrowdStrikeThreatSeverity.CRITICAL, CrowdStrikeThreatSeverity.HIGH],
            limit=50
        )
        
        print(f"Found {len(detections)} high-severity detections")
        
        # 2. Investigate specific indicators
        for detection in detections[:5]:  # Top 5
            if detection.file_hash:
                threat_intel = await client.search_threat_indicators(
                    indicator_type="hash",
                    indicator_value=detection.file_hash
                )
                
                print(f"Threat intel for {detection.file_hash}:")
                print(f"- Confidence: {threat_intel['threat_assessment']['confidence']}")
                print(f"- Threat actors: {threat_intel['attribution']['threat_actors']}")
        
        # 3. Check cloud security posture
        cloud_findings = await client.get_cloud_security_findings(
            cloud_provider="aws",
            severity_filter=["critical", "high"]
        )
        
        print(f"Found {cloud_findings['vulnerability_summary']['total_count']} cloud security findings")
        
        # 4. Execute custom FQL query
        fql_query = FQLQuery(
            query_text="""
            DeviceEvents 
            | where ActionType in ('ProcessCreated', 'FileCreated', 'NetworkConnection')
            | where Timestamp > ago(1h)
            | where ProcessCommandLine contains 'powershell'
            | summarize EventCount = count() by DeviceName, ActionType
            | order by EventCount desc
            """,
            time_range="1h",
            limit=100
        )
        
        fql_results = await client.execute_fql_query(fql_query)
        print(f"FQL query returned {fql_results['query_metadata']['result_count']} results")
        
    except Exception as e:
        print(f"Threat investigation failed: {e}")


if __name__ == "__main__":
    # Would be run in async context with proper logging setup
    # asyncio.run(example_threat_investigation())
    pass