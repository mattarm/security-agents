"""
MCP Server Manager - Enterprise-grade MCP server integration with authentication, 
rate limiting, and circuit breaker patterns.

Implementation Pattern for SecurityAgents Platform Phase 2B
Author: Tiger Team Alpha-2 Integration Specialist
"""

import asyncio
import time
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
import json

# Third-party imports for enterprise patterns
import aiohttp
import boto3
from botocore.exceptions import ClientError


class CircuitBreakerState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class MCPServerConfig:
    """Configuration for MCP server connection with enterprise security settings."""
    server_name: str
    server_url: str
    auth_type: str  # oauth2, api_key, iam
    
    # Rate limiting configuration
    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    burst_limit: int = 10
    
    # Circuit breaker configuration
    failure_threshold: int = 5
    recovery_timeout: int = 60  # seconds
    success_threshold: int = 3  # for half-open state
    
    # Timeout configuration
    request_timeout: int = 30
    connection_timeout: int = 10
    
    # Authentication configuration
    auth_config: Dict[str, Any] = field(default_factory=dict)
    
    # AWS integration
    aws_region: str = "us-west-2"
    parameter_store_prefix: str = "/secops/mcp"


class RateLimiter:
    """Enterprise-grade rate limiter with burst handling and backpressure."""
    
    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.requests_minute = []
        self.requests_hour = []
        self.burst_tokens = config.burst_limit
        self.last_refill = time.time()
        
    async def acquire(self) -> bool:
        """Acquire rate limit token with intelligent backoff."""
        now = time.time()
        
        # Refill burst tokens
        time_passed = now - self.last_refill
        if time_passed >= 1.0:  # Refill every second
            self.burst_tokens = min(
                self.config.burst_limit, 
                self.burst_tokens + int(time_passed)
            )
            self.last_refill = now
        
        # Clean old requests from tracking
        minute_ago = now - 60
        hour_ago = now - 3600
        
        self.requests_minute = [r for r in self.requests_minute if r > minute_ago]
        self.requests_hour = [r for r in self.requests_hour if r > hour_ago]
        
        # Check limits
        if len(self.requests_minute) >= self.config.max_requests_per_minute:
            return False
        if len(self.requests_hour) >= self.config.max_requests_per_hour:
            return False
        if self.burst_tokens <= 0:
            return False
        
        # Acquire token
        self.requests_minute.append(now)
        self.requests_hour.append(now)
        self.burst_tokens -= 1
        
        return True
    
    def get_wait_time(self) -> int:
        """Calculate intelligent wait time for backoff."""
        now = time.time()
        minute_ago = now - 60
        
        # Clean old requests
        self.requests_minute = [r for r in self.requests_minute if r > minute_ago]
        
        if len(self.requests_minute) >= self.config.max_requests_per_minute:
            # Wait until oldest request ages out
            oldest = min(self.requests_minute)
            return max(1, int(oldest + 60 - now))
        
        if self.burst_tokens <= 0:
            return 1  # Wait 1 second for token refill
        
        return 0


class CircuitBreaker:
    """Circuit breaker pattern for MCP server reliability."""
    
    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.success_count = 0
        
    def can_request(self) -> bool:
        """Check if requests are allowed based on circuit breaker state."""
        if self.state == CircuitBreakerState.CLOSED:
            return True
        elif self.state == CircuitBreakerState.OPEN:
            if (time.time() - self.last_failure_time) > self.config.recovery_timeout:
                self.state = CircuitBreakerState.HALF_OPEN
                self.success_count = 0
                return True
            return False
        else:  # HALF_OPEN
            return True
    
    def record_success(self):
        """Record successful request."""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
        else:
            self.failure_count = 0
    
    def record_failure(self):
        """Record failed request."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.config.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            self.success_count = 0


class AuthManager:
    """Enterprise authentication manager with AWS integration."""
    
    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.session = None
        self.token_cache = {}
        self.ssm_client = None
        
        if config.auth_type in ["oauth2", "api_key"]:
            self._init_aws_clients()
    
    def _init_aws_clients(self):
        """Initialize AWS clients for parameter store access."""
        try:
            self.ssm_client = boto3.client('ssm', region_name=self.config.aws_region)
        except Exception as e:
            logging.error(f"Failed to initialize AWS clients: {e}")
    
    async def get_credentials(self) -> Dict[str, str]:
        """Retrieve credentials from AWS Parameter Store."""
        if not self.ssm_client:
            return self.config.auth_config
        
        credentials = {}
        param_prefix = f"{self.config.parameter_store_prefix}/{self.config.server_name}"
        
        try:
            # Get parameters from Parameter Store
            params_to_fetch = [
                f"{param_prefix}/client_id",
                f"{param_prefix}/client_secret", 
                f"{param_prefix}/api_key",
                f"{param_prefix}/access_token"
            ]
            
            for param_name in params_to_fetch:
                try:
                    response = self.ssm_client.get_parameter(
                        Name=param_name, 
                        WithDecryption=True
                    )
                    key = param_name.split('/')[-1]
                    credentials[key] = response['Parameter']['Value']
                except ClientError as e:
                    if e.response['Error']['Code'] != 'ParameterNotFound':
                        logging.warning(f"Could not fetch {param_name}: {e}")
        
        except Exception as e:
            logging.error(f"Error fetching credentials from Parameter Store: {e}")
            return self.config.auth_config
        
        return {**self.config.auth_config, **credentials}
    
    async def get_access_token(self) -> Optional[str]:
        """Get OAuth2 access token with caching."""
        if self.config.auth_type != "oauth2":
            return None
        
        # Check cache
        cache_key = f"{self.config.server_name}_token"
        if cache_key in self.token_cache:
            token_data = self.token_cache[cache_key]
            if token_data['expires_at'] > time.time():
                return token_data['access_token']
        
        # Fetch new token
        credentials = await self.get_credentials()
        token = await self._fetch_oauth_token(credentials)
        
        if token:
            self.token_cache[cache_key] = {
                'access_token': token['access_token'],
                'expires_at': time.time() + token.get('expires_in', 3600) - 60  # 1min buffer
            }
            return token['access_token']
        
        return None
    
    async def _fetch_oauth_token(self, credentials: Dict[str, str]) -> Optional[Dict]:
        """Fetch OAuth2 token using client credentials flow."""
        token_url = credentials.get('token_url')
        client_id = credentials.get('client_id')
        client_secret = credentials.get('client_secret')
        
        if not all([token_url, client_id, client_secret]):
            logging.error("Missing OAuth2 credentials")
            return None
        
        async with aiohttp.ClientSession() as session:
            data = {
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret
            }
            
            try:
                async with session.post(token_url, data=data) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logging.error(f"OAuth token request failed: {response.status}")
                        return None
            except Exception as e:
                logging.error(f"OAuth token request error: {e}")
                return None


class MCPServerManager:
    """Enterprise MCP server manager with comprehensive reliability patterns."""
    
    def __init__(self, server_config: MCPServerConfig):
        self.config = server_config
        self.auth_manager = AuthManager(server_config)
        self.rate_limiter = RateLimiter(server_config)
        self.circuit_breaker = CircuitBreaker(server_config)
        
        # Audit logging
        self.logger = logging.getLogger(f"mcp_server.{server_config.server_name}")
        self.audit_logger = logging.getLogger(f"audit.{server_config.server_name}")
        
        # Metrics tracking
        self.metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'rate_limited_requests': 0,
            'circuit_breaker_trips': 0,
            'avg_response_time': 0.0,
            'last_request_time': None
        }
    
    async def call_mcp_tool(
        self, 
        tool_name: str, 
        params: Dict[str, Any],
        correlation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Call MCP tool with enterprise reliability patterns:
        - Authentication with AWS Parameter Store
        - Rate limiting with intelligent backoff
        - Circuit breaker for fault tolerance
        - Complete audit logging
        - Performance metrics
        """
        
        start_time = time.time()
        correlation_id = correlation_id or str(uuid.uuid4())
        
        # Update metrics
        self.metrics['total_requests'] += 1
        self.metrics['last_request_time'] = datetime.now()
        
        # Audit log request initiation
        self.audit_logger.info({
            'event': 'mcp_request_start',
            'correlation_id': correlation_id,
            'server': self.config.server_name,
            'tool': tool_name,
            'timestamp': datetime.utcnow().isoformat(),
            'params_count': len(params)
        })
        
        try:
            # Circuit breaker check
            if not self.circuit_breaker.can_request():
                self.metrics['circuit_breaker_trips'] += 1
                raise Exception(f"Circuit breaker OPEN for {self.config.server_name}")
            
            # Rate limiting
            if not await self.rate_limiter.acquire():
                wait_time = self.rate_limiter.get_wait_time()
                self.metrics['rate_limited_requests'] += 1
                
                self.logger.warning(f"Rate limited, waiting {wait_time}s")
                await asyncio.sleep(wait_time)
                
                if not await self.rate_limiter.acquire():
                    raise Exception(f"Rate limit exceeded for {self.config.server_name}")
            
            # Authentication
            auth_headers = await self._prepare_auth_headers()
            
            # Make MCP request
            response = await self._make_mcp_request(
                tool_name, 
                params, 
                auth_headers,
                correlation_id
            )
            
            # Record success
            self.circuit_breaker.record_success()
            self.metrics['successful_requests'] += 1
            
            # Update response time metrics
            response_time = time.time() - start_time
            self._update_response_time_metric(response_time)
            
            # Audit log success
            self.audit_logger.info({
                'event': 'mcp_request_success',
                'correlation_id': correlation_id,
                'server': self.config.server_name,
                'tool': tool_name,
                'response_time_ms': int(response_time * 1000),
                'timestamp': datetime.utcnow().isoformat()
            })
            
            return response
            
        except Exception as e:
            # Record failure
            self.circuit_breaker.record_failure()
            self.metrics['failed_requests'] += 1
            
            # Audit log failure
            self.audit_logger.error({
                'event': 'mcp_request_failure',
                'correlation_id': correlation_id,
                'server': self.config.server_name,
                'tool': tool_name,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
            
            raise e
    
    async def _prepare_auth_headers(self) -> Dict[str, str]:
        """Prepare authentication headers based on auth type."""
        headers = {'Content-Type': 'application/json'}
        
        if self.config.auth_type == "oauth2":
            access_token = await self.auth_manager.get_access_token()
            if access_token:
                headers['Authorization'] = f'Bearer {access_token}'
        
        elif self.config.auth_type == "api_key":
            credentials = await self.auth_manager.get_credentials()
            api_key = credentials.get('api_key')
            if api_key:
                headers['X-API-Key'] = api_key
        
        return headers
    
    async def _make_mcp_request(
        self, 
        tool_name: str, 
        params: Dict[str, Any],
        auth_headers: Dict[str, str],
        correlation_id: str
    ) -> Dict[str, Any]:
        """Make the actual MCP request with timeout and error handling."""
        
        request_payload = {
            'tool': tool_name,
            'params': params,
            'correlation_id': correlation_id
        }
        
        timeout = aiohttp.ClientTimeout(
            total=self.config.request_timeout,
            connect=self.config.connection_timeout
        )
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                async with session.post(
                    self.config.server_url,
                    headers=auth_headers,
                    json=request_payload
                ) as response:
                    
                    if response.status >= 400:
                        error_text = await response.text()
                        raise Exception(f"MCP request failed: {response.status} - {error_text}")
                    
                    return await response.json()
                    
            except asyncio.TimeoutError:
                raise Exception(f"MCP request timeout after {self.config.request_timeout}s")
            except aiohttp.ClientError as e:
                raise Exception(f"MCP client error: {e}")
    
    def _update_response_time_metric(self, response_time: float):
        """Update rolling average response time."""
        current_avg = self.metrics['avg_response_time']
        total_successful = self.metrics['successful_requests']
        
        if total_successful == 1:
            self.metrics['avg_response_time'] = response_time
        else:
            # Exponential moving average
            alpha = 2.0 / (min(total_successful, 100) + 1)
            self.metrics['avg_response_time'] = (
                alpha * response_time + (1 - alpha) * current_avg
            )
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status for monitoring."""
        return {
            'server_name': self.config.server_name,
            'circuit_breaker_state': self.circuit_breaker.state.value,
            'metrics': self.metrics.copy(),
            'rate_limiter': {
                'requests_last_minute': len(self.rate_limiter.requests_minute),
                'requests_last_hour': len(self.rate_limiter.requests_hour),
                'burst_tokens_available': self.rate_limiter.burst_tokens
            },
            'last_check': datetime.utcnow().isoformat()
        }


# Example usage and testing
if __name__ == "__main__":
    # This would be moved to configuration management
    crowdstrike_config = MCPServerConfig(
        server_name="crowdstrike_falcon",
        server_url="https://api.crowdstrike.com/mcp",
        auth_type="oauth2",
        max_requests_per_minute=30,  # CrowdStrike rate limits
        max_requests_per_hour=1000,
        auth_config={
            'token_url': 'https://api.crowdstrike.com/oauth2/token'
        }
    )
    
    async def test_integration():
        manager = MCPServerManager(crowdstrike_config)
        
        try:
            # Example FQL query for threat detection
            response = await manager.call_mcp_tool(
                'fql_query',
                {
                    'query': 'DeviceEvents | where Timestamp > ago(1h) | limit 10',
                    'timerange': '1h'
                }
            )
            print("CrowdStrike MCP Response:", response)
            
            # Check health status
            health = manager.get_health_status()
            print("Health Status:", health)
            
        except Exception as e:
            print(f"Integration test failed: {e}")
    
    # Would run in async context
    # asyncio.run(test_integration())