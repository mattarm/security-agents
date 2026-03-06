"""
Performance and Load Testing for MCP Integration System

Performance testing to validate 1000+ events/hour processing capability
and <5 second response time requirements for enterprise deployment.

P0 Testing for Production Deployment Validation
"""

import pytest
import asyncio
import time
import statistics
from datetime import datetime, timedelta
from typing import List, Dict, Any
import uuid
import concurrent.futures
from dataclasses import dataclass

from mcp_integration.gateway.enterprise_mcp_gateway import (
    EnterpriseSecurityMCPGateway,
    SecurityEvent,
    EventType,
    EventSeverity
)


@dataclass
class PerformanceTestResult:
    """Performance test results structure."""
    test_name: str
    total_operations: int
    total_time_seconds: float
    throughput_per_hour: float
    average_response_time: float
    p95_response_time: float
    p99_response_time: float
    error_count: int
    error_rate: float
    success: bool
    requirements_met: Dict[str, bool]


@dataclass
class LoadTestConfiguration:
    """Load test configuration."""
    duration_seconds: int = 300  # 5 minutes
    target_rps: int = 10  # Requests per second
    ramp_up_seconds: int = 30
    max_workers: int = 20
    event_types: List[EventType] = None
    severity_distribution: Dict[EventSeverity, float] = None


class PerformanceTestSuite:
    """Performance test suite for MCP integration system."""
    
    # Performance requirements
    REQUIRED_THROUGHPUT_PER_HOUR = 1000
    REQUIRED_MAX_RESPONSE_TIME = 5.0  # seconds
    REQUIRED_P95_RESPONSE_TIME = 3.0  # seconds
    REQUIRED_MAX_ERROR_RATE = 0.05  # 5%
    
    def __init__(self):
        self.results: List[PerformanceTestResult] = []
        self.gateway = None
    
    async def setup_gateway(self) -> EnterpriseSecurityMCPGateway:
        """Set up enterprise gateway for performance testing."""
        gateway = EnterpriseSecurityMCPGateway(
            aws_region="us-west-2",
            github_token="ghp_perf_test_token"
        )
        
        # Mock platform clients for performance testing
        from unittest.mock import Mock
        gateway.platform_clients = {
            'crowdstrike': Mock(),
            'aws': Mock(),
            'github': Mock()
        }
        
        # Configure fast mock responses
        for platform in gateway.platform_clients.values():
            platform.search_threat_indicators = Mock(return_value={'confidence': 85})
            platform.analyze_cloudtrail_events = Mock(return_value={'events': []})
            platform.scan_repository_security = Mock(return_value={'score': 75})
        
        await gateway.start_gateway(num_workers=10)  # More workers for performance
        return gateway
    
    def generate_test_event(self, event_id: str = None) -> SecurityEvent:
        """Generate a test security event."""
        event_types = [EventType.THREAT_DETECTION, EventType.VULNERABILITY_DISCOVERY, 
                      EventType.COMPLIANCE_VIOLATION, EventType.INCIDENT_ESCALATION]
        severities = [EventSeverity.CRITICAL, EventSeverity.HIGH, EventSeverity.MEDIUM, EventSeverity.LOW]
        
        return SecurityEvent(
            event_id=event_id or str(uuid.uuid4()),
            event_type=event_types[int(time.time() * 1000) % len(event_types)],
            severity=severities[int(time.time() * 1000) % len(severities)],
            source_platform="performance_test",
            timestamp=datetime.utcnow(),
            correlation_id=str(uuid.uuid4()),
            title=f"Performance Test Event {event_id or 'auto'}",
            description="Generated event for performance testing",
            affected_resources=[f"resource-{event_id or 'auto'}"],
            indicators={"test_metric": f"value-{event_id or 'auto'}"}
        )
    
    async def measure_event_ingestion_performance(self, num_events: int = 1000) -> PerformanceTestResult:
        """Measure event ingestion performance."""
        gateway = await self.setup_gateway()
        
        response_times = []
        errors = 0
        
        start_time = time.time()
        
        try:
            # Generate events
            events = [self.generate_test_event(str(i)) for i in range(num_events)]
            
            # Ingest events and measure response times
            for event in events:
                event_start = time.time()
                try:
                    await gateway.ingest_security_event(event)
                    event_end = time.time()
                    response_times.append(event_end - event_start)
                except Exception:
                    errors += 1
                    response_times.append(5.0)  # Max response time for errors
            
            # Wait for processing
            await asyncio.sleep(5)
            
        finally:
            await gateway.stop_gateway()
        
        total_time = time.time() - start_time
        
        # Calculate metrics
        throughput_per_hour = (num_events / total_time) * 3600
        avg_response_time = statistics.mean(response_times) if response_times else 0
        p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else 0
        p99_response_time = statistics.quantiles(response_times, n=100)[98] if len(response_times) >= 100 else 0
        error_rate = errors / num_events
        
        requirements_met = {
            'throughput': throughput_per_hour >= self.REQUIRED_THROUGHPUT_PER_HOUR,
            'avg_response_time': avg_response_time <= self.REQUIRED_MAX_RESPONSE_TIME,
            'p95_response_time': p95_response_time <= self.REQUIRED_P95_RESPONSE_TIME,
            'error_rate': error_rate <= self.REQUIRED_MAX_ERROR_RATE
        }
        
        result = PerformanceTestResult(
            test_name="Event Ingestion Performance",
            total_operations=num_events,
            total_time_seconds=total_time,
            throughput_per_hour=throughput_per_hour,
            average_response_time=avg_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            error_count=errors,
            error_rate=error_rate,
            success=all(requirements_met.values()),
            requirements_met=requirements_met
        )
        
        self.results.append(result)
        return result
    
    async def measure_workflow_execution_performance(self, num_workflows: int = 100) -> PerformanceTestResult:
        """Measure workflow execution performance."""
        gateway = await self.setup_gateway()
        
        response_times = []
        errors = 0
        
        start_time = time.time()
        
        try:
            # Execute workflows and measure response times
            for i in range(num_workflows):
                workflow_start = time.time()
                try:
                    await gateway.execute_orchestration_workflow(
                        'threat_investigation',
                        parameters={'test_id': i, 'performance_test': True},
                        correlation_id=str(uuid.uuid4())
                    )
                    workflow_end = time.time()
                    response_times.append(workflow_end - workflow_start)
                except Exception:
                    errors += 1
                    response_times.append(10.0)  # Max response time for errors
                
        finally:
            await gateway.stop_gateway()
        
        total_time = time.time() - start_time
        
        # Calculate metrics
        throughput_per_hour = (num_workflows / total_time) * 3600
        avg_response_time = statistics.mean(response_times) if response_times else 0
        p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else 0
        p99_response_time = statistics.quantiles(response_times, n=100)[98] if len(response_times) >= 100 else 0
        error_rate = errors / num_workflows
        
        requirements_met = {
            'avg_response_time': avg_response_time <= self.REQUIRED_MAX_RESPONSE_TIME,
            'p95_response_time': p95_response_time <= self.REQUIRED_P95_RESPONSE_TIME,
            'error_rate': error_rate <= self.REQUIRED_MAX_ERROR_RATE
        }
        
        result = PerformanceTestResult(
            test_name="Workflow Execution Performance",
            total_operations=num_workflows,
            total_time_seconds=total_time,
            throughput_per_hour=throughput_per_hour,
            average_response_time=avg_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            error_count=errors,
            error_rate=error_rate,
            success=all(requirements_met.values()),
            requirements_met=requirements_met
        )
        
        self.results.append(result)
        return result
    
    async def run_sustained_load_test(self, config: LoadTestConfiguration) -> PerformanceTestResult:
        """Run sustained load test."""
        gateway = await self.setup_gateway()
        
        response_times = []
        errors = 0
        operations_completed = 0
        
        start_time = time.time()
        test_end_time = start_time + config.duration_seconds
        
        try:
            # Ramp up phase
            current_rps = 1
            while time.time() < test_end_time:
                # Calculate current target RPS (ramp up)
                elapsed = time.time() - start_time
                if elapsed < config.ramp_up_seconds:
                    current_rps = max(1, int((elapsed / config.ramp_up_seconds) * config.target_rps))
                else:
                    current_rps = config.target_rps
                
                # Execute operations for this second
                second_start = time.time()
                second_tasks = []
                
                for _ in range(current_rps):
                    if time.time() >= test_end_time:
                        break
                    
                    event = self.generate_test_event()
                    task = self._timed_event_ingestion(gateway, event)
                    second_tasks.append(task)
                
                # Wait for this second's operations to complete
                if second_tasks:
                    results = await asyncio.gather(*second_tasks, return_exceptions=True)
                    
                    for result in results:
                        operations_completed += 1
                        if isinstance(result, Exception):
                            errors += 1
                            response_times.append(5.0)
                        else:
                            response_times.append(result)
                
                # Sleep remainder of second
                elapsed_this_second = time.time() - second_start
                if elapsed_this_second < 1.0:
                    await asyncio.sleep(1.0 - elapsed_this_second)
                    
        finally:
            await gateway.stop_gateway()
        
        total_time = time.time() - start_time
        
        # Calculate metrics
        throughput_per_hour = (operations_completed / total_time) * 3600
        avg_response_time = statistics.mean(response_times) if response_times else 0
        p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else 0
        p99_response_time = statistics.quantiles(response_times, n=100)[98] if len(response_times) >= 100 else 0
        error_rate = errors / operations_completed if operations_completed > 0 else 1.0
        
        requirements_met = {
            'throughput': throughput_per_hour >= self.REQUIRED_THROUGHPUT_PER_HOUR,
            'avg_response_time': avg_response_time <= self.REQUIRED_MAX_RESPONSE_TIME,
            'p95_response_time': p95_response_time <= self.REQUIRED_P95_RESPONSE_TIME,
            'error_rate': error_rate <= self.REQUIRED_MAX_ERROR_RATE
        }
        
        result = PerformanceTestResult(
            test_name=f"Sustained Load Test ({config.target_rps} RPS)",
            total_operations=operations_completed,
            total_time_seconds=total_time,
            throughput_per_hour=throughput_per_hour,
            average_response_time=avg_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            error_count=errors,
            error_rate=error_rate,
            success=all(requirements_met.values()),
            requirements_met=requirements_met
        )
        
        self.results.append(result)
        return result
    
    async def _timed_event_ingestion(self, gateway: EnterpriseSecurityMCPGateway, event: SecurityEvent) -> float:
        """Helper method to time event ingestion."""
        start = time.time()
        try:
            await gateway.ingest_security_event(event)
            return time.time() - start
        except Exception:
            raise
    
    async def run_concurrent_user_simulation(self, num_users: int = 50, duration_seconds: int = 300) -> PerformanceTestResult:
        """Simulate concurrent users accessing the system."""
        gateway = await self.setup_gateway()
        
        response_times = []
        errors = 0
        operations_completed = 0
        
        start_time = time.time()
        
        async def user_simulation(user_id: int):
            """Simulate a single user's activity."""
            user_response_times = []
            user_errors = 0
            user_operations = 0
            
            end_time = start_time + duration_seconds
            
            while time.time() < end_time:
                try:
                    # Random operation type
                    operation_type = ["event_ingestion", "workflow_execution"][int(time.time()) % 2]
                    
                    op_start = time.time()
                    
                    if operation_type == "event_ingestion":
                        event = self.generate_test_event(f"user-{user_id}-{user_operations}")
                        await gateway.ingest_security_event(event)
                    else:
                        await gateway.execute_orchestration_workflow(
                            'threat_investigation',
                            parameters={'user_id': user_id, 'operation': user_operations}
                        )
                    
                    op_end = time.time()
                    user_response_times.append(op_end - op_start)
                    user_operations += 1
                    
                    # Random delay between operations (1-5 seconds)
                    await asyncio.sleep(1 + (time.time() % 4))
                    
                except Exception:
                    user_errors += 1
                    user_response_times.append(5.0)
            
            return user_response_times, user_errors, user_operations
        
        try:
            # Run all user simulations concurrently
            user_tasks = [user_simulation(i) for i in range(num_users)]
            user_results = await asyncio.gather(*user_tasks, return_exceptions=True)
            
            # Aggregate results
            for result in user_results:
                if not isinstance(result, Exception):
                    user_times, user_errors_count, user_ops = result
                    response_times.extend(user_times)
                    errors += user_errors_count
                    operations_completed += user_ops
                    
        finally:
            await gateway.stop_gateway()
        
        total_time = time.time() - start_time
        
        # Calculate metrics
        throughput_per_hour = (operations_completed / total_time) * 3600
        avg_response_time = statistics.mean(response_times) if response_times else 0
        p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else 0
        p99_response_time = statistics.quantiles(response_times, n=100)[98] if len(response_times) >= 100 else 0
        error_rate = errors / operations_completed if operations_completed > 0 else 1.0
        
        requirements_met = {
            'throughput': throughput_per_hour >= self.REQUIRED_THROUGHPUT_PER_HOUR,
            'avg_response_time': avg_response_time <= self.REQUIRED_MAX_RESPONSE_TIME,
            'p95_response_time': p95_response_time <= self.REQUIRED_P95_RESPONSE_TIME,
            'error_rate': error_rate <= self.REQUIRED_MAX_ERROR_RATE
        }
        
        result = PerformanceTestResult(
            test_name=f"Concurrent Users Simulation ({num_users} users)",
            total_operations=operations_completed,
            total_time_seconds=total_time,
            throughput_per_hour=throughput_per_hour,
            average_response_time=avg_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            error_count=errors,
            error_rate=error_rate,
            success=all(requirements_met.values()),
            requirements_met=requirements_met
        )
        
        self.results.append(result)
        return result
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        if not self.results:
            return {'error': 'No performance test results available'}
        
        # Overall summary
        total_operations = sum(r.total_operations for r in self.results)
        total_time = sum(r.total_time_seconds for r in self.results)
        total_errors = sum(r.error_count for r in self.results)
        
        all_response_times = []
        all_throughputs = []
        
        for result in self.results:
            all_throughputs.append(result.throughput_per_hour)
        
        # Requirements validation
        requirements_validation = {
            'throughput_requirement_met': all(
                r.throughput_per_hour >= self.REQUIRED_THROUGHPUT_PER_HOUR 
                for r in self.results if 'throughput' in r.requirements_met
            ),
            'response_time_requirement_met': all(
                r.average_response_time <= self.REQUIRED_MAX_RESPONSE_TIME
                for r in self.results
            ),
            'p95_requirement_met': all(
                r.p95_response_time <= self.REQUIRED_P95_RESPONSE_TIME
                for r in self.results
            ),
            'error_rate_requirement_met': all(
                r.error_rate <= self.REQUIRED_MAX_ERROR_RATE
                for r in self.results
            )
        }
        
        report = {
            'test_summary': {
                'total_tests_run': len(self.results),
                'total_operations_executed': total_operations,
                'total_test_time_seconds': total_time,
                'total_errors': total_errors,
                'overall_success': all(r.success for r in self.results)
            },
            'performance_metrics': {
                'max_throughput_per_hour': max(all_throughputs) if all_throughputs else 0,
                'min_throughput_per_hour': min(all_throughputs) if all_throughputs else 0,
                'avg_throughput_per_hour': statistics.mean(all_throughputs) if all_throughputs else 0,
                'fastest_avg_response_time': min(r.average_response_time for r in self.results),
                'slowest_avg_response_time': max(r.average_response_time for r in self.results)
            },
            'requirements_validation': requirements_validation,
            'requirements_status': {
                'throughput_target': f"{self.REQUIRED_THROUGHPUT_PER_HOUR} events/hour",
                'response_time_target': f"{self.REQUIRED_MAX_RESPONSE_TIME} seconds",
                'p95_response_time_target': f"{self.REQUIRED_P95_RESPONSE_TIME} seconds",
                'error_rate_target': f"{self.REQUIRED_MAX_ERROR_RATE * 100}%"
            },
            'individual_test_results': [
                {
                    'test_name': r.test_name,
                    'operations': r.total_operations,
                    'throughput_per_hour': round(r.throughput_per_hour, 2),
                    'avg_response_time': round(r.average_response_time, 3),
                    'p95_response_time': round(r.p95_response_time, 3),
                    'error_rate': round(r.error_rate * 100, 2),
                    'success': r.success,
                    'requirements_met': r.requirements_met
                }
                for r in self.results
            ],
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        if not self.results:
            return ["No test results available for analysis"]
        
        # Throughput recommendations
        throughput_failures = [r for r in self.results if not r.requirements_met.get('throughput', True)]
        if throughput_failures:
            recommendations.append(
                f"Throughput below target in {len(throughput_failures)} tests. "
                "Consider increasing worker pool size or optimizing event processing."
            )
        
        # Response time recommendations
        response_time_failures = [r for r in self.results if not r.requirements_met.get('avg_response_time', True)]
        if response_time_failures:
            recommendations.append(
                f"Response time above target in {len(response_time_failures)} tests. "
                "Consider optimizing workflow execution or adding caching."
            )
        
        # Error rate recommendations
        error_rate_failures = [r for r in self.results if not r.requirements_met.get('error_rate', True)]
        if error_rate_failures:
            recommendations.append(
                f"Error rate above target in {len(error_rate_failures)} tests. "
                "Investigate error patterns and improve error handling."
            )
        
        # P95 response time recommendations
        p95_failures = [r for r in self.results if not r.requirements_met.get('p95_response_time', True)]
        if p95_failures:
            recommendations.append(
                "P95 response times above target. Consider implementing request prioritization "
                "and optimizing slow operations."
            )
        
        if not any([throughput_failures, response_time_failures, error_rate_failures, p95_failures]):
            recommendations.append(
                "All performance requirements met! System is ready for production deployment."
            )
        
        return recommendations


# Test class for pytest integration
@pytest.mark.performance
class TestPerformanceValidation:
    """Performance validation test suite for MCP integration system."""
    
    @pytest.fixture
    def performance_suite(self):
        """Performance test suite fixture."""
        return PerformanceTestSuite()
    
    @pytest.mark.asyncio
    async def test_event_ingestion_throughput_requirement(self, performance_suite):
        """Test that event ingestion meets 1000+ events/hour requirement."""
        result = await performance_suite.measure_event_ingestion_performance(num_events=500)
        
        # Assert performance requirements
        assert result.success, f"Performance test failed: {result.requirements_met}"
        assert result.throughput_per_hour >= PerformanceTestSuite.REQUIRED_THROUGHPUT_PER_HOUR, \
            f"Throughput {result.throughput_per_hour} below requirement {PerformanceTestSuite.REQUIRED_THROUGHPUT_PER_HOUR}"
        assert result.average_response_time <= PerformanceTestSuite.REQUIRED_MAX_RESPONSE_TIME, \
            f"Response time {result.average_response_time} above requirement {PerformanceTestSuite.REQUIRED_MAX_RESPONSE_TIME}"
        assert result.error_rate <= PerformanceTestSuite.REQUIRED_MAX_ERROR_RATE, \
            f"Error rate {result.error_rate} above requirement {PerformanceTestSuite.REQUIRED_MAX_ERROR_RATE}"
    
    @pytest.mark.asyncio
    async def test_workflow_execution_performance_requirement(self, performance_suite):
        """Test that workflow execution meets response time requirements."""
        result = await performance_suite.measure_workflow_execution_performance(num_workflows=50)
        
        assert result.success, f"Workflow performance test failed: {result.requirements_met}"
        assert result.average_response_time <= PerformanceTestSuite.REQUIRED_MAX_RESPONSE_TIME, \
            f"Workflow response time {result.average_response_time} above requirement"
        assert result.p95_response_time <= PerformanceTestSuite.REQUIRED_P95_RESPONSE_TIME, \
            f"P95 response time {result.p95_response_time} above requirement"
    
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_sustained_load_performance(self, performance_suite):
        """Test sustained load performance over 5 minutes."""
        config = LoadTestConfiguration(
            duration_seconds=300,  # 5 minutes
            target_rps=5,  # 5 requests per second = 18,000 per hour
            ramp_up_seconds=60
        )
        
        result = await performance_suite.run_sustained_load_test(config)
        
        assert result.success, f"Sustained load test failed: {result.requirements_met}"
        assert result.throughput_per_hour >= PerformanceTestSuite.REQUIRED_THROUGHPUT_PER_HOUR, \
            f"Sustained throughput {result.throughput_per_hour} below requirement"
    
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_concurrent_users_performance(self, performance_suite):
        """Test performance under concurrent user load."""
        result = await performance_suite.run_concurrent_user_simulation(
            num_users=20, 
            duration_seconds=180
        )
        
        assert result.success, f"Concurrent users test failed: {result.requirements_met}"
        assert result.error_rate <= PerformanceTestSuite.REQUIRED_MAX_ERROR_RATE, \
            f"Error rate under concurrent load {result.error_rate} above requirement"
    
    @pytest.mark.asyncio
    async def test_generate_performance_report(self, performance_suite):
        """Test performance report generation."""
        # Run a quick performance test
        await performance_suite.measure_event_ingestion_performance(num_events=100)
        
        report = performance_suite.generate_performance_report()
        
        assert 'test_summary' in report
        assert 'performance_metrics' in report
        assert 'requirements_validation' in report
        assert 'individual_test_results' in report
        assert 'recommendations' in report
        
        # Verify report structure
        assert report['test_summary']['total_tests_run'] >= 1
        assert len(report['individual_test_results']) >= 1
        assert len(report['recommendations']) >= 1


# Standalone performance test runner
async def run_comprehensive_performance_tests():
    """Run comprehensive performance test suite and generate report."""
    print("🚀 Starting comprehensive performance test suite...")
    print(f"Requirements: {PerformanceTestSuite.REQUIRED_THROUGHPUT_PER_HOUR} events/hour, "
          f"{PerformanceTestSuite.REQUIRED_MAX_RESPONSE_TIME}s response time")
    print("=" * 80)
    
    suite = PerformanceTestSuite()
    
    # Test 1: Event ingestion performance
    print("\n📊 Test 1: Event Ingestion Performance (1000 events)")
    result1 = await suite.measure_event_ingestion_performance(num_events=1000)
    print(f"   Throughput: {result1.throughput_per_hour:.0f} events/hour")
    print(f"   Avg Response Time: {result1.average_response_time:.3f}s")
    print(f"   P95 Response Time: {result1.p95_response_time:.3f}s")
    print(f"   Error Rate: {result1.error_rate * 100:.2f}%")
    print(f"   Status: {'✅ PASS' if result1.success else '❌ FAIL'}")
    
    # Test 2: Workflow execution performance
    print("\n📊 Test 2: Workflow Execution Performance (100 workflows)")
    result2 = await suite.measure_workflow_execution_performance(num_workflows=100)
    print(f"   Throughput: {result2.throughput_per_hour:.0f} workflows/hour")
    print(f"   Avg Response Time: {result2.average_response_time:.3f}s")
    print(f"   P95 Response Time: {result2.p95_response_time:.3f}s")
    print(f"   Status: {'✅ PASS' if result2.success else '❌ FAIL'}")
    
    # Test 3: Sustained load test
    print("\n📊 Test 3: Sustained Load Test (5 minutes, 10 RPS)")
    config = LoadTestConfiguration(duration_seconds=300, target_rps=10)
    result3 = await suite.run_sustained_load_test(config)
    print(f"   Operations: {result3.total_operations}")
    print(f"   Throughput: {result3.throughput_per_hour:.0f} events/hour")
    print(f"   Avg Response Time: {result3.average_response_time:.3f}s")
    print(f"   Status: {'✅ PASS' if result3.success else '❌ FAIL'}")
    
    # Test 4: Concurrent users
    print("\n📊 Test 4: Concurrent Users Simulation (25 users, 3 minutes)")
    result4 = await suite.run_concurrent_user_simulation(num_users=25, duration_seconds=180)
    print(f"   Operations: {result4.total_operations}")
    print(f"   Throughput: {result4.throughput_per_hour:.0f} ops/hour")
    print(f"   Error Rate: {result4.error_rate * 100:.2f}%")
    print(f"   Status: {'✅ PASS' if result4.success else '❌ FAIL'}")
    
    # Generate final report
    print("\n" + "=" * 80)
    print("📋 PERFORMANCE TEST SUMMARY")
    print("=" * 80)
    
    report = suite.generate_performance_report()
    
    print(f"Total Tests: {report['test_summary']['total_tests_run']}")
    print(f"Total Operations: {report['test_summary']['total_operations_executed']:,}")
    print(f"Overall Success: {'✅ YES' if report['test_summary']['overall_success'] else '❌ NO'}")
    
    print(f"\nMax Throughput: {report['performance_metrics']['max_throughput_per_hour']:,.0f} events/hour")
    print(f"Fastest Response: {report['performance_metrics']['fastest_avg_response_time']:.3f}s")
    
    print("\n📋 Requirements Validation:")
    for req, met in report['requirements_validation'].items():
        status = '✅ MET' if met else '❌ NOT MET'
        print(f"   {req.replace('_', ' ').title()}: {status}")
    
    print(f"\n💡 Recommendations:")
    for i, rec in enumerate(report['recommendations'], 1):
        print(f"   {i}. {rec}")
    
    print("\n" + "=" * 80)
    overall_status = "✅ READY FOR PRODUCTION" if report['test_summary']['overall_success'] else "❌ REQUIRES OPTIMIZATION"
    print(f"FINAL STATUS: {overall_status}")
    print("=" * 80)


if __name__ == "__main__":
    # Run performance tests directly
    asyncio.run(run_comprehensive_performance_tests())