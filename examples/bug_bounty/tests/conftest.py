"""
Enhanced Bug Bounty Framework - Comprehensive Test Suite
Test configuration and fixtures for the testing framework
"""

import asyncio
import pytest
import tempfile
import shutil
import os
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any

# Import framework components
from enhanced_integration import EnhancedBugBountyFramework, enhanced_framework
from ml_enhancements import OptimizedMLEnhancer, ml_enhancer
from optimization_manager import EnhancedOptimizationManager, optimization_manager

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def temp_directory():
    """Create temporary directory for test files"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.fixture
def mock_config():
    """Mock configuration for testing"""
    return {
        "database": {
            "url": "sqlite:///:memory:",
            "echo": False
        },
        "cache": {
            "max_size": 100,
            "default_ttl": 300
        },
        "optimization": {
            "auto_adjust": True,
            "aggressive_mode": False,
            "resource_monitoring": True
        },
        "ml": {
            "enable_advanced_models": True,
            "confidence_threshold": 0.7,
            "false_positive_reduction": True
        },
        "security_tools": {
            "subfinder": {
                "threads": 10,
                "timeout": 30
            },
            "nuclei": {
                "rate_limit": 50,
                "timeout": 10
            }
        }
    }

@pytest.fixture
def mock_framework(mock_config):
    """Create mock enhanced framework for testing"""
    framework = EnhancedBugBountyFramework()
    
    # Mock external dependencies
    framework.ml_enhancer = Mock(spec=OptimizedMLEnhancer)
    framework.optimization_manager = Mock(spec=EnhancedOptimizationManager)
    
    # Setup mock methods
    framework.ml_enhancer.analyze_vulnerability = AsyncMock(return_value={
        'confidence': 0.85,
        'classification': 'high_risk',
        'false_positive_probability': 0.15
    })
    
    framework.optimization_manager.get_comprehensive_stats = Mock(return_value={
        'cache_stats': {'hit_ratio': 0.85},
        'retry_stats': {'success_rate': 0.90},
        'resource_usage': {'cpu_percent': 25.0, 'memory_percent': 45.0}
    })
    
    return framework

@pytest.fixture
def sample_target_data():
    """Sample target data for testing"""
    return {
        'target': 'https://demo.testfire.net',
        'scope': {
            'in_scope': ['*.testfire.net'],
            'out_of_scope': ['admin.testfire.net'],
            'methods': ['GET', 'POST'],
            'allow_subdomains': True
        }
    }

@pytest.fixture
def sample_vulnerability_data():
    """Sample vulnerability data for testing"""
    return {
        'type': 'SQL Injection',
        'severity': 'High',
        'endpoint': 'https://demo.testfire.net/login.php',
        'description': 'SQL injection vulnerability in login form',
        'confidence': 0.85,
        'method': 'POST',
        'parameter': 'username'
    }

@pytest.fixture
def sample_scan_results():
    """Sample scan results for testing"""
    return {
        'target': 'https://demo.testfire.net',
        'start_time': '2025-06-26T10:00:00Z',
        'end_time': '2025-06-26T10:30:00Z',
        'status': 'completed',
        'phases': {
            'reconnaissance': {
                'subdomains': ['www.testfire.net', 'api.testfire.net'],
                'live_hosts': ['https://demo.testfire.net'],
                'technologies': ['Apache', 'MySQL']
            },
            'vulnerability_discovery': {
                'vulnerabilities': [
                    {
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'endpoint': 'https://demo.testfire.net/login.php',
                        'confidence': 0.85
                    }
                ]
            }
        },
        'findings': [
            {
                'id': 'finding_1',
                'vulnerability': {
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'endpoint': 'https://demo.testfire.net/login.php',
                    'confidence': 0.85
                },
                'consolidated_score': 0.90
            }
        ]
    }

@pytest.fixture
def mock_security_tools():
    """Mock security tools for testing"""
    tools = {
        'subfinder': AsyncMock(return_value={
            'tool': 'subfinder',
            'subdomains': ['www.testfire.net', 'api.testfire.net'],
            'execution_time': 5.2
        }),
        'httpx': AsyncMock(return_value={
            'tool': 'httpx',
            'live_hosts': ['https://demo.testfire.net'],
            'execution_time': 2.1
        }),
        'nuclei': AsyncMock(return_value={
            'tool': 'nuclei',
            'vulnerabilities': [
                {
                    'template_id': 'sql-injection',
                    'severity': 'high',
                    'url': 'https://demo.testfire.net/login.php'
                }
            ],
            'execution_time': 15.3
        })
    }
    return tools

@pytest.fixture
def mock_database_connection():
    """Mock database connection for testing"""
    connection = Mock()
    connection.execute = AsyncMock()
    connection.fetch = AsyncMock()
    connection.fetchrow = AsyncMock()
    connection.fetchval = AsyncMock()
    return connection

class MockProcess:
    """Mock subprocess for testing tool execution"""
    
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout.encode() if isinstance(stdout, str) else stdout
        self.stderr = stderr.encode() if isinstance(stderr, str) else stderr
    
    async def wait(self):
        return self.returncode
    
    async def communicate(self):
        return self.stdout, self.stderr

@pytest.fixture
def mock_subprocess():
    """Mock subprocess for testing external tool execution"""
    return MockProcess

# Test data generators
def generate_test_targets(count: int = 10):
    """Generate test target data"""
    targets = []
    for i in range(count):
        targets.append({
            'url': f'https://test{i}.example.com',
            'priority': 0.5 + (i * 0.05),
            'type': 'web_application'
        })
    return targets

def generate_test_vulnerabilities(count: int = 5):
    """Generate test vulnerability data"""
    vuln_types = ['SQL Injection', 'XSS', 'CSRF', 'LFI', 'RCE']
    severities = ['Critical', 'High', 'Medium', 'Low']
    
    vulnerabilities = []
    for i in range(count):
        vulnerabilities.append({
            'type': vuln_types[i % len(vuln_types)],
            'severity': severities[i % len(severities)],
            'endpoint': f'https://test.example.com/vuln{i}.php',
            'confidence': 0.6 + (i * 0.08),
            'description': f'Test vulnerability {i + 1}'
        })
    return vulnerabilities

# Test utilities
class TestUtilities:
    """Utility functions for testing"""
    
    @staticmethod
    def assert_valid_target_analysis(analysis: Dict[str, Any]):
        """Assert that target analysis has required fields"""
        required_fields = [
            'target', 'validated_data', 'priority_score', 
            'ml_analysis', 'recommended_tools', 'estimated_scan_time'
        ]
        for field in required_fields:
            assert field in analysis, f"Missing required field: {field}"
    
    @staticmethod
    def assert_valid_scan_results(results: Dict[str, Any]):
        """Assert that scan results have required structure"""
        required_fields = ['target', 'start_time', 'phases', 'findings', 'status']
        for field in required_fields:
            assert field in results, f"Missing required field: {field}"
    
    @staticmethod
    def assert_valid_vulnerability(vulnerability: Dict[str, Any]):
        """Assert that vulnerability has required fields"""
        required_fields = ['type', 'severity', 'endpoint', 'confidence']
        for field in required_fields:
            assert field in vulnerability, f"Missing required field: {field}"

# Performance test helpers
@pytest.fixture
def performance_timer():
    """Timer for performance testing"""
    import time
    
    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
        
        def start(self):
            self.start_time = time.time()
        
        def stop(self):
            self.end_time = time.time()
        
        @property
        def elapsed(self):
            if self.start_time is None or self.end_time is None:
                return None
            return self.end_time - self.start_time
    
    return Timer()

# Environment setup for tests
def setup_test_environment():
    """Setup test environment variables"""
    os.environ.update({
        'ENVIRONMENT': 'test',
        'LOG_LEVEL': 'DEBUG',
        'DATABASE_URL': 'sqlite:///:memory:',
        'CACHE_TTL_SECONDS': '300',
        'MAX_CONCURRENT_SCANS': '2'
    })

def teardown_test_environment():
    """Clean up test environment"""
    test_vars = [
        'ENVIRONMENT', 'LOG_LEVEL', 'DATABASE_URL', 
        'CACHE_TTL_SECONDS', 'MAX_CONCURRENT_SCANS'
    ]
    for var in test_vars:
        os.environ.pop(var, None)

# Test markers for categorizing tests
pytest_markers = {
    'unit': 'Unit tests for individual components',
    'integration': 'Integration tests for component interaction',
    'performance': 'Performance and load tests',
    'security': 'Security-related tests',
    'ml': 'Machine learning component tests',
    'slow': 'Tests that take longer to execute'
}
