"""
Unit Tests for Enhanced Integration System
Testing the main framework components, target analysis, and scanning functionality
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from enhanced_integration import EnhancedBugBountyFramework, enhanced_target_analysis, enhanced_comprehensive_scan
from tests.conftest import TestUtilities

class TestEnhancedBugBountyFramework:
    """Test cases for the main Enhanced Bug Bounty Framework"""
    
    @pytest.mark.asyncio
    async def test_framework_initialization(self, mock_config):
        """Test framework initialization with configuration"""
        framework = EnhancedBugBountyFramework()
        
        assert framework is not None
        assert hasattr(framework, 'ml_enhancer')
        assert hasattr(framework, 'optimization_manager')
        assert framework.targets == []
        assert framework.findings == []
        assert framework.reports == []
    
    @pytest.mark.asyncio
    async def test_target_validation(self, mock_framework, sample_target_data):
        """Test target validation functionality"""
        target = sample_target_data['target']
        scope = sample_target_data['scope']
        
        validated_target = await mock_framework._validate_target(target, scope)
        
        assert validated_target['original_target'] == target
        assert validated_target['target_type'] == 'url'
        assert validated_target['is_valid'] is True
        assert 'parsed_url' in validated_target
    
    @pytest.mark.asyncio
    async def test_target_priority_calculation(self, mock_framework):
        """Test target priority scoring"""
        # High priority target (admin endpoint)
        high_priority_target = {
            'original_target': 'https://admin.example.com/login',
            'target_type': 'url',
            'is_valid': True,
            'parsed_url': {
                'scheme': 'https',
                'netloc': 'admin.example.com',
                'path': '/login',
                'query': ''
            }
        }
        
        priority_score = mock_framework._calculate_target_priority(high_priority_target)
        assert priority_score > 0.6  # Should be high priority
        
        # Low priority target
        low_priority_target = {
            'original_target': 'https://static.example.com',
            'target_type': 'url',
            'is_valid': True,
            'parsed_url': {
                'scheme': 'https',
                'netloc': 'static.example.com',
                'path': '/',
                'query': ''
            }
        }
        
        low_priority_score = mock_framework._calculate_target_priority(low_priority_target)
        assert low_priority_score < priority_score  # Should be lower priority
    
    @pytest.mark.asyncio
    async def test_optimal_tool_selection(self, mock_framework):
        """Test optimal tool selection based on target characteristics"""
        # High priority target
        tools = mock_framework._select_optimal_tools("https://admin.example.com", 0.8)
        assert 'subfinder' in tools
        assert 'nuclei' in tools
        assert len(tools) >= 3  # Should include multiple tools for high priority
        
        # Medium priority target
        tools = mock_framework._select_optimal_tools("https://example.com", 0.5)
        assert 'subfinder' in tools
        assert len(tools) >= 2  # Should include basic tools
    
    @pytest.mark.asyncio
    async def test_scan_duration_estimation(self, mock_framework):
        """Test scan duration estimation"""
        estimation = mock_framework._estimate_scan_duration("https://example.com", 0.7)
        
        assert 'estimated_seconds' in estimation
        assert 'estimated_minutes' in estimation
        assert 'confidence' in estimation
        assert estimation['estimated_seconds'] > 0
        assert estimation['confidence'] > 0
    
    @pytest.mark.asyncio
    async def test_optimization_recommendations(self, mock_framework):
        """Test optimization recommendations generation"""
        # High-value target
        recommendations = mock_framework._get_optimization_recommendations("https://admin.example.com")
        assert recommendations['optimization_level'] == 'maximum'
        assert recommendations['retry_attempts'] == 5
        
        # Regular target
        recommendations = mock_framework._get_optimization_recommendations("https://example.com")
        assert recommendations['optimization_level'] == 'balanced'
        assert recommendations['retry_attempts'] == 3

class TestTargetAnalysis:
    """Test cases for target analysis functionality"""
    
    @pytest.mark.asyncio
    async def test_analyze_target_success(self, mock_framework, sample_target_data):
        """Test successful target analysis"""
        target = sample_target_data['target']
        scope = sample_target_data['scope']
        
        # Mock ML enhancer response
        mock_framework.ml_enhancer.analyze_vulnerability.return_value = {
            'confidence': 0.85,
            'classification': 'high_risk'
        }
        
        analysis = await mock_framework.analyze_target(target, scope)
        
        TestUtilities.assert_valid_target_analysis(analysis)
        assert analysis['target'] == target
        assert analysis['priority_score'] > 0
        assert 'ml_analysis' in analysis
        assert 'recommended_tools' in analysis
    
    @pytest.mark.asyncio
    async def test_analyze_target_fallback(self, mock_framework):
        """Test target analysis fallback mechanism"""
        target = "invalid-target"
        
        # Mock ML enhancer to raise exception
        mock_framework.ml_enhancer.analyze_vulnerability.side_effect = Exception("ML service unavailable")
        
        analysis = await mock_framework.analyze_target(target)
        
        assert 'fallback_used' in analysis
        assert analysis['fallback_used'] is True
        assert analysis['priority_score'] == 0.5  # Default priority
    
    @pytest.mark.asyncio
    async def test_enhanced_target_analysis_function(self, sample_target_data):
        """Test the convenience function for target analysis"""
        target = sample_target_data['target']
        scope = sample_target_data['scope']
        
        with patch('enhanced_integration.enhanced_framework') as mock_framework:
            mock_framework.analyze_target = AsyncMock(return_value={
                'target': target,
                'priority_score': 0.8,
                'analysis_timestamp': '2025-06-26T10:00:00Z'
            })
            
            analysis = await enhanced_target_analysis(target, scope)
            
            assert analysis['target'] == target
            mock_framework.analyze_target.assert_called_once_with(target, scope)

class TestComprehensiveScan:
    """Test cases for comprehensive scanning functionality"""
    
    @pytest.mark.asyncio
    async def test_execute_comprehensive_scan_success(self, mock_framework, sample_scan_results):
        """Test successful comprehensive scan execution"""
        target_analysis = {
            'target': 'https://demo.testfire.net',
            'priority_score': 0.8,
            'recommended_tools': ['subfinder', 'nuclei', 'httpx']
        }
        
        # Mock the scan phases
        mock_framework._execute_optimized_reconnaissance = AsyncMock(return_value={
            'subdomains': ['www.testfire.net'],
            'live_hosts': ['https://demo.testfire.net']
        })
        
        mock_framework._execute_ml_enhanced_vulnerability_discovery = AsyncMock(return_value={
            'vulnerabilities': [
                {
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'confidence': 0.85
                }
            ]
        })
        
        mock_framework._execute_intelligent_exploitation = AsyncMock(return_value={
            'attempted_exploits': [],
            'successful_exploits': []
        })
        
        mock_framework._consolidate_and_score_findings = AsyncMock(return_value=[])
        mock_framework._generate_performance_report = AsyncMock(return_value={})
        
        scan_results = await mock_framework.execute_comprehensive_scan(target_analysis)
        
        TestUtilities.assert_valid_scan_results(scan_results)
        assert scan_results['status'] == 'completed'
        assert 'phases' in scan_results
        assert 'findings' in scan_results
    
    @pytest.mark.asyncio
    async def test_scan_recovery_mechanism(self, mock_framework):
        """Test scan failure recovery mechanism"""
        target_analysis = {
            'target': 'https://demo.testfire.net',
            'priority_score': 0.8,
            'recommended_tools': ['subfinder']
        }
        
        # Mock reconnaissance to fail
        mock_framework._execute_optimized_reconnaissance = AsyncMock(
            side_effect=Exception("Network error")
        )
        
        # Mock recovery mechanism
        mock_framework._recover_from_scan_failure = AsyncMock(return_value={
            'target': 'https://demo.testfire.net',
            'status': 'failed',
            'recovery_attempted': True,
            'recovery_successful': True
        })
        
        scan_results = await mock_framework.execute_comprehensive_scan(target_analysis)
        
        assert scan_results['status'] == 'failed'
        assert scan_results['recovery_attempted'] is True

class TestReconnaissancePhase:
    """Test cases for reconnaissance phase"""
    
    @pytest.mark.asyncio
    async def test_optimized_reconnaissance_execution(self, mock_framework, mock_security_tools):
        """Test optimized reconnaissance with multiple tools"""
        target = "demo.testfire.net"
        analysis = {'recommended_tools': ['subfinder', 'httpx']}
        
        # Mock individual tool executions
        mock_framework._run_subfinder_optimized = mock_security_tools['subfinder']
        mock_framework._run_httpx_optimized = mock_security_tools['httpx']
        
        recon_results = await mock_framework._execute_optimized_reconnaissance(target, analysis)
        
        assert 'subdomains' in recon_results
        assert 'live_hosts' in recon_results
        assert isinstance(recon_results['subdomains'], list)
        assert isinstance(recon_results['live_hosts'], list)
    
    @pytest.mark.asyncio
    async def test_subfinder_optimized_execution(self, mock_framework):
        """Test optimized subfinder execution"""
        target = "demo.testfire.net"
        
        result = await mock_framework._run_subfinder_optimized(target)
        
        assert result['tool'] == 'subfinder'
        assert 'subdomains' in result
        assert 'execution_time' in result
        assert isinstance(result['subdomains'], list)
    
    @pytest.mark.asyncio
    async def test_httpx_optimized_execution(self, mock_framework):
        """Test optimized httpx execution"""
        target = "demo.testfire.net"
        
        result = await mock_framework._run_httpx_optimized(target)
        
        assert result['tool'] == 'httpx'
        assert 'live_hosts' in result
        assert 'execution_time' in result
        assert isinstance(result['live_hosts'], list)

class TestVulnerabilityDiscovery:
    """Test cases for vulnerability discovery phase"""
    
    @pytest.mark.asyncio
    async def test_ml_enhanced_vulnerability_discovery(self, mock_framework, sample_vulnerability_data):
        """Test ML-enhanced vulnerability discovery"""
        target = "demo.testfire.net"
        recon_results = {
            'subdomains': ['www.demo.testfire.net'],
            'live_hosts': ['https://demo.testfire.net']
        }
        
        # Mock ML enhancement
        mock_framework.ml_enhancer.analyze_vulnerability.return_value = {
            'confidence': 0.85,
            'false_positive_probability': 0.15
        }
        
        vuln_results = await mock_framework._execute_ml_enhanced_vulnerability_discovery(target, recon_results)
        
        assert 'vulnerabilities' in vuln_results
        assert 'ml_analysis' in vuln_results
        assert isinstance(vuln_results['vulnerabilities'], list)
        
        if vuln_results['vulnerabilities']:
            vuln = vuln_results['vulnerabilities'][0]
            TestUtilities.assert_valid_vulnerability(vuln)
            assert 'ml_enhancement' in vuln
            assert 'final_confidence' in vuln

class TestReporting:
    """Test cases for enhanced reporting"""
    
    @pytest.mark.asyncio
    async def test_enhanced_report_generation(self, mock_framework, sample_scan_results):
        """Test enhanced report generation"""
        # Mock ML and optimization stats
        mock_framework.ml_enhancer.get_system_stats.return_value = {
            'performance_metrics': {
                'accuracy': 0.85,
                'false_positive_rate': 0.15
            }
        }
        
        mock_framework.optimization_manager.get_comprehensive_stats.return_value = {
            'cache_stats': {'hit_ratio': 0.85},
            'optimization_level': 'balanced'
        }
        
        report = await mock_framework.generate_enhanced_report(sample_scan_results)
        
        assert 'executive_summary' in report
        assert 'technical_findings' in report
        assert 'risk_assessment' in report
        assert 'ml_insights' in report
        assert 'optimization_report' in report
        assert 'recommendations' in report
        assert 'report_metadata' in report
    
    @pytest.mark.asyncio
    async def test_executive_summary_generation(self, mock_framework, sample_scan_results):
        """Test executive summary generation"""
        summary = mock_framework._generate_executive_summary(sample_scan_results)
        
        assert 'target_assessed' in summary
        assert 'overall_risk_level' in summary
        assert 'critical_findings_count' in summary
        assert 'key_recommendations' in summary
        assert isinstance(summary['key_recommendations'], list)
    
    @pytest.mark.asyncio
    async def test_risk_assessment_generation(self, mock_framework, sample_scan_results):
        """Test risk assessment generation"""
        risk_assessment = mock_framework._generate_risk_assessment(sample_scan_results)
        
        assert 'overall_risk_score' in risk_assessment
        assert 'risk_distribution' in risk_assessment
        assert 'risk_level' in risk_assessment
        assert 'priority_actions' in risk_assessment
        assert isinstance(risk_assessment['priority_actions'], list)

class TestPerformanceAndOptimization:
    """Test cases for performance monitoring and optimization"""
    
    @pytest.mark.asyncio
    async def test_performance_report_generation(self, mock_framework):
        """Test performance report generation"""
        target = "demo.testfire.net"
        
        # Mock optimization manager stats
        mock_framework.optimization_manager.get_comprehensive_stats.return_value = {
            'cache_stats': {'hit_ratio': 0.85},
            'retry_stats': {'success_rate': 0.90},
            'resource_usage': {'cpu_percent': 25.0}
        }
        
        performance_report = await mock_framework._generate_performance_report(target)
        
        assert 'target' in performance_report
        assert 'optimization_stats' in performance_report
        assert 'framework_metrics' in performance_report
        assert 'recommendations' in performance_report
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_scan_performance_benchmarks(self, mock_framework, performance_timer):
        """Test scan performance benchmarks"""
        target_analysis = {
            'target': 'https://demo.testfire.net',
            'priority_score': 0.5,
            'recommended_tools': ['subfinder']
        }
        
        # Mock quick execution
        mock_framework._execute_optimized_reconnaissance = AsyncMock(return_value={})
        mock_framework._execute_ml_enhanced_vulnerability_discovery = AsyncMock(return_value={'vulnerabilities': []})
        mock_framework._execute_intelligent_exploitation = AsyncMock(return_value={})
        mock_framework._consolidate_and_score_findings = AsyncMock(return_value=[])
        mock_framework._generate_performance_report = AsyncMock(return_value={})
        
        performance_timer.start()
        await mock_framework.execute_comprehensive_scan(target_analysis)
        performance_timer.stop()
        
        # Basic performance assertion - scan should complete quickly in mock mode
        assert performance_timer.elapsed < 5.0  # Should complete within 5 seconds

if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v"])
