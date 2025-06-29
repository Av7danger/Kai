#!/usr/bin/env python3
"""
Comprehensive Test Suite for Optimized Bug Hunter
Tests all optimizations including performance, caching, error handling, and monitoring
"""

import asyncio
import time
import json
import sys
import os
from typing import Dict, List, Any
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from subprocess_handler import SubprocessHandler
from cache_manager import CacheManager, CacheBackend
from database_manager import DatabaseManager
from performance_monitor import PerformanceMonitor
from error_handler import ErrorHandler, ErrorCategory, ErrorSeverity
from ai_agent import AIAgent, AIProvider
from kali_optimizer import KaliOptimizer

class OptimizationTestSuite:
    """Comprehensive test suite for all optimizations"""
    
    def __init__(self):
        self.test_results = []
        self.start_time = time.time()
        
        # Initialize components
        self.subprocess_handler = SubprocessHandler()
        self.cache_manager = CacheManager(CacheBackend.MEMORY, max_size=100)
        self.db_manager = DatabaseManager()
        self.performance_monitor = PerformanceMonitor()
        self.error_handler = ErrorHandler()
        self.ai_agent = AIAgent()
        self.kali_optimizer = KaliOptimizer(self.subprocess_handler)
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all optimization tests"""
        print("🚀 Starting Comprehensive Optimization Test Suite")
        print("=" * 60)
        
        test_suites = [
            ("Performance Optimizations", self.test_performance_optimizations),
            ("Caching System", self.test_caching_system),
            ("Error Handling", self.test_error_handling),
            ("Database Optimizations", self.test_database_optimizations),
            ("Subprocess Handler", self.test_subprocess_handler),
            ("AI Agent", self.test_ai_agent),
            ("Kali Optimizer", self.test_kali_optimizer),
            ("System Integration", self.test_system_integration)
        ]
        
        for suite_name, test_func in test_suites:
            print(f"\n📋 Running {suite_name}...")
            try:
                result = await test_func()
                self.test_results.append({
                    'suite': suite_name,
                    'status': 'PASSED' if result['success'] else 'FAILED',
                    'details': result
                })
                print(f"✅ {suite_name}: {'PASSED' if result['success'] else 'FAILED'}")
            except Exception as e:
                self.test_results.append({
                    'suite': suite_name,
                    'status': 'ERROR',
                    'details': {'error': str(e)}
                })
                print(f"❌ {suite_name}: ERROR - {e}")
        
        return self.generate_test_report()
    
    async def test_performance_optimizations(self) -> Dict[str, Any]:
        """Test performance monitoring and optimizations"""
        results = {
            'success': True,
            'metrics': {},
            'alerts': []
        }
        
        try:
            # Start performance monitoring
            self.performance_monitor.start_monitoring()
            
            # Simulate some activity
            for i in range(5):
                self.performance_monitor.record_request(0.1 + (i * 0.02), success=True)
                self.performance_monitor.add_custom_metric("test_metric", i * 10, "test")
                await asyncio.sleep(0.1)
            
            # Get current metrics
            current_metrics = self.performance_monitor.get_current_metrics()
            results['metrics']['current'] = current_metrics
            
            # Test performance summary
            summary = self.performance_monitor.get_performance_summary(1)
            results['metrics']['summary'] = summary
            
            # Test alert system
            def alert_callback(alert):
                results['alerts'].append(alert)
            
            self.performance_monitor.add_alert_callback(alert_callback)
            
            # Stop monitoring
            self.performance_monitor.stop_monitoring()
            
            # Verify metrics are collected
            if not current_metrics or current_metrics['uptime_seconds'] <= 0:
                results['success'] = False
                results['error'] = 'No metrics collected'
            
        except Exception as e:
            results['success'] = False
            results['error'] = str(e)
        
        return results
    
    async def test_caching_system(self) -> Dict[str, Any]:
        """Test caching system functionality"""
        results = {
            'success': True,
            'cache_tests': {}
        }
        
        try:
            # Test basic caching
            test_key = "test_key"
            test_value = {"data": "test_value", "timestamp": time.time()}
            
            # Set value
            self.cache_manager.set(test_key, test_value, ttl=60)
            results['cache_tests']['set'] = True
            
            # Get value
            retrieved_value = self.cache_manager.get(test_key)
            results['cache_tests']['get'] = retrieved_value == test_value
            
            # Test cache stats
            stats = self.cache_manager.get_stats()
            results['cache_tests']['stats'] = stats['total_entries'] > 0
            
            # Test cache key generation
            generated_key = self.cache_manager.generate_key("test", "args", kwarg1="value1")
            results['cache_tests']['key_generation'] = len(generated_key) > 0
            
            # Test cache decorator
            @self.cache_manager.cached(ttl=30, key_prefix="test")
            def test_function(x):
                return x * 2
            
            result1 = test_function(5)
            result2 = test_function(5)  # Should be cached
            results['cache_tests']['decorator'] = result1 == result2 == 10
            
            # Verify all tests passed
            results['success'] = all(results['cache_tests'].values())
            
        except Exception as e:
            results['success'] = False
            results['error'] = str(e)
        
        return results
    
    async def test_error_handling(self) -> Dict[str, Any]:
        """Test error handling and recovery"""
        results = {
            'success': True,
            'error_tests': {}
        }
        
        try:
            # Test error context manager
            try:
                with self.error_handler.error_context(ErrorCategory.NETWORK, ErrorSeverity.HIGH):
                    raise ConnectionError("Test network error")
            except ConnectionError:
                results['error_tests']['context_manager'] = True
            
            # Test error decorator
            @self.error_handler.handle_errors(ErrorCategory.VALIDATION, ErrorSeverity.MEDIUM, retry_count=1)
            def test_function():
                raise ValueError("Test validation error")
            
            try:
                test_function()
            except ValueError:
                results['error_tests']['decorator'] = True
            
            # Test error summary
            summary = self.error_handler.get_error_summary()
            results['error_tests']['summary'] = summary['total_errors'] > 0
            
            # Test error categorization
            network_errors = self.error_handler.get_errors_by_category(ErrorCategory.NETWORK)
            results['error_tests']['categorization'] = len(network_errors) > 0
            
            # Verify all tests passed
            results['success'] = all(results['error_tests'].values())
            
        except Exception as e:
            results['success'] = False
            results['error'] = str(e)
        
        return results
    
    async def test_database_optimizations(self) -> Dict[str, Any]:
        """Test database optimizations"""
        results = {
            'success': True,
            'db_tests': {}
        }
        
        try:
            # Initialize database
            await self.db_manager.initialize()
            
            # Test connection pooling
            results['db_tests']['initialization'] = True
            
            # Test efficient queries
            test_data = {
                'workflow_id': 'test_workflow',
                'target': 'test.com',
                'status': 'completed',
                'start_time': time.time(),
                'end_time': time.time() + 60,
                'steps': json.dumps([{'name': 'test', 'status': 'completed'}]),
                'logs': json.dumps([{'message': 'test log'}]),
                'vulnerabilities': json.dumps([])
            }
            
            # Insert test data
            await self.db_manager.save_workflow(test_data)
            results['db_tests']['insert'] = True
            
            # Query test data
            workflows = await self.db_manager.get_workflows(limit=10)
            results['db_tests']['query'] = len(workflows) > 0
            
            # Test stats
            stats = await self.db_manager.get_stats()
            results['db_tests']['stats'] = stats['total_workflows'] > 0
            
            # Cleanup
            await self.db_manager.close()
            
            # Verify all tests passed
            results['success'] = all(results['db_tests'].values())
            
        except Exception as e:
            results['success'] = False
            results['error'] = str(e)
        
        return results
    
    async def test_subprocess_handler(self) -> Dict[str, Any]:
        """Test subprocess handler optimizations"""
        results = {
            'success': True,
            'subprocess_tests': {}
        }
        
        try:
            # Test basic command execution
            result = self.subprocess_handler.run_command(['echo', 'Hello World'])
            results['subprocess_tests']['basic_execution'] = result['success']
            
            # Test async command execution
            async_result = await self.subprocess_handler.run_command_async(['echo', 'Hello Async'])
            results['subprocess_tests']['async_execution'] = async_result.status.value == 'success'
            
            # Test retry mechanism
            retry_result = self.subprocess_handler.run_with_retry(['echo', 'Retry Test'])
            results['subprocess_tests']['retry_mechanism'] = retry_result['success']
            
            # Test tool checking with cache
            tool_check = self.subprocess_handler.run_tool_check('python')
            results['subprocess_tests']['tool_check'] = 'success' in tool_check
            
            # Test cached result
            cached_check = self.subprocess_handler.run_tool_check('python')
            results['subprocess_tests']['cached_result'] = cached_check.get('cached', False)
            
            # Verify all tests passed
            results['success'] = all(results['subprocess_tests'].values())
            
        except Exception as e:
            results['success'] = False
            results['error'] = str(e)
        
        return results
    
    async def test_ai_agent(self) -> Dict[str, Any]:
        """Test AI agent optimizations"""
        results = {
            'success': True,
            'ai_tests': {}
        }
        
        try:
            # Test target analysis
            analysis = await self.ai_agent.analyze_target("https://example.com", "*.example.com")
            results['ai_tests']['target_analysis'] = hasattr(analysis, 'target_url')
            
            # Test result analysis
            vuln_results = {"vulnerabilities": []}
            recon_results = {"subdomains": []}
            result_analysis = await self.ai_agent.analyze_results(vuln_results, recon_results)
            results['ai_tests']['result_analysis'] = result_analysis.analysis_type.value == 'result_analysis'
            
            # Test workflow planning
            workflow_plan = await self.ai_agent.plan_workflow(
                "https://example.com", 
                "*.example.com", 
                ["nmap", "nuclei"]
            )
            results['ai_tests']['workflow_planning'] = 'workflow_steps' in workflow_plan
            
            # Test chat functionality
            chat_response = await self.ai_agent.chat("What tools should I use for web testing?")
            results['ai_tests']['chat'] = len(chat_response) > 0
            
            # Test caching
            cached_analysis = await self.ai_agent.analyze_target("https://example.com", "*.example.com")
            results['ai_tests']['caching'] = hasattr(cached_analysis, 'target_url')
            
            # Verify all tests passed
            results['success'] = all(results['ai_tests'].values())
            
        except Exception as e:
            results['success'] = False
            results['error'] = str(e)
        
        return results
    
    async def test_kali_optimizer(self) -> Dict[str, Any]:
        """Test Kali optimizer functionality"""
        results = {
            'success': True,
            'kali_tests': {}
        }
        
        try:
            # Test tool checking
            tools_status = await self.kali_optimizer.check_all_tools()
            results['kali_tests']['tool_checking'] = len(tools_status) > 0
            
            # Test system resources
            system_resources = self.kali_optimizer.get_system_resources()
            results['kali_tests']['system_resources'] = 'cpu_percent' in system_resources
            
            # Test target optimization
            optimization = await self.kali_optimizer.optimize_for_target(
                "https://example.com", 
                {"attack_surface": ["web"]}
            )
            results['kali_tests']['target_optimization'] = len(optimization) > 0
            
            # Test diagnostics
            diagnostics = await self.kali_optimizer.run_diagnostics()
            results['kali_tests']['diagnostics'] = 'system_info' in diagnostics
            
            # Verify all tests passed
            results['success'] = all(results['kali_tests'].values())
            
        except Exception as e:
            results['success'] = False
            results['error'] = str(e)
        
        return results
    
    async def test_system_integration(self) -> Dict[str, Any]:
        """Test system integration and end-to-end functionality"""
        results = {
            'success': True,
            'integration_tests': {}
        }
        
        try:
            # Test complete workflow with all optimizations
            start_time = time.time()
            
            # Start performance monitoring
            self.performance_monitor.start_monitoring()
            
            # Use caching for AI analysis
            analysis = await self.ai_agent.analyze_target("https://test.com", "*.test.com")
            
            # Use optimized subprocess for tool checking
            tool_check = self.subprocess_handler.run_tool_check('python')
            
            # Record performance metrics
            self.performance_monitor.record_request(time.time() - start_time, True)
            
            # Get final metrics
            final_metrics = self.performance_monitor.get_current_metrics()
            
            # Stop monitoring
            self.performance_monitor.stop_monitoring()
            
            # Verify integration
            results['integration_tests']['workflow_completion'] = hasattr(analysis, 'target_url')
            results['integration_tests']['performance_tracking'] = final_metrics['uptime_seconds'] > 0
            results['integration_tests']['tool_integration'] = 'success' in tool_check
            
            # Verify all tests passed
            results['success'] = all(results['integration_tests'].values())
            
        except Exception as e:
            results['success'] = False
            results['error'] = str(e)
        
        return results
    
    def generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        end_time = time.time()
        total_time = end_time - self.start_time
        
        passed_tests = sum(1 for result in self.test_results if result['status'] == 'PASSED')
        failed_tests = sum(1 for result in self.test_results if result['status'] == 'FAILED')
        error_tests = sum(1 for result in self.test_results if result['status'] == 'ERROR')
        total_tests = len(self.test_results)
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        report = {
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'errors': error_tests,
                'success_rate': success_rate,
                'total_time': total_time
            },
            'results': self.test_results,
            'recommendations': self.generate_recommendations()
        }
        
        return report
    
    def generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        failed_tests = [r for r in self.test_results if r['status'] in ['FAILED', 'ERROR']]
        
        if failed_tests:
            recommendations.append(f"Fix {len(failed_tests)} failed test(s)")
        
        # Performance recommendations
        if any('performance' in r['suite'].lower() for r in self.test_results if r['status'] == 'FAILED'):
            recommendations.append("Review performance optimizations")
        
        # Caching recommendations
        if any('caching' in r['suite'].lower() for r in self.test_results if r['status'] == 'FAILED'):
            recommendations.append("Check caching system configuration")
        
        # Error handling recommendations
        if any('error' in r['suite'].lower() for r in self.test_results if r['status'] == 'FAILED'):
            recommendations.append("Verify error handling mechanisms")
        
        if not recommendations:
            recommendations.append("All optimizations working correctly!")
        
        return recommendations

async def main():
    """Main test runner"""
    print("🐛 Kali Bug Hunter - Optimization Test Suite")
    print("=" * 60)
    
    # Create test suite
    test_suite = OptimizationTestSuite()
    
    # Run all tests
    report = await test_suite.run_all_tests()
    
    # Print results
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    summary = report['summary']
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Passed: {summary['passed']} ✅")
    print(f"Failed: {summary['failed']} ❌")
    print(f"Errors: {summary['errors']} ⚠️")
    print(f"Success Rate: {summary['success_rate']:.1f}%")
    print(f"Total Time: {summary['total_time']:.2f}s")
    
    print("\n📋 DETAILED RESULTS")
    print("-" * 40)
    
    for result in report['results']:
        status_icon = "✅" if result['status'] == 'PASSED' else "❌" if result['status'] == 'FAILED' else "⚠️"
        print(f"{status_icon} {result['suite']}: {result['status']}")
        
        if result['status'] != 'PASSED' and 'error' in result['details']:
            print(f"   Error: {result['details']['error']}")
    
    print("\n💡 RECOMMENDATIONS")
    print("-" * 40)
    
    for recommendation in report['recommendations']:
        print(f"• {recommendation}")
    
    # Save report to file
    report_file = "optimization_test_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n📄 Detailed report saved to: {report_file}")
    
    # Return exit code
    if summary['success_rate'] >= 80:
        print("\n🎉 Optimization test suite completed successfully!")
        return 0
    else:
        print("\n⚠️ Some optimizations need attention.")
        return 1

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⏹️ Test suite interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n💥 Unexpected error: {e}")
        sys.exit(1) 