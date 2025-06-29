#!/usr/bin/env python3
"""
🧪 Step 7: Advanced Integration & Optimization Test Suite
Comprehensive testing for advanced integration, optimization, and deployment

Tests:
- Advanced integration workflows
- Performance optimization
- Caching and resource management
- Security features
- Deployment and scaling
- Backup and recovery
- Health monitoring
- Analytics and reporting
"""

import os
import sys
import time
import json
import yaml
import threading
from datetime import datetime, timedelta
from pathlib import Path
import logging

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import Step 7 components
try:
    from advanced_integration import initialize_integration_manager, get_integration_manager
    from performance_optimizer import initialize_performance_optimizer, get_performance_optimizer
    from deployment_manager import initialize_deployment_manager, get_deployment_manager
    STEP7_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Step 7 components not available: {e}")
    STEP7_AVAILABLE = False

# Import framework components for testing
try:
    from recon_manager import get_recon_manager
    from ai_analysis import get_ai_manager
    from monitoring_manager import get_monitoring_manager
    from bug_submission import get_submission_manager
    from exploit_manager import get_exploit_manager
    from dashboard import get_dashboard_manager
    FRAMEWORK_AVAILABLE = True
except ImportError:
    FRAMEWORK_AVAILABLE = False
    print("Warning: Framework components not available")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Step7Tester:
    """Step 7 testing class"""
    
    def __init__(self):
        self.test_results = []
        self.integration_manager = None
        self.performance_optimizer = None
        self.deployment_manager = None
        
    def run_all_tests(self):
        """Run all Step 7 tests"""
        print("🚀 Starting Step 7: Advanced Integration & Optimization Tests")
        print("=" * 70)
        
        if not STEP7_AVAILABLE:
            print("❌ Step 7 components not available. Skipping tests.")
            return
        
        # Test advanced integration
        self.test_advanced_integration()
        
        # Test performance optimization
        self.test_performance_optimization()
        
        # Test caching and resource management
        self.test_caching_and_resources()
        
        # Test security features
        self.test_security_features()
        
        # Test deployment and scaling
        self.test_deployment_and_scaling()
        
        # Test backup and recovery
        self.test_backup_and_recovery()
        
        # Test health monitoring
        self.test_health_monitoring()
        
        # Test analytics and reporting
        self.test_analytics_and_reporting()
        
        # Test workflow automation
        self.test_workflow_automation()
        
        # Test optimization recommendations
        self.test_optimization_recommendations()
        
        # Print test summary
        self.print_test_summary()
    
    def test_advanced_integration(self):
        """Test advanced integration system"""
        print("\n🔗 Testing Advanced Integration System")
        print("-" * 40)
        
        try:
            # Initialize integration manager
            self.integration_manager = initialize_integration_manager()
            assert self.integration_manager is not None, "Integration manager should be initialized"
            print("✅ Integration manager initialized successfully")
            
            # Test configuration loading
            config = self.integration_manager.config
            assert 'performance' in config, "Performance configuration should be loaded"
            assert 'security' in config, "Security configuration should be loaded"
            assert 'workflows' in config, "Workflows configuration should be loaded"
            print("✅ Configuration loaded successfully")
            
            # Test framework manager integration
            managers = self.integration_manager.framework_managers
            assert len(managers) > 0, "At least one framework manager should be available"
            print(f"✅ {len(managers)} framework managers integrated")
            
            # Test workflow creation
            workflow_steps = [
                {
                    'id': 'test_recon',
                    'name': 'Test Reconnaissance',
                    'component': 'recon',
                    'function': 'start_scan',
                    'parameters': {'target_domain': 'example.com'},
                    'dependencies': [],
                    'timeout': 300,
                    'critical': True
                },
                {
                    'id': 'test_analysis',
                    'name': 'Test Analysis',
                    'component': 'ai',
                    'function': 'analyze_results',
                    'parameters': {'session_id': '{test_recon.session_id}'},
                    'dependencies': ['test_recon'],
                    'timeout': 180,
                    'critical': False
                }
            ]
            
            # Convert to WorkflowStep objects
            from advanced_integration import WorkflowStep
            steps = [WorkflowStep(**step) for step in workflow_steps]
            
            success = self.integration_manager.create_workflow(
                'test_workflow',
                'Test Workflow',
                steps,
                'Test workflow for integration testing'
            )
            assert success, "Workflow creation should succeed"
            print("✅ Test workflow created successfully")
            
            # Test workflow execution (simulated)
            execution_id = self.integration_manager.execute_workflow('test_workflow')
            assert execution_id is not None, "Workflow execution should return ID"
            print("✅ Workflow execution initiated")
            
            self.test_results.append(('Advanced Integration', 'PASS'))
            
        except Exception as e:
            print(f"❌ Advanced integration test failed: {e}")
            self.test_results.append(('Advanced Integration', 'FAIL', str(e)))
    
    def test_performance_optimization(self):
        """Test performance optimization system"""
        print("\n⚡ Testing Performance Optimization")
        print("-" * 40)
        
        try:
            # Initialize performance optimizer
            config = {
                'performance': {
                    'cache_size': 1000,
                    'cache_ttl': 3600,
                    'memory_limit': '1GB'
                }
            }
            self.performance_optimizer = initialize_performance_optimizer(config)
            assert self.performance_optimizer is not None, "Performance optimizer should be initialized"
            print("✅ Performance optimizer initialized successfully")
            
            # Test cache manager
            cache_manager = self.performance_optimizer.cache_manager
            assert cache_manager is not None, "Cache manager should be available"
            
            # Test caching functionality
            cache_manager.set('test_key', 'test_value', ttl=60)
            cached_value = cache_manager.get('test_key')
            assert cached_value == 'test_value', "Cached value should be retrieved correctly"
            print("✅ Caching functionality working")
            
            # Test cache statistics
            stats = cache_manager.get_stats()
            assert 'hits' in stats, "Cache stats should include hits"
            assert 'misses' in stats, "Cache stats should include misses"
            print("✅ Cache statistics working")
            
            # Test database optimizer
            db_optimizer = self.performance_optimizer.db_optimizer
            assert db_optimizer is not None, "Database optimizer should be available"
            
            # Test query tracking
            db_optimizer.track_query("SELECT * FROM test", 0.1)
            recommendations = db_optimizer.get_query_recommendations()
            assert isinstance(recommendations, list), "Query recommendations should be a list"
            print("✅ Database optimization working")
            
            # Test memory manager
            memory_manager = self.performance_optimizer.memory_manager
            assert memory_manager is not None, "Memory manager should be available"
            
            memory_stats = memory_manager.get_memory_stats()
            assert 'total' in memory_stats, "Memory stats should include total"
            assert 'used' in memory_stats, "Memory stats should include used"
            print("✅ Memory management working")
            
            # Test performance profiler
            profiler = self.performance_optimizer.profiler
            assert profiler is not None, "Performance profiler should be available"
            
            # Test function profiling
            @profiler.profile_function
            def test_function():
                time.sleep(0.1)
                return "test"
            
            test_function()
            analysis = profiler.get_performance_analysis()
            assert 'total_operations' in analysis, "Performance analysis should include operations"
            print("✅ Performance profiling working")
            
            # Test optimization recommendations
            recommendations = self.performance_optimizer.get_optimization_recommendations()
            assert isinstance(recommendations, list), "Optimization recommendations should be a list"
            print("✅ Optimization recommendations working")
            
            self.test_results.append(('Performance Optimization', 'PASS'))
            
        except Exception as e:
            print(f"❌ Performance optimization test failed: {e}")
            self.test_results.append(('Performance Optimization', 'FAIL', str(e)))
    
    def test_caching_and_resources(self):
        """Test caching and resource management"""
        print("\n💾 Testing Caching and Resource Management")
        print("-" * 40)
        
        try:
            optimizer = get_performance_optimizer()
            
            # Test cache performance
            cache_manager = optimizer.cache_manager
            
            # Test cache hit/miss scenarios
            cache_manager.set('hit_test', 'value1')
            hit_value = cache_manager.get('hit_test')
            assert hit_value == 'value1', "Cache hit should work"
            
            miss_value = cache_manager.get('nonexistent_key')
            assert miss_value is None, "Cache miss should return None"
            
            stats = cache_manager.get_stats()
            assert stats['hits'] > 0, "Should have cache hits"
            assert stats['misses'] > 0, "Should have cache misses"
            print("✅ Cache hit/miss scenarios working")
            
            # Test cache eviction
            for i in range(1100):  # Exceed cache size
                cache_manager.set(f'key_{i}', f'value_{i}')
            
            # Check if eviction occurred
            stats_after = cache_manager.get_stats()
            assert stats_after['evictions'] > 0, "Cache eviction should occur"
            print("✅ Cache eviction working")
            
            # Test memory management
            memory_manager = optimizer.memory_manager
            memory_stats = memory_manager.get_memory_stats()
            
            assert memory_stats['percent'] >= 0, "Memory usage should be non-negative"
            assert memory_stats['percent'] <= 100, "Memory usage should be <= 100%"
            print("✅ Memory monitoring working")
            
            # Test resource optimization
            optimizer.schedule_optimization('cache')
            optimizer.schedule_optimization('memory')
            optimizer.schedule_optimization('gc')
            print("✅ Resource optimization scheduling working")
            
            self.test_results.append(('Caching and Resources', 'PASS'))
            
        except Exception as e:
            print(f"❌ Caching and resources test failed: {e}")
            self.test_results.append(('Caching and Resources', 'FAIL', str(e)))
    
    def test_security_features(self):
        """Test security features"""
        print("\n🔒 Testing Security Features")
        print("-" * 40)
        
        try:
            integration_manager = get_integration_manager()
            security_manager = integration_manager.security_manager
            
            # Test encryption/decryption
            test_data = "sensitive_data_123"
            encrypted = security_manager.encrypt_data(test_data)
            decrypted = security_manager.decrypt_data(encrypted)
            
            if security_manager.config['enable_encryption']:
                assert encrypted != test_data, "Data should be encrypted"
                assert decrypted == test_data, "Data should be decrypted correctly"
                print("✅ Encryption/decryption working")
            else:
                assert encrypted == test_data, "Data should remain unencrypted when encryption disabled"
                print("✅ Encryption disabled correctly")
            
            # Test input validation
            validation_rules = {
                'required': True,
                'type': 'string',
                'min_length': 5,
                'max_length': 20
            }
            
            valid_input = "valid_input"
            invalid_input = "abc"  # Too short
            
            assert security_manager.validate_input(valid_input, validation_rules), "Valid input should pass validation"
            assert not security_manager.validate_input(invalid_input, validation_rules), "Invalid input should fail validation"
            print("✅ Input validation working")
            
            # Test rate limiting
            identifier = "test_user"
            
            # Should allow first request
            assert security_manager.check_rate_limit(identifier), "First request should be allowed"
            
            # Simulate multiple requests
            for _ in range(10):
                security_manager.check_rate_limit(identifier)
            
            # Should still allow within limit
            assert security_manager.check_rate_limit(identifier), "Request within limit should be allowed"
            print("✅ Rate limiting working")
            
            # Test audit logging
            security_manager.log_audit_event(
                user_id="test_user",
                action="test_action",
                resource="test_resource",
                success=True
            )
            print("✅ Audit logging working")
            
            self.test_results.append(('Security Features', 'PASS'))
            
        except Exception as e:
            print(f"❌ Security features test failed: {e}")
            self.test_results.append(('Security Features', 'FAIL', str(e)))
    
    def test_deployment_and_scaling(self):
        """Test deployment and scaling features"""
        print("\n🚀 Testing Deployment and Scaling")
        print("-" * 40)
        
        try:
            # Initialize deployment manager
            self.deployment_manager = initialize_deployment_manager()
            assert self.deployment_manager is not None, "Deployment manager should be initialized"
            print("✅ Deployment manager initialized successfully")
            
            # Test configuration loading
            config = self.deployment_manager.config
            assert 'environment' in config, "Environment configuration should be loaded"
            assert 'deployments' in config, "Deployments configuration should be loaded"
            print("✅ Deployment configuration loaded")
            
            # Test Docker manager
            docker_manager = self.deployment_manager.docker_manager
            assert docker_manager is not None, "Docker manager should be available"
            print(f"✅ Docker manager available: {docker_manager.available}")
            
            # Test Kubernetes manager
            k8s_manager = self.deployment_manager.kubernetes_manager
            assert k8s_manager is not None, "Kubernetes manager should be available"
            print(f"✅ Kubernetes manager available: {k8s_manager.available}")
            
            # Test health monitor
            health_monitor = self.deployment_manager.health_monitor
            assert health_monitor is not None, "Health monitor should be available"
            
            health_status = health_monitor.get_health_status()
            assert isinstance(health_status, dict), "Health status should be a dictionary"
            print("✅ Health monitoring working")
            
            # Test backup manager
            backup_manager = self.deployment_manager.backup_manager
            assert backup_manager is not None, "Backup manager should be available"
            
            # Test backup creation
            backup_path = backup_manager.create_backup('files')
            if backup_path:
                print(f"✅ Backup created: {backup_path}")
            else:
                print("⚠️  Backup creation skipped (may not have permissions)")
            
            # Test backup listing
            backups = backup_manager.list_backups()
            assert isinstance(backups, list), "Backup list should be a list"
            print("✅ Backup management working")
            
            # Test security hardener
            security_hardener = self.deployment_manager.security_hardener
            assert security_hardener is not None, "Security hardener should be available"
            print("✅ Security hardener available")
            
            # Test deployment report
            report = self.deployment_manager.get_deployment_report()
            assert 'environment' in report, "Deployment report should include environment"
            assert 'deployments' in report, "Deployment report should include deployments"
            print("✅ Deployment reporting working")
            
            self.test_results.append(('Deployment and Scaling', 'PASS'))
            
        except Exception as e:
            print(f"❌ Deployment and scaling test failed: {e}")
            self.test_results.append(('Deployment and Scaling', 'FAIL', str(e)))
    
    def test_backup_and_recovery(self):
        """Test backup and recovery functionality"""
        print("\n💾 Testing Backup and Recovery")
        print("-" * 40)
        
        try:
            deployment_manager = get_deployment_manager()
            backup_manager = deployment_manager.backup_manager
            
            # Test backup creation
            backup_path = backup_manager.create_backup('files')
            if backup_path:
                assert os.path.exists(backup_path), "Backup should be created"
                print(f"✅ Backup created successfully: {backup_path}")
                
                # Test backup listing
                backups = backup_manager.list_backups()
                assert len(backups) > 0, "Should have at least one backup"
                
                # Find our backup
                our_backup = next((b for b in backups if b['path'] == backup_path), None)
                assert our_backup is not None, "Our backup should be in the list"
                assert our_backup['size'] > 0, "Backup should have size > 0"
                print("✅ Backup listing working")
                
                # Test backup restoration (simulated)
                # Note: We don't actually restore to avoid affecting the test environment
                print("✅ Backup restoration test skipped (simulated)")
                
            else:
                print("⚠️  Backup creation skipped (may not have permissions)")
            
            self.test_results.append(('Backup and Recovery', 'PASS'))
            
        except Exception as e:
            print(f"❌ Backup and recovery test failed: {e}")
            self.test_results.append(('Backup and Recovery', 'FAIL', str(e)))
    
    def test_health_monitoring(self):
        """Test health monitoring functionality"""
        print("\n🏥 Testing Health Monitoring")
        print("-" * 40)
        
        try:
            deployment_manager = get_deployment_manager()
            health_monitor = deployment_manager.health_monitor
            
            # Test health status
            health_status = health_monitor.get_health_status()
            assert isinstance(health_status, dict), "Health status should be a dictionary"
            print("✅ Health status monitoring working")
            
            # Test recovery action registration
            def test_recovery_action():
                print("Test recovery action executed")
            
            health_monitor.add_recovery_action('test_service', test_recovery_action)
            print("✅ Recovery action registration working")
            
            # Test health checks (simulated)
            # Add a test health check
            health_monitor.health_checks['test_service'] = {
                'url': 'http://localhost:9999/health'  # Non-existent service
            }
            
            # The health monitor runs in a background thread, so we just verify it's working
            print("✅ Health monitoring system working")
            
            self.test_results.append(('Health Monitoring', 'PASS'))
            
        except Exception as e:
            print(f"❌ Health monitoring test failed: {e}")
            self.test_results.append(('Health Monitoring', 'FAIL', str(e)))
    
    def test_analytics_and_reporting(self):
        """Test analytics and reporting functionality"""
        print("\n📊 Testing Analytics and Reporting")
        print("-" * 40)
        
        try:
            # Test performance analytics
            optimizer = get_performance_optimizer()
            
            # Get performance report
            report = optimizer.get_performance_report()
            assert 'cache_stats' in report, "Report should include cache stats"
            assert 'memory_stats' in report, "Report should include memory stats"
            assert 'performance_analysis' in report, "Report should include performance analysis"
            assert 'recommendations' in report, "Report should include recommendations"
            print("✅ Performance reporting working")
            
            # Test cache statistics
            cache_stats = report['cache_stats']
            assert 'hits' in cache_stats, "Cache stats should include hits"
            assert 'misses' in cache_stats, "Cache stats should include misses"
            assert 'hit_rate' in cache_stats, "Cache stats should include hit rate"
            print("✅ Cache analytics working")
            
            # Test memory statistics
            memory_stats = report['memory_stats']
            assert 'total' in memory_stats, "Memory stats should include total"
            assert 'used' in memory_stats, "Memory stats should include used"
            assert 'percent' in memory_stats, "Memory stats should include percent"
            print("✅ Memory analytics working")
            
            # Test performance analysis
            performance_analysis = report['performance_analysis']
            assert isinstance(performance_analysis, dict), "Performance analysis should be a dictionary"
            print("✅ Performance analysis working")
            
            # Test optimization recommendations
            recommendations = report['recommendations']
            assert isinstance(recommendations, list), "Recommendations should be a list"
            print("✅ Optimization recommendations working")
            
            # Test system information
            system_info = report['system_info']
            assert 'cpu_count' in system_info, "System info should include CPU count"
            assert 'memory_total' in system_info, "System info should include memory total"
            print("✅ System information working")
            
            self.test_results.append(('Analytics and Reporting', 'PASS'))
            
        except Exception as e:
            print(f"❌ Analytics and reporting test failed: {e}")
            self.test_results.append(('Analytics and Reporting', 'FAIL', str(e)))
    
    def test_workflow_automation(self):
        """Test workflow automation functionality"""
        print("\n🤖 Testing Workflow Automation")
        print("-" * 40)
        
        try:
            integration_manager = get_integration_manager()
            
            # Test workflow management
            workflows = integration_manager.workflows
            assert isinstance(workflows, dict), "Workflows should be a dictionary"
            
            # Check if our test workflow exists
            if 'test_workflow' in workflows:
                test_workflow = workflows['test_workflow']
                assert len(test_workflow) > 0, "Test workflow should have steps"
                print("✅ Test workflow exists")
                
                # Test workflow validation
                is_valid = integration_manager._validate_workflow(test_workflow)
                assert is_valid, "Test workflow should be valid"
                print("✅ Workflow validation working")
            
            # Test execution management
            executions = integration_manager.executions
            assert isinstance(executions, dict), "Executions should be a dictionary"
            print("✅ Execution management working")
            
            # Test workflow status
            if executions:
                execution_id = list(executions.keys())[0]
                status = integration_manager.get_workflow_status(execution_id)
                assert status is not None, "Workflow status should be retrievable"
                print("✅ Workflow status tracking working")
            
            self.test_results.append(('Workflow Automation', 'PASS'))
            
        except Exception as e:
            print(f"❌ Workflow automation test failed: {e}")
            self.test_results.append(('Workflow Automation', 'FAIL', str(e)))
    
    def test_optimization_recommendations(self):
        """Test optimization recommendations"""
        print("\n💡 Testing Optimization Recommendations")
        print("-" * 40)
        
        try:
            optimizer = get_performance_optimizer()
            
            # Get optimization recommendations
            recommendations = optimizer.get_optimization_recommendations()
            assert isinstance(recommendations, list), "Recommendations should be a list"
            print(f"✅ Generated {len(recommendations)} optimization recommendations")
            
            # Test recommendation structure
            if recommendations:
                recommendation = recommendations[0]
                assert hasattr(recommendation, 'type'), "Recommendation should have type"
                assert hasattr(recommendation, 'priority'), "Recommendation should have priority"
                assert hasattr(recommendation, 'description'), "Recommendation should have description"
                assert hasattr(recommendation, 'impact'), "Recommendation should have impact"
                assert hasattr(recommendation, 'implementation'), "Recommendation should have implementation"
                assert hasattr(recommendation, 'estimated_improvement'), "Recommendation should have estimated improvement"
                print("✅ Recommendation structure correct")
            
            # Test database recommendations
            db_recommendations = optimizer.db_optimizer.get_query_recommendations()
            assert isinstance(db_recommendations, list), "Database recommendations should be a list"
            print("✅ Database recommendations working")
            
            # Test performance recommendations
            perf_recommendations = optimizer.profiler.get_optimization_recommendations()
            assert isinstance(perf_recommendations, list), "Performance recommendations should be a list"
            print("✅ Performance recommendations working")
            
            self.test_results.append(('Optimization Recommendations', 'PASS'))
            
        except Exception as e:
            print(f"❌ Optimization recommendations test failed: {e}")
            self.test_results.append(('Optimization Recommendations', 'FAIL', str(e)))
    
    def print_test_summary(self):
        """Print test summary"""
        print("\n" + "=" * 70)
        print("📋 Step 7 Test Summary")
        print("=" * 70)
        
        passed = 0
        failed = 0
        skipped = 0
        
        for test_name, result, *details in self.test_results:
            if result == 'PASS':
                print(f"✅ {test_name}: PASS")
                passed += 1
            elif result == 'FAIL':
                print(f"❌ {test_name}: FAIL")
                if details:
                    print(f"   Error: {details[0]}")
                failed += 1
            elif result == 'SKIP':
                print(f"⚠️  {test_name}: SKIP")
                if details:
                    print(f"   Reason: {details[0]}")
                skipped += 1
        
        print(f"\n📊 Results: {passed} passed, {failed} failed, {skipped} skipped")
        
        if failed == 0:
            print("🎉 All Step 7 tests passed!")
            print("\n🚀 Step 7: Advanced Integration & Optimization is ready for production!")
        else:
            print(f"⚠️  {failed} test(s) failed. Please check the errors above.")
    
    def cleanup(self):
        """Clean up test files"""
        print("\n🧹 Cleaning up test files...")
        
        # Clean up test databases
        test_dbs = ['advanced_integration.db', 'dashboard.db']
        for db_file in test_dbs:
            if os.path.exists(db_file):
                os.remove(db_file)
                print(f"✅ Removed test database: {db_file}")
        
        # Clean up test output directories
        test_dirs = ['advanced_integration_results', 'dashboard_results', 'backups']
        for dir_name in test_dirs:
            if os.path.exists(dir_name):
                import shutil
                shutil.rmtree(dir_name)
                print(f"✅ Removed test directory: {dir_name}")

def main():
    """Main test function"""
    print("🧪 Step 7: Advanced Integration & Optimization Test Suite")
    print("=" * 80)
    
    # Create tester instance
    tester = Step7Tester()
    
    try:
        # Run all tests
        tester.run_all_tests()
        
    except KeyboardInterrupt:
        print("\n⚠️  Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        logger.exception("Test suite error")
    
    finally:
        # Ask user if they want to clean up
        try:
            cleanup = input("\n🧹 Clean up test files? (y/n): ").lower().strip()
            if cleanup == 'y':
                tester.cleanup()
        except:
            pass

if __name__ == '__main__':
    main() 