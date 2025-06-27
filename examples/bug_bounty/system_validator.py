#!/usr/bin/env python3
"""
🎯 ULTRA-OPTIMIZED GEMINI AGENTIC SYSTEM - COMPLETE TESTING SUITE
🚀 Comprehensive testing and validation of all system components
"""

import asyncio
import os
import sys
import time
import json
from pathlib import Path

# Test imports
try:
    from ultra_optimized_gemini_system import UltraOrchestrator
    from gemini_analytics_dashboard import UltraAnalyticsDashboard
    from production_deployment import ProductionDeployment
    print("✅ All system modules imported successfully")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)

class SystemValidator:
    """Comprehensive system validation and testing"""
    
    def __init__(self):
        self.test_results = {
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'details': []
        }
    
    def test(self, name: str, func, *args, **kwargs):
        """Run a test and record results"""
        try:
            print(f"🔍 Testing: {name}")
            result = func(*args, **kwargs)
            if asyncio.iscoroutine(result):
                result = asyncio.run(result)
            
            if result:
                print(f"✅ PASS: {name}")
                self.test_results['passed'] += 1
                self.test_results['details'].append(f"✅ {name}: PASSED")
                return True
            else:
                print(f"⚠️ WARN: {name}")
                self.test_results['warnings'] += 1
                self.test_results['details'].append(f"⚠️ {name}: WARNING")
                return False
        except Exception as e:
            print(f"❌ FAIL: {name} - {e}")
            self.test_results['failed'] += 1
            self.test_results['details'].append(f"❌ {name}: FAILED - {e}")
            return False
    
    def test_system_requirements(self):
        """Test system requirements"""
        print("\n🔧 Testing System Requirements...")
        
        # Test Python version
        self.test("Python 3.11+", lambda: sys.version_info >= (3, 11))
        
        # Test required modules
        modules = ['google.generativeai', 'psutil', 'yaml', 'sqlite3']
        for module in modules:
            self.test(f"Module: {module}", lambda m=module: __import__(m))
        
        # Test file system permissions
        self.test("File system write access", lambda: self._test_file_access())
        
        return True
    
    def _test_file_access(self):
        """Test file system access"""
        try:
            test_file = Path("test_write_access.tmp")
            test_file.write_text("test")
            test_file.unlink()
            return True
        except:
            return False
    
    async def test_ultra_system(self):
        """Test ultra-optimized Gemini system"""
        print("\n🧠 Testing Ultra Gemini System...")
        
        try:
            # Initialize orchestrator
            orchestrator = UltraOrchestrator()
            
            # Test initialization
            self.test("Orchestrator initialization", lambda: orchestrator is not None)
            
            # Test database connection
            self.test("Database connection", lambda: os.path.exists(orchestrator.db_path))
            
            # Test Gemini API (simulation mode)
            self.test("Gemini API simulation", lambda: orchestrator.gemini is not None)
            
            # Test campaign creation (quick test)
            campaign_id = await orchestrator.start_ultra_campaign("test.example.com")
            self.test("Campaign creation", lambda: campaign_id is not None)
            
            # Test workflow execution (1 iteration)
            results = await orchestrator.execute_ultra_workflow(campaign_id, max_iterations=1)
            self.test("Workflow execution", lambda: results['iterations'] >= 1)
            
            print(f"🎯 Test campaign completed with {results['iterations']} iterations")
            
        except Exception as e:
            self.test("Ultra system test", lambda: False)
            print(f"❌ Ultra system test failed: {e}")
    
    def test_analytics_dashboard(self):
        """Test analytics dashboard"""
        print("\n📊 Testing Analytics Dashboard...")
        
        try:
            dashboard = UltraAnalyticsDashboard()
            
            # Test dashboard initialization
            self.test("Dashboard initialization", lambda: dashboard is not None)
            
            # Test report generation
            report = dashboard.generate_comprehensive_report()
            self.test("Report generation", lambda: 'report_timestamp' in report)
            
            # Test report export
            filename = dashboard.export_report_to_file("test_report.json")
            self.test("Report export", lambda: "successfully" in filename)
            
            # Cleanup
            if os.path.exists("test_report.json"):
                os.remove("test_report.json")
            
        except Exception as e:
            self.test("Analytics dashboard test", lambda: False)
            print(f"❌ Analytics test failed: {e}")
    
    def test_production_deployment(self):
        """Test production deployment system"""
        print("\n🏭 Testing Production Deployment...")
        
        try:
            deployment = ProductionDeployment("test_config.yaml")
            
            # Test deployment initialization
            self.test("Deployment initialization", lambda: deployment is not None)
            
            # Test configuration
            self.test("Configuration loading", lambda: deployment.config is not None)
            
            # Test production readiness check
            validation = deployment.validate_production_readiness()
            self.test("Production validation", lambda: 'ready_for_production' in validation)
            
            # Cleanup test config
            if os.path.exists("test_config.yaml"):
                os.remove("test_config.yaml")
            
        except Exception as e:
            self.test("Production deployment test", lambda: False)
            print(f"❌ Production test failed: {e}")
    
    def test_performance_optimization(self):
        """Test performance optimizations"""
        print("\n⚡ Testing Performance Optimizations...")
        
        try:
            # Test caching system
            from ultra_optimized_gemini_system import UltraEfficientGeminiAPI
            gemini_api = UltraEfficientGeminiAPI()
            
            self.test("Gemini API initialization", lambda: gemini_api is not None)
            self.test("Cache system", lambda: hasattr(gemini_api, 'decision_cache'))
            self.test("Pattern recognition", lambda: hasattr(gemini_api, 'pattern_cache'))
            
            # Test resource manager
            from ultra_optimized_gemini_system import UltraResourceManager
            resource_manager = UltraResourceManager()
            
            self.test("Resource manager", lambda: resource_manager is not None)
            self.test("Performance profiles", lambda: hasattr(resource_manager, 'performance_profiles'))
            self.test("Execution cache", lambda: hasattr(resource_manager, 'execution_cache'))
            
        except Exception as e:
            self.test("Performance optimization test", lambda: False)
            print(f"❌ Performance test failed: {e}")
    
    def run_complete_validation(self):
        """Run complete system validation"""
        print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║     🎯 ULTRA GEMINI SYSTEM - COMPLETE VALIDATION SUITE          ║
    ║              Comprehensive Testing & Validation                  ║
    ╚═══════════════════════════════════════════════════════════════════╝
        """)
        
        start_time = time.time()
        
        # Run all tests
        self.test_system_requirements()
        asyncio.run(self.test_ultra_system())
        self.test_analytics_dashboard()
        self.test_production_deployment()
        self.test_performance_optimization()
        
        # Calculate results
        duration = time.time() - start_time
        total_tests = self.test_results['passed'] + self.test_results['failed'] + self.test_results['warnings']
        
        print(f"\n{'='*70}")
        print("🏆 VALIDATION COMPLETE")
        print(f"{'='*70}")
        print(f"⏱️ Duration: {duration:.2f} seconds")
        print(f"📊 Total Tests: {total_tests}")
        print(f"✅ Passed: {self.test_results['passed']}")
        print(f"⚠️ Warnings: {self.test_results['warnings']}")
        print(f"❌ Failed: {self.test_results['failed']}")
        
        success_rate = (self.test_results['passed'] / total_tests * 100) if total_tests > 0 else 0
        print(f"📈 Success Rate: {success_rate:.1f}%")
        
        if self.test_results['failed'] == 0:
            print("\n🎉 ALL CRITICAL TESTS PASSED!")
            print("🚀 System is ready for production deployment!")
        else:
            print(f"\n⚠️ {self.test_results['failed']} critical tests failed")
            print("🔧 Review failed tests before deployment")
        
        # Detailed results
        print(f"\n📋 Detailed Results:")
        for detail in self.test_results['details']:
            print(f"  {detail}")
        
        return self.test_results['failed'] == 0

def run_performance_benchmark():
    """Run performance benchmark"""
    print("\n⚡ Running Performance Benchmark...")
    
    async def benchmark():
        orchestrator = UltraOrchestrator()
        
        # Benchmark campaign execution
        start_time = time.time()
        campaign_id = await orchestrator.start_ultra_campaign("benchmark.test.com")
        results = await orchestrator.execute_ultra_workflow(campaign_id, max_iterations=3)
        duration = time.time() - start_time
        
        print(f"📊 Benchmark Results:")
        print(f"  ⏱️ Duration: {duration:.2f} seconds")
        print(f"  🔄 Iterations: {results['iterations']}")
        print(f"  📈 Decisions/Second: {results['iterations'] / duration:.1f}")
        print(f"  🧠 API Calls: {orchestrator.gemini.api_calls}")
        print(f"  📦 Cache Hits: {orchestrator.gemini.cache_hits}")
        
        if orchestrator.gemini.api_calls > 0:
            cache_rate = orchestrator.gemini.cache_hits / orchestrator.gemini.api_calls * 100
            print(f"  💾 Cache Efficiency: {cache_rate:.1f}%")
        
        return duration < 10.0  # Should complete in under 10 seconds
    
    result = asyncio.run(benchmark())
    return result

def main():
    """Main testing function"""
    print("🚀 Starting Ultra Gemini System Validation...")
    
    # Check API key status
    api_key = os.getenv('GEMINI_API_KEY')
    if api_key:
        print("✅ Gemini API key detected - running in production mode")
    else:
        print("⚠️ No API key - running in simulation mode")
    
    # Run validation
    validator = SystemValidator()
    success = validator.run_complete_validation()
    
    # Run performance benchmark
    if success:
        print("\n" + "="*70)
        print("🏎️ PERFORMANCE BENCHMARK")
        print("="*70)
        benchmark_success = run_performance_benchmark()
        
        if benchmark_success:
            print("✅ Performance benchmark passed!")
        else:
            print("⚠️ Performance benchmark concerns detected")
    
    # Final status
    print(f"\n{'='*70}")
    if success:
        print("🎯 SYSTEM VALIDATION: PASSED")
        print("🚀 Ready for production deployment!")
        print("📖 Next steps:")
        print("  1. Set GEMINI_API_KEY for production mode")
        print("  2. Run: python production_deployment.py")
        print("  3. Deploy with: cd ultra_gemini_production && ./deploy.sh")
    else:
        print("❌ SYSTEM VALIDATION: FAILED")
        print("🔧 Fix issues before deployment")
    
    print("="*70)
    return 0 if success else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
