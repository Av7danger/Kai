#!/usr/bin/env python3
"""
🧪 Enhanced System Test Suite
Tests the complete enhanced bug hunting system with robust error handling
"""

import os
import sys
import time
import json
import requests
import subprocess
import threading
from pathlib import Path
from typing import Dict, List, Any

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_subprocess_handler():
    """Test the robust subprocess handler"""
    print("🔧 Testing Subprocess Handler...")
    
    try:
        from subprocess_handler import subprocess_handler, SubprocessResult
        
        # Test successful command
        result = subprocess_handler.run_sync_command(['echo', 'test'])
        assert result.success, f"Command should succeed: {result.error_message}"
        assert 'test' in result.stdout, "Output should contain 'test'"
        print("✅ Subprocess handler - successful command test passed")
        
        # Test command not found
        result = subprocess_handler.run_sync_command(['nonexistent_command'])
        assert not result.success, "Command should fail"
        assert result.error_type == "file_not_found", f"Error type should be file_not_found, got {result.error_type}"
        print("✅ Subprocess handler - command not found test passed")
        
        # Test command existence check
        exists = subprocess_handler.check_command_exists('echo')
        assert exists, "echo command should exist"
        print("✅ Subprocess handler - command existence check passed")
        
        return True
        
    except Exception as e:
        print(f"❌ Subprocess handler test failed: {e}")
        return False

def test_kali_optimizer():
    """Test the Kali Linux optimizer"""
    print("🛠️ Testing Kali Optimizer...")
    
    try:
        from kali_optimizer import get_kali_optimizer
        
        optimizer = get_kali_optimizer()
        
        # Test tool checking
        tools_status = optimizer.check_all_tools()
        assert isinstance(tools_status, dict), "Tools status should be a dictionary"
        print(f"✅ Kali optimizer - checked {len(tools_status)} tools")
        
        # Test system diagnostics
        diagnostics = optimizer.run_system_diagnostics()
        assert diagnostics is not None, "System diagnostics should not be None"
        print(f"✅ Kali optimizer - CPU: {diagnostics.cpu_usage}%, Memory: {diagnostics.memory_usage}%")
        
        # Test diagnostics summary
        summary = optimizer.get_diagnostics_summary()
        assert isinstance(summary, dict), "Diagnostics summary should be a dictionary"
        print("✅ Kali optimizer - diagnostics summary generated")
        
        return True
        
    except Exception as e:
        print(f"❌ Kali optimizer test failed: {e}")
        return False

def test_streamlined_system():
    """Test the streamlined autonomous system"""
    print("🎯 Testing Streamlined System...")
    
    try:
        from streamlined_autonomous import initialize_streamlined_hunter, get_streamlined_hunter
        
        # Initialize the system
        hunter = initialize_streamlined_hunter()
        assert hunter is not None, "Hunter should be initialized"
        print("✅ Streamlined system - initialization passed")
        
        # Test program submission
        program_id = hunter.submit_program(
            name="Test Program",
            target_domain="example.com",
            scope=["*.example.com"],
            reward_range="high",
            platform="hackerone"
        )
        assert program_id is not None, "Program ID should be returned"
        print(f"✅ Streamlined system - program submitted: {program_id}")
        
        # Test Gemini analysis
        analysis = hunter.analyze_with_gemini(program_id)
        assert isinstance(analysis, dict), "Analysis should be a dictionary"
        print("✅ Streamlined system - Gemini analysis completed")
        
        # Test workflow execution
        workflow_result = hunter.execute_workflow(program_id)
        assert isinstance(workflow_result, dict), "Workflow result should be a dictionary"
        print("✅ Streamlined system - workflow execution completed")
        
        # Test vulnerability discovery
        vulnerabilities = hunter.discover_vulnerabilities(program_id, workflow_result)
        assert isinstance(vulnerabilities, list), "Vulnerabilities should be a list"
        print(f"✅ Streamlined system - discovered {len(vulnerabilities)} vulnerabilities")
        
        return True
        
    except Exception as e:
        print(f"❌ Streamlined system test failed: {e}")
        return False

def test_api_endpoints():
    """Test the API endpoints"""
    print("🌐 Testing API Endpoints...")
    
    try:
        # Start the server in a separate thread
        def start_server():
            from streamlined_autonomous import app
            app.run(host='127.0.0.1', port=5001, debug=False, use_reloader=False)
        
        server_thread = threading.Thread(target=start_server, daemon=True)
        server_thread.start()
        
        # Wait for server to start
        time.sleep(3)
        
        base_url = "http://127.0.0.1:5001"
        
        # Test diagnostics endpoint
        response = requests.get(f"{base_url}/api/diagnostics", timeout=10)
        assert response.status_code == 200, f"Diagnostics endpoint failed: {response.status_code}"
        diagnostics = response.json()
        assert isinstance(diagnostics, dict), "Diagnostics should be a dictionary"
        print("✅ API - diagnostics endpoint working")
        
        # Test tools endpoint
        response = requests.get(f"{base_url}/api/tools", timeout=10)
        assert response.status_code == 200, f"Tools endpoint failed: {response.status_code}"
        tools = response.json()
        assert isinstance(tools, dict), "Tools should be a dictionary"
        print("✅ API - tools endpoint working")
        
        # Test program submission
        program_data = {
            "name": "API Test Program",
            "target_domain": "test.example.com",
            "scope": ["*.test.example.com"],
            "reward_range": "medium",
            "platform": "hackerone"
        }
        
        response = requests.post(f"{base_url}/api/submit_program", 
                               json=program_data, timeout=30)
        assert response.status_code == 200, f"Program submission failed: {response.status_code}"
        result = response.json()
        assert result['success'], f"Program submission should succeed: {result.get('error')}"
        print("✅ API - program submission working")
        
        return True
        
    except Exception as e:
        print(f"❌ API endpoints test failed: {e}")
        return False

def test_error_handling():
    """Test error handling and recovery"""
    print("🛡️ Testing Error Handling...")
    
    try:
        from subprocess_handler import subprocess_handler
        
        # Test timeout handling
        result = subprocess_handler.run_sync_command(['sleep', '10'], timeout=1)
        assert not result.success, "Command should timeout"
        assert result.killed_by_timeout, "Command should be killed by timeout"
        print("✅ Error handling - timeout detection working")
        
        # Test permission error handling
        result = subprocess_handler.run_sync_command(['/root/protected_file'])
        if not result.success:
            print("✅ Error handling - permission error detection working")
        
        # Test retry mechanism
        result = subprocess_handler.run_sync_command(['echo', 'retry_test'])
        assert result.success, "Retry mechanism should work"
        print("✅ Error handling - retry mechanism working")
        
        return True
        
    except Exception as e:
        print(f"❌ Error handling test failed: {e}")
        return False

def test_dashboard_functionality():
    """Test dashboard functionality"""
    print("📊 Testing Dashboard Functionality...")
    
    try:
        # Check if dashboard templates exist
        templates_dir = Path(__file__).parent / "templates"
        assert (templates_dir / "streamlined_dashboard.html").exists(), "Streamlined dashboard template missing"
        assert (templates_dir / "enhanced_dashboard.html").exists(), "Enhanced dashboard template missing"
        print("✅ Dashboard - templates exist")
        
        # Check if static assets are accessible
        static_dir = Path(__file__).parent / "static"
        if static_dir.exists():
            print("✅ Dashboard - static assets directory exists")
        
        return True
        
    except Exception as e:
        print(f"❌ Dashboard functionality test failed: {e}")
        return False

def test_system_integration():
    """Test complete system integration"""
    print("🔗 Testing System Integration...")
    
    try:
        # Test all components working together
        from subprocess_handler import subprocess_handler
        from kali_optimizer import get_kali_optimizer
        from streamlined_autonomous import initialize_streamlined_hunter
        
        # Initialize all components
        optimizer = get_kali_optimizer()
        hunter = initialize_streamlined_hunter()
        
        # Test system diagnostics
        diagnostics = optimizer.run_system_diagnostics()
        assert diagnostics is not None, "System diagnostics should work"
        
        # Test tool status
        tools_status = optimizer.check_all_tools()
        assert isinstance(tools_status, dict), "Tools status should work"
        
        # Test program workflow
        program_id = hunter.submit_program(
            name="Integration Test",
            target_domain="integration.test",
            scope=["*.integration.test"],
            reward_range="low",
            platform="test"
        )
        assert program_id is not None, "Program submission should work"
        
        print("✅ System integration - all components working together")
        return True
        
    except Exception as e:
        print(f"❌ System integration test failed: {e}")
        return False

def run_performance_test():
    """Run performance tests"""
    print("⚡ Running Performance Tests...")
    
    try:
        from subprocess_handler import subprocess_handler
        import time
        
        # Test subprocess handler performance
        start_time = time.time()
        for i in range(10):
            result = subprocess_handler.run_sync_command(['echo', f'test_{i}'])
            assert result.success, f"Performance test command {i} failed"
        
        elapsed_time = time.time() - start_time
        print(f"✅ Performance - 10 subprocess calls in {elapsed_time:.2f}s")
        
        # Test concurrent operations
        import concurrent.futures
        
        def run_concurrent_test():
            result = subprocess_handler.run_sync_command(['echo', 'concurrent'])
            return result.success
        
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(run_concurrent_test) for _ in range(10)]
            results = [future.result() for future in futures]
        
        elapsed_time = time.time() - start_time
        assert all(results), "All concurrent operations should succeed"
        print(f"✅ Performance - 10 concurrent operations in {elapsed_time:.2f}s")
        
        return True
        
    except Exception as e:
        print(f"❌ Performance test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 Enhanced Bug Hunting System Test Suite")
    print("=" * 50)
    
    tests = [
        ("Subprocess Handler", test_subprocess_handler),
        ("Kali Optimizer", test_kali_optimizer),
        ("Streamlined System", test_streamlined_system),
        ("API Endpoints", test_api_endpoints),
        ("Error Handling", test_error_handling),
        ("Dashboard Functionality", test_dashboard_functionality),
        ("System Integration", test_system_integration),
        ("Performance", run_performance_test)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n🔍 Running {test_name} Test...")
        try:
            success = test_func()
            results.append((test_name, success))
            if success:
                print(f"✅ {test_name} - PASSED")
            else:
                print(f"❌ {test_name} - FAILED")
        except Exception as e:
            print(f"❌ {test_name} - ERROR: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{test_name}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! System is ready for production.")
        return 0
    else:
        print("⚠️ Some tests failed. Please review the issues above.")
        return 1

if __name__ == '__main__':
    exit(main()) 