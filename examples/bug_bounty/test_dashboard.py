#!/usr/bin/env python3
"""
🧪 Dashboard Test Script
Comprehensive testing for the dashboard functionality

Tests:
- Dashboard initialization and configuration
- User authentication and management
- Framework integration
- API endpoints
- Analytics and reporting
- Real-time updates
- Export functionality
"""

import os
import sys
import time
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import logging

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from dashboard import initialize_dashboard_manager, get_dashboard_manager
    from dashboard_api import initialize_dashboard_api, get_dashboard_api
    DASHBOARD_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Dashboard components not available: {e}")
    DASHBOARD_AVAILABLE = False

# Import framework components for testing
try:
    from recon_manager import get_recon_manager
    from ai_analysis import get_ai_manager
    from monitoring_manager import get_monitoring_manager
    from bug_submission import get_submission_manager
    from exploit_manager import get_exploit_manager
    FRAMEWORK_AVAILABLE = True
except ImportError:
    FRAMEWORK_AVAILABLE = False
    print("Warning: Framework components not available")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DashboardTester:
    """Dashboard testing class"""
    
    def __init__(self):
        self.test_results = []
        self.dashboard_manager = None
        self.dashboard_api = None
        
    def run_all_tests(self):
        """Run all dashboard tests"""
        print("🚀 Starting Dashboard Tests")
        print("=" * 50)
        
        if not DASHBOARD_AVAILABLE:
            print("❌ Dashboard components not available. Skipping tests.")
            return
        
        # Test dashboard initialization
        self.test_dashboard_initialization()
        
        # Test user management
        self.test_user_management()
        
        # Test framework integration
        self.test_framework_integration()
        
        # Test analytics and reporting
        self.test_analytics_and_reporting()
        
        # Test API functionality
        self.test_api_functionality()
        
        # Test export functionality
        self.test_export_functionality()
        
        # Print test summary
        self.print_test_summary()
    
    def test_dashboard_initialization(self):
        """Test dashboard initialization"""
        print("\n📊 Testing Dashboard Initialization")
        print("-" * 30)
        
        try:
            # Test dashboard manager initialization
            self.dashboard_manager = initialize_dashboard_manager()
            assert self.dashboard_manager is not None, "Dashboard manager should be initialized"
            print("✅ Dashboard manager initialized successfully")
            
            # Test configuration loading
            config = self.dashboard_manager.config
            assert 'dashboard' in config, "Dashboard configuration should be loaded"
            assert 'users' in config, "Users configuration should be loaded"
            print("✅ Configuration loaded successfully")
            
            # Test database initialization
            assert os.path.exists('dashboard.db'), "Dashboard database should be created"
            print("✅ Database initialized successfully")
            
            # Test output directory creation
            output_dir = Path('dashboard_results')
            assert output_dir.exists(), "Output directory should be created"
            for subdir in ['reports', 'exports', 'charts', 'logs']:
                assert (output_dir / subdir).exists(), f"Subdirectory {subdir} should be created"
            print("✅ Output directories created successfully")
            
            self.test_results.append(('Dashboard Initialization', 'PASS'))
            
        except Exception as e:
            print(f"❌ Dashboard initialization failed: {e}")
            self.test_results.append(('Dashboard Initialization', 'FAIL', str(e)))
    
    def test_user_management(self):
        """Test user management functionality"""
        print("\n👥 Testing User Management")
        print("-" * 30)
        
        try:
            # Test default admin user creation
            admin_user = self.dashboard_manager.authenticate_user('admin', 'admin123')
            assert admin_user is not None, "Default admin user should exist"
            assert admin_user.role == 'admin', "Admin user should have admin role"
            print("✅ Default admin user authentication successful")
            
            # Test invalid authentication
            invalid_user = self.dashboard_manager.authenticate_user('invalid', 'invalid')
            assert invalid_user is None, "Invalid credentials should return None"
            print("✅ Invalid authentication handled correctly")
            
            # Test user retrieval
            user = self.dashboard_manager.get_user_by_id(admin_user.id)
            assert user is not None, "User should be retrievable by ID"
            assert user.username == 'admin', "Retrieved user should match"
            print("✅ User retrieval by ID successful")
            
            self.test_results.append(('User Management', 'PASS'))
            
        except Exception as e:
            print(f"❌ User management test failed: {e}")
            self.test_results.append(('User Management', 'FAIL', str(e)))
    
    def test_framework_integration(self):
        """Test framework component integration"""
        print("\n🔗 Testing Framework Integration")
        print("-" * 30)
        
        if not FRAMEWORK_AVAILABLE:
            print("⚠️  Framework components not available. Skipping integration tests.")
            self.test_results.append(('Framework Integration', 'SKIP', 'Components not available'))
            return
        
        try:
            # Test framework manager initialization
            managers = self.dashboard_manager.framework_managers
            assert len(managers) > 0, "At least one framework manager should be available"
            print(f"✅ {len(managers)} framework managers initialized")
            
            # Test reconnaissance integration
            if 'recon' in managers:
                recon_manager = managers['recon']
                assert hasattr(recon_manager, 'targets'), "Recon manager should have targets"
                print("✅ Reconnaissance manager integrated")
            
            # Test AI analysis integration
            if 'ai' in managers:
                ai_manager = managers['ai']
                assert hasattr(ai_manager, 'analysis_sessions'), "AI manager should have sessions"
                print("✅ AI analysis manager integrated")
            
            # Test monitoring integration
            if 'monitoring' in managers:
                monitoring_manager = managers['monitoring']
                assert hasattr(monitoring_manager, 'active_tasks'), "Monitoring manager should have tasks"
                print("✅ Monitoring manager integrated")
            
            # Test submission integration
            if 'submission' in managers:
                submission_manager = managers['submission']
                assert hasattr(submission_manager, 'submissions'), "Submission manager should have submissions"
                print("✅ Submission manager integrated")
            
            # Test exploitation integration
            if 'exploitation' in managers:
                exploit_manager = managers['exploitation']
                assert hasattr(exploit_manager, 'active_sessions'), "Exploit manager should have sessions"
                print("✅ Exploitation manager integrated")
            
            self.test_results.append(('Framework Integration', 'PASS'))
            
        except Exception as e:
            print(f"❌ Framework integration test failed: {e}")
            self.test_results.append(('Framework Integration', 'FAIL', str(e)))
    
    def test_analytics_and_reporting(self):
        """Test analytics and reporting functionality"""
        print("\n📈 Testing Analytics and Reporting")
        print("-" * 30)
        
        try:
            # Test dashboard statistics
            stats = self.dashboard_manager.get_dashboard_stats()
            assert hasattr(stats, 'total_targets'), "Stats should have total_targets"
            assert hasattr(stats, 'active_scans'), "Stats should have active_scans"
            assert hasattr(stats, 'vulnerabilities_found'), "Stats should have vulnerabilities_found"
            assert hasattr(stats, 'success_rate'), "Stats should have success_rate"
            print("✅ Dashboard statistics generated successfully")
            
            # Test analytics charts generation
            charts = self.dashboard_manager.generate_analytics_charts()
            assert isinstance(charts, dict), "Charts should be a dictionary"
            print("✅ Analytics charts generated successfully")
            
            # Test framework status
            status = self.dashboard_manager._get_framework_status()
            assert isinstance(status, dict), "Framework status should be a dictionary"
            print("✅ Framework status retrieved successfully")
            
            # Test report export
            report_path = self.dashboard_manager.export_report('overview', 'json')
            assert os.path.exists(report_path), "Report should be exported"
            print(f"✅ Report exported successfully: {report_path}")
            
            # Test HTML report generation
            html_report_path = self.dashboard_manager.export_report('overview', 'html')
            assert os.path.exists(html_report_path), "HTML report should be exported"
            print(f"✅ HTML report exported successfully: {html_report_path}")
            
            self.test_results.append(('Analytics and Reporting', 'PASS'))
            
        except Exception as e:
            print(f"❌ Analytics and reporting test failed: {e}")
            self.test_results.append(('Analytics and Reporting', 'FAIL', str(e)))
    
    def test_api_functionality(self):
        """Test API functionality"""
        print("\n🌐 Testing API Functionality")
        print("-" * 30)
        
        try:
            # Initialize API
            self.dashboard_api = initialize_dashboard_api()
            assert self.dashboard_api is not None, "Dashboard API should be initialized"
            print("✅ Dashboard API initialized successfully")
            
            # Test API configuration
            config = self.dashboard_api.config
            assert 'api' in config, "API configuration should be loaded"
            print("✅ API configuration loaded successfully")
            
            # Test database initialization
            assert os.path.exists('dashboard.db'), "API database should be created"
            print("✅ API database initialized successfully")
            
            # Test framework managers in API
            managers = self.dashboard_api.framework_managers
            assert isinstance(managers, dict), "Framework managers should be a dictionary"
            print(f"✅ {len(managers)} framework managers available in API")
            
            # Test current stats generation
            stats = self.dashboard_api._get_current_stats()
            assert isinstance(stats, dict), "Current stats should be a dictionary"
            assert 'timestamp' in stats, "Stats should have timestamp"
            print("✅ Current stats generated successfully")
            
            self.test_results.append(('API Functionality', 'PASS'))
            
        except Exception as e:
            print(f"❌ API functionality test failed: {e}")
            self.test_results.append(('API Functionality', 'FAIL', str(e)))
    
    def test_export_functionality(self):
        """Test export functionality"""
        print("\n📤 Testing Export Functionality")
        print("-" * 30)
        
        try:
            # Test reconnaissance data export
            if 'recon' in self.dashboard_api.framework_managers:
                recon_data = self.dashboard_api._export_recon_data()
                assert isinstance(recon_data, dict), "Recon data should be a dictionary"
                assert 'export_timestamp' in recon_data, "Export should have timestamp"
                print("✅ Reconnaissance data export successful")
            
            # Test AI data export
            if 'ai' in self.dashboard_api.framework_managers:
                ai_data = self.dashboard_api._export_ai_data()
                assert isinstance(ai_data, dict), "AI data should be a dictionary"
                assert 'export_timestamp' in ai_data, "Export should have timestamp"
                print("✅ AI analysis data export successful")
            
            # Test monitoring data export
            if 'monitoring' in self.dashboard_api.framework_managers:
                monitoring_data = self.dashboard_api._export_monitoring_data()
                assert isinstance(monitoring_data, dict), "Monitoring data should be a dictionary"
                assert 'export_timestamp' in monitoring_data, "Export should have timestamp"
                print("✅ Monitoring data export successful")
            
            # Test submissions data export
            if 'submission' in self.dashboard_api.framework_managers:
                submissions_data = self.dashboard_api._export_submissions_data()
                assert isinstance(submissions_data, dict), "Submissions data should be a dictionary"
                assert 'export_timestamp' in submissions_data, "Export should have timestamp"
                print("✅ Submissions data export successful")
            
            # Test exploitation data export
            if 'exploitation' in self.dashboard_api.framework_managers:
                exploitation_data = self.dashboard_api._export_exploitation_data()
                assert isinstance(exploitation_data, dict), "Exploitation data should be a dictionary"
                assert 'export_timestamp' in exploitation_data, "Export should have timestamp"
                print("✅ Exploitation data export successful")
            
            self.test_results.append(('Export Functionality', 'PASS'))
            
        except Exception as e:
            print(f"❌ Export functionality test failed: {e}")
            self.test_results.append(('Export Functionality', 'FAIL', str(e)))
    
    def print_test_summary(self):
        """Print test summary"""
        print("\n" + "=" * 50)
        print("📋 Test Summary")
        print("=" * 50)
        
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
            print("🎉 All tests passed!")
        else:
            print(f"⚠️  {failed} test(s) failed. Please check the errors above.")
    
    def cleanup(self):
        """Clean up test files"""
        print("\n🧹 Cleaning up test files...")
        
        # Remove test database
        if os.path.exists('dashboard.db'):
            os.remove('dashboard.db')
            print("✅ Removed test database")
        
        # Remove test output directory
        output_dir = Path('dashboard_results')
        if output_dir.exists():
            import shutil
            shutil.rmtree(output_dir)
            print("✅ Removed test output directory")

def main():
    """Main test function"""
    print("🧪 Bug Bounty Framework Dashboard Test Suite")
    print("=" * 60)
    
    # Create tester instance
    tester = DashboardTester()
    
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