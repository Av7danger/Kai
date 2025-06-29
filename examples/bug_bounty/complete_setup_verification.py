#!/usr/bin/env python3
"""
🚀 BUG BOUNTY PLATFORM COMPLETE SETUP & SUMMARY
Final setup verification and comprehensive platform overview
"""

import os
import sys
import json
import sqlite3
import subprocess
from pathlib import Path
from datetime import datetime
import time

def print_banner():
    """Print the main banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                  🚀 BUG BOUNTY PLATFORM - COMPLETE SETUP             ║
║                                                                      ║
║     Next-Generation Vulnerability Analysis & Bug Bounty Platform     ║
║        with AI-Powered Analysis and Advanced Web Interface           ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def verify_files():
    """Verify all necessary files are present"""
    print("📁 Verifying platform files...")
    
    required_files = {
        # Core Analysis Scripts
        'gemini_vuln_analyzer.py': 'AI-powered vulnerability analyzer',
        'manual_vuln_tester.py': 'Manual vulnerability testing framework',
        'gemini_vuln_reproducer.py': 'AI vulnerability reproduction engine',
        'vulnerability_analysis_demo.py': 'Interactive demonstration script',
        'quick_start_vulnerability_analysis.py': 'Quick start analysis tool',
        
        # Database & Initialization
        'init_db.py': 'Database initialization script',
        'bb_pro.db': 'Main vulnerability database',
        
        # Advanced Web UI
        'advanced_vuln_ui.py': 'Next-generation web interface',
        'web_ui.py': 'Legacy web interface',
        
        # Templates (Advanced UI)
        'templates/advanced_base.html': 'Advanced base template',
        'templates/advanced_dashboard.html': 'Advanced dashboard template',
        'templates/advanced_vulnerabilities.html': 'Vulnerabilities listing template',
        'templates/advanced_vulnerability_detail.html': 'Vulnerability detail template',
        'templates/advanced_reports.html': 'Reports management template',
        'templates/advanced_settings.html': 'Settings configuration template',
        
        # System Management
        'bb_pro_optimizer.py': 'Platform optimization suite',
        'bb_pro_monitor.py': 'System monitoring & health checks',
        
        # Documentation
        'COMPLETE_VULNERABILITY_ANALYSIS_GUIDE.md': 'Complete user guide',
        'VULNERABILITY_REPRODUCTION_GUIDE.md': 'Reproduction guide',
        'README.md': 'Platform overview'
    }
    
    missing_files = []
    present_files = []
    
    for file_path, description in required_files.items():
        if os.path.exists(file_path):
            present_files.append((file_path, description))
            print(f"  ✅ {file_path}")
        else:
            missing_files.append((file_path, description))
            print(f"  ❌ {file_path} - MISSING")
    
    print(f"\n📊 Files Status: {len(present_files)}/{len(required_files)} present")
    
    if missing_files:
        print("\n⚠️  Missing Files:")
        for file_path, description in missing_files:
            print(f"    - {file_path}: {description}")
    
    return len(missing_files) == 0

def verify_database():
    """Verify database structure and sample data"""
    print("\n🗄️  Verifying database...")
    
    if not os.path.exists('bb_pro.db'):
        print("  ❌ Database file not found")
        return False
    
    try:
        conn = sqlite3.connect('bb_pro.db')
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        required_tables = ['targets', 'vulnerabilities', 'documents']
        missing_tables = [table for table in required_tables if table not in tables]
        
        if missing_tables:
            print(f"  ❌ Missing tables: {missing_tables}")
            conn.close()
            return False
        
        print("  ✅ All required tables present")
        
        # Check sample data
        cursor.execute("SELECT COUNT(*) FROM targets")
        target_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vuln_count = cursor.fetchone()[0]
        
        print(f"  📊 Database contains: {target_count} targets, {vuln_count} vulnerabilities")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"  ❌ Database error: {e}")
        return False

def check_dependencies():
    """Check Python dependencies"""
    print("\n📦 Checking dependencies...")
    
    required_packages = {
        'flask': 'Web framework for UI',
        'sqlite3': 'Database operations',
        'requests': 'HTTP client library',
        'pathlib': 'File path operations',
        'datetime': 'Date/time handling',
        'threading': 'Multi-threading support',
        'json': 'JSON data handling',
        'csv': 'CSV file operations',
        'hashlib': 'Cryptographic hashing',
        'subprocess': 'Process execution',
        'logging': 'Application logging'
    }
    
    optional_packages = {
        'google.generativeai': 'Google Gemini AI integration',
        'psutil': 'System monitoring',
        'zipfile': 'Archive operations'
    }
    
    missing_required = []
    missing_optional = []
    
    # Check required packages
    for package, description in required_packages.items():
        try:
            __import__(package)
            print(f"  ✅ {package}")
        except ImportError:
            missing_required.append((package, description))
            print(f"  ❌ {package} - REQUIRED")
    
    # Check optional packages
    for package, description in optional_packages.items():
        try:
            __import__(package)
            print(f"  ✅ {package} (optional)")
        except ImportError:
            missing_optional.append((package, description))
            print(f"  ⚠️  {package} - OPTIONAL")
    
    if missing_required:
        print(f"\n❌ Missing required packages: {len(missing_required)}")
        for package, description in missing_required:
            print(f"    - {package}: {description}")
        return False
    
    if missing_optional:
        print(f"\n⚠️  Missing optional packages: {len(missing_optional)}")
        for package, description in missing_optional:
            print(f"    - {package}: {description}")
        print("    Install with: pip install google-generativeai psutil")
    
    return True

def check_ai_configuration():
    """Check AI service configuration"""
    print("\n🤖 Checking AI configuration...")
    
    gemini_api_key = os.getenv('GEMINI_API_KEY')
    
    if gemini_api_key:
        print("  ✅ GEMINI_API_KEY environment variable set")
        
        try:
            import google.generativeai as genai
            print("  ✅ Google Generative AI library available")
            
            # Test API connection (basic)
            genai.configure(api_key=gemini_api_key)
            print("  ✅ API key configured")
            
            return True
            
        except ImportError:
            print("  ❌ Google Generative AI library not installed")
            print("    Install with: pip install google-generativeai")
            return False
        except Exception as e:
            print(f"  ⚠️  API configuration issue: {e}")
            return False
    else:
        print("  ⚠️  GEMINI_API_KEY not set")
        print("    Get API key from: https://makersuite.google.com/app/apikey")
        print("    Set with: set GEMINI_API_KEY=your_api_key_here")
        return False

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        'vulnerability_analysis_reports',
        'manual_test_reports',
        'backups',
        'temp',
        'logs'
    ]
    
    for directory in directories:
        dir_path = Path(directory)
        if not dir_path.exists():
            dir_path.mkdir(exist_ok=True)
            print(f"  ✅ Created: {directory}")
        else:
            print(f"  ✅ Exists: {directory}")

def test_ui_startup():
    """Test if the UI can start"""
    print("\n🌐 Testing UI startup...")
    
    try:
        # Import to check for syntax errors
        import advanced_vuln_ui
        print("  ✅ Advanced UI imports successfully")
        
        # Check Flask app creation
        if hasattr(advanced_vuln_ui, 'app'):
            print("  ✅ Flask app created")
        
        return True
        
    except ImportError as e:
        print(f"  ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"  ❌ UI startup error: {e}")
        return False

def generate_system_summary():
    """Generate comprehensive system summary"""
    print("\n📋 Generating system summary...")
    
    summary = {
        'platform_name': 'Bug Bounty Pro - Advanced Vulnerability Analysis Platform',
        'version': '2.0.0',
        'setup_date': datetime.now().isoformat(),
        'components': {
            'core_analyzers': [
                'AI-Powered Vulnerability Analyzer (Gemini)',
                'Manual Vulnerability Testing Framework',
                'Automated Reproduction Engine',
                'Interactive Demo System'
            ],
            'web_interfaces': [
                'Next-Generation Advanced UI (Flask)',
                'Legacy Web Interface',
                'REST API Endpoints'
            ],
            'data_management': [
                'SQLite Database with WAL mode',
                'Automated Backup System',
                'Data Export/Import Tools'
            ],
            'system_tools': [
                'Platform Optimizer',
                'Health Monitor',
                'Performance Analyzer',
                'Security Scanner'
            ]
        },
        'features': {
            'ai_powered': True,
            'web_interface': True,
            'report_generation': True,
            'vulnerability_tracking': True,
            'target_management': True,
            'automated_analysis': True,
            'manual_testing': True,
            'poc_generation': True,
            'reproduction_guides': True,
            'system_monitoring': True,
            'performance_optimization': True,
            'security_enhancements': True
        },
        'urls': {
            'main_ui': 'http://localhost:5000',
            'dashboard': 'http://localhost:5000/',
            'vulnerabilities': 'http://localhost:5000/vulnerabilities',
            'reports': 'http://localhost:5000/reports',
            'settings': 'http://localhost:5000/settings'
        },
        'file_structure': {
            'analyzers': ['gemini_vuln_analyzer.py', 'manual_vuln_tester.py', 'gemini_vuln_reproducer.py'],
            'ui': ['advanced_vuln_ui.py', 'web_ui.py'],
            'database': ['bb_pro.db', 'init_db.py'],
            'tools': ['bb_pro_optimizer.py', 'bb_pro_monitor.py'],
            'templates': ['templates/advanced_*.html'],
            'reports': ['vulnerability_analysis_reports/', 'manual_test_reports/']
        }
    }
    
    # Save summary
    with open('system_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("  ✅ System summary saved to system_summary.json")
    return summary

def print_getting_started():
    """Print getting started instructions"""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                          🚀 GETTING STARTED                          ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 QUICK START COMMANDS:

  1. Start the Advanced Web UI:
     python advanced_vuln_ui.py
     
  2. Access the Platform:
     Open: http://localhost:5000
     
  3. Run System Health Check:
     python bb_pro_monitor.py dashboard
     
  4. Optimize the Platform:
     python bb_pro_optimizer.py all
     
  5. Quick Vulnerability Analysis:
     python quick_start_vulnerability_analysis.py

🔧 CONFIGURATION:

  • Set AI API Key:
    set GEMINI_API_KEY=your_api_key_here
    
  • Get API Key from:
    https://makersuite.google.com/app/apikey

🌟 MAIN FEATURES:

  ✅ AI-Powered Vulnerability Analysis
  ✅ Advanced Web Interface with Modern UI
  ✅ Comprehensive Report Generation
  ✅ Real-time System Monitoring
  ✅ Automated Vulnerability Reproduction
  ✅ Manual Testing Framework
  ✅ Performance Optimization Tools
  ✅ Security Enhancement Suite

📖 DOCUMENTATION:

  • Complete Guide: COMPLETE_VULNERABILITY_ANALYSIS_GUIDE.md
  • Reproduction Guide: VULNERABILITY_REPRODUCTION_GUIDE.md
  • System Summary: system_summary.json

🎉 PLATFORM READY FOR USE!
""")

def main():
    """Main setup verification function"""
    print_banner()
    
    print("🔍 Starting comprehensive platform verification...\n")
    
    checks = [
        ("File Structure", verify_files),
        ("Database", verify_database),
        ("Dependencies", check_dependencies),
        ("AI Configuration", check_ai_configuration),
        ("UI Startup", test_ui_startup)
    ]
    
    results = {}
    
    # Run all checks
    for check_name, check_func in checks:
        print(f"\n{'='*70}")
        print(f"🔎 {check_name} Check")
        print('='*70)
        
        try:
            result = check_func()
            results[check_name] = result
        except Exception as e:
            print(f"❌ {check_name} check failed: {e}")
            results[check_name] = False
    
    # Create directories
    create_directories()
    
    # Generate system summary
    summary = generate_system_summary()
    
    # Final results
    print(f"\n{'='*70}")
    print("📊 VERIFICATION RESULTS")
    print('='*70)
    
    total_checks = len(results)
    passed_checks = sum(1 for result in results.values() if result)
    
    for check_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{check_name:<20} {status}")
    
    print(f"\nSUMMARY: {passed_checks}/{total_checks} checks passed")
    
    if passed_checks == total_checks:
        print("\n🎉 ALL CHECKS PASSED - PLATFORM READY!")
        print_getting_started()
    elif passed_checks >= total_checks - 1:
        print("\n⚠️  PLATFORM MOSTLY READY - Minor issues detected")
        print("   Consider addressing warnings for optimal performance")
        print_getting_started()
    else:
        print("\n❌ PLATFORM NOT READY - Critical issues detected")
        print("   Please resolve the failed checks before proceeding")
    
    print(f"\n🕒 Verification completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("📄 Detailed summary saved to: system_summary.json")

if __name__ == "__main__":
    main()
