#!/usr/bin/env python3
"""
Test script for Kali Bug Hunter Framework
Simple tests to verify functionality
"""

import os
import sys
import time
import json
import subprocess
from pathlib import Path

def test_imports():
    """Test if all required modules can be imported"""
    print("🔍 Testing imports...")
    
    try:
        import yaml
        print("✅ PyYAML imported successfully")
    except ImportError:
        print("❌ PyYAML not found")
        return False
    
    try:
        from flask import Flask
        print("✅ Flask imported successfully")
    except ImportError:
        print("❌ Flask not found")
        return False
    
    try:
        from flask_login import LoginManager
        print("✅ Flask-Login imported successfully")
    except ImportError:
        print("⚠️ Flask-Login not found (will be installed by setup script)")
        # Don't fail the test for this, as it will be installed by setup
    
    return True

def test_config():
    """Test configuration file"""
    print("\n🔧 Testing configuration...")
    
    if not os.path.exists('kali_config.yml'):
        print("❌ kali_config.yml not found")
        return False
    
    try:
        import yaml
        with open('kali_config.yml', 'r') as f:
            config = yaml.safe_load(f)
        
        required_keys = ['kali', 'scanning', 'tools', 'dashboard', 'security']
        for key in required_keys:
            if key not in config:
                print(f"❌ Missing config key: {key}")
                return False
        
        print("✅ Configuration file is valid")
        return True
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False

def test_kali_tools():
    """Test Kali Linux tools availability"""
    print("\n🛠️ Testing Kali tools...")
    
    # Core tools
    core_tools = ['nmap', 'nuclei', 'ffuf', 'subfinder', 'amass', 'httpx']
    
    # New reconnaissance tools
    recon_tools = ['masscan', 'theharvester', 'dnsrecon', 'whatweb', 'wafw00f', 'gobuster', 'dirb', 'assetfinder']
    
    # New vulnerability scanning tools
    vuln_tools = ['nikto', 'wpscan', 'joomscan', 'sqlmap', 'xsser', 'arachni', 'dalfox']
    
    # New exploitation tools
    exploit_tools = ['metasploit-framework', 'hydra', 'medusa', 'patator', 'crackmapexec', 'responder']
    
    # New analysis tools
    analysis_tools = ['hashcat', 'john', 'binwalk', 'strings', 'exiftool', 'steghide', 'foremost']
    
    all_tools = core_tools + recon_tools + vuln_tools + exploit_tools + analysis_tools
    available_tools = []
    
    print("🔍 Testing core tools...")
    for tool in core_tools:
        if test_tool_availability(tool):
            available_tools.append(tool)
    
    print("🕵️ Testing reconnaissance tools...")
    for tool in recon_tools:
        if test_tool_availability(tool):
            available_tools.append(tool)
    
    print("🛡️ Testing vulnerability scanning tools...")
    for tool in vuln_tools:
        if test_tool_availability(tool):
            available_tools.append(tool)
    
    print("⚔️ Testing exploitation tools...")
    for tool in exploit_tools:
        if test_tool_availability(tool):
            available_tools.append(tool)
    
    print("🔬 Testing analysis tools...")
    for tool in analysis_tools:
        if test_tool_availability(tool):
            available_tools.append(tool)
    
    print(f"\n📊 Tools available: {len(available_tools)}/{len(all_tools)}")
    print(f"✅ Core tools: {len([t for t in core_tools if t in available_tools])}/{len(core_tools)}")
    print(f"✅ Recon tools: {len([t for t in recon_tools if t in available_tools])}/{len(recon_tools)}")
    print(f"✅ Vuln tools: {len([t for t in vuln_tools if t in available_tools])}/{len(vuln_tools)}")
    print(f"✅ Exploit tools: {len([t for t in exploit_tools if t in available_tools])}/{len(exploit_tools)}")
    print(f"✅ Analysis tools: {len([t for t in analysis_tools if t in available_tools])}/{len(analysis_tools)}")
    
    return len(available_tools) > 0

def test_tool_availability(tool):
    """Test if a specific tool is available"""
    try:
        result = subprocess.run([tool, '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"✅ {tool} is available")
            return True
        else:
            print(f"❌ {tool} not working properly")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print(f"❌ {tool} not found")
        return False

def test_database():
    """Test database functionality"""
    print("\n🗄️ Testing database...")
    
    try:
        import sqlite3
        
        # Test database creation
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        
        # Test tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_targets (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                status TEXT DEFAULT 'pending'
            )
        ''')
        
        # Test insert
        cursor.execute('''
            INSERT INTO test_targets (id, domain, status)
            VALUES (?, ?, ?)
        ''', ('test_1', 'example.com', 'pending'))
        
        # Test select
        cursor.execute('SELECT * FROM test_targets WHERE domain = ?', ('example.com',))
        result = cursor.fetchone()
        
        if result and result[1] == 'example.com':
            print("✅ Database operations working")
            conn.close()
            return True
        else:
            print("❌ Database query failed")
            conn.close()
            return False
            
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

def test_web_templates():
    """Test web templates"""
    print("\n🌐 Testing web templates...")
    
    templates_dir = Path('templates')
    if not templates_dir.exists():
        print("❌ Templates directory not found")
        return False
    
    required_templates = ['kali_dashboard.html', 'kali_login.html']
    
    for template in required_templates:
        template_path = templates_dir / template
        if template_path.exists():
            print(f"✅ {template} found")
        else:
            print(f"❌ {template} not found")
            return False
    
    return True

def test_directory_structure():
    """Test directory structure"""
    print("\n📁 Testing directory structure...")
    
    required_dirs = ['kali_results', 'templates', 'logs']
    required_files = ['kali_bug_hunter.py', 'kali_config.yml', 'kali_setup.sh']
    
    # Check directories
    for dir_name in required_dirs:
        if os.path.exists(dir_name):
            print(f"✅ Directory {dir_name} exists")
        else:
            print(f"❌ Directory {dir_name} missing")
            return False
    
    # Check files
    for file_name in required_files:
        if os.path.exists(file_name):
            print(f"✅ File {file_name} exists")
        else:
            print(f"❌ File {file_name} missing")
            return False
    
    return True

def test_application_startup():
    """Test if the application can start (without running it)"""
    print("\n🚀 Testing application startup...")
    
    try:
        # Import the main application
        sys.path.insert(0, os.getcwd())
        
        # Test if we can import the main module
        import kali_bug_hunter
        print("✅ Main application module imported successfully")
        
        # Test if we can create a Flask app
        from flask import Flask
        app = Flask(__name__)
        print("✅ Flask app created successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Application startup error: {e}")
        return False

def run_all_tests():
    """Run all tests"""
    print("🐛 Kali Bug Hunter Framework Test Suite")
    print("=" * 50)
    
    tests = [
        ("Imports", test_imports),
        ("Configuration", test_config),
        ("Kali Tools", test_kali_tools),
        ("Database", test_database),
        ("Web Templates", test_web_templates),
        ("Directory Structure", test_directory_structure),
        ("Application Startup", test_application_startup)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} test failed")
        except Exception as e:
            print(f"❌ {test_name} test error: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Kali Bug Hunter is ready to use.")
        print("\n📋 Next Steps:")
        print("1. Run: ./kali_setup.sh")
        print("2. Start: ./start.sh")
        print("3. Access: http://localhost:5000")
        return True
    else:
        print("⚠️ Some tests failed. Please check the errors above.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1) 