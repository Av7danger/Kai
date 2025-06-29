#!/usr/bin/env python3
"""
Test Reconnaissance Tools
Demonstrates the new reconnaissance capabilities
"""

import asyncio
import json
import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from simple_main import (
    light_recon_scan, deep_recon_scan, 
    vulnerability_scan_light, vulnerability_scan_deep
)

async def test_light_recon():
    """Test light reconnaissance scan"""
    print("🔍 Testing Light Reconnaissance Scan")
    print("=" * 50)
    
    target = "httpbin.org"  # Safe test target
    
    try:
        results = await light_recon_scan(target)
        
        if "error" in results:
            print(f"❌ Error: {results['error']}")
            return
        
        print(f"✅ Light recon scan completed for {target}")
        print(f"📊 Scan Type: {results.get('scan_type', 'N/A')}")
        print(f"⏰ Timestamp: {results.get('timestamp', 'N/A')}")
        
        # Open Ports
        open_ports = results.get('open_ports', {})
        if open_ports:
            print(f"\n🔓 Open Ports ({len(open_ports)}):")
            for port, service in open_ports.items():
                print(f"   • Port {port}: {service}")
        else:
            print("\n🔒 No open ports found")
        
        # Subdomains
        subdomains = results.get('subdomains', [])
        if subdomains:
            print(f"\n🌐 Subdomains ({len(subdomains)}):")
            for subdomain in subdomains[:10]:  # Show first 10
                print(f"   • {subdomain}")
            if len(subdomains) > 10:
                print(f"   ... and {len(subdomains) - 10} more")
        else:
            print("\n🌐 No subdomains found")
        
        # Technologies
        technologies = results.get('technologies', [])
        if technologies:
            print(f"\n🛠️ Technologies ({len(technologies)}):")
            for tech in technologies:
                print(f"   • {tech}")
        else:
            print("\n🛠️ No technologies detected")
        
        # Security Headers
        headers = results.get('headers', {})
        if headers:
            print(f"\n🛡️ Security Headers:")
            for header, value in headers.items():
                status = "✅" if value != "Missing" else "❌"
                print(f"   {status} {header}: {value}")
        
        print("\n" + "=" * 50)
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

async def test_deep_recon():
    """Test deep reconnaissance scan"""
    print("🔍 Testing Deep Reconnaissance Scan")
    print("=" * 50)
    
    target = "httpbin.org"  # Safe test target
    
    try:
        results = await deep_recon_scan(target)
        
        if "error" in results:
            print(f"❌ Error: {results['error']}")
            return
        
        print(f"✅ Deep recon scan completed for {target}")
        print(f"📊 Scan Type: {results.get('scan_type', 'N/A')}")
        print(f"⏰ Timestamp: {results.get('timestamp', 'N/A')}")
        
        # Open Ports (comprehensive)
        open_ports = results.get('open_ports', {})
        if open_ports:
            print(f"\n🔓 Open Ports ({len(open_ports)}):")
            for port, service in open_ports.items():
                print(f"   • Port {port}: {service}")
        else:
            print("\n🔒 No open ports found")
        
        # WAF Detection
        waf_info = results.get('waf_detection', {})
        if waf_info:
            print(f"\n🛡️ WAF Detection:")
            if waf_info.get('detected'):
                print(f"   ✅ WAF Detected: {waf_info.get('type', 'Unknown')}")
                print(f"   📊 Confidence: {waf_info.get('confidence', 0)}%")
            else:
                print("   ❌ No WAF detected")
        
        # SSL Info
        ssl_info = results.get('ssl_info', {})
        if ssl_info:
            print(f"\n🔐 SSL Information:")
            if 'version' in ssl_info:
                print(f"   • Version: {ssl_info['version']}")
            if 'cipher' in ssl_info:
                print(f"   • Cipher: {ssl_info['cipher'][0]}")
        
        # Hidden Files
        hidden_files = results.get('hidden_files', [])
        if hidden_files:
            print(f"\n📁 Hidden Files ({len(hidden_files)}):")
            for file in hidden_files[:5]:  # Show first 5
                print(f"   • {file}")
            if len(hidden_files) > 5:
                print(f"   ... and {len(hidden_files) - 5} more")
        else:
            print("\n📁 No hidden files found")
        
        # API Endpoints
        api_endpoints = results.get('api_endpoints', [])
        if api_endpoints:
            print(f"\n🔌 API Endpoints ({len(api_endpoints)}):")
            for endpoint in api_endpoints:
                print(f"   • {endpoint}")
        else:
            print("\n🔌 No API endpoints found")
        
        # Admin Panels
        admin_panels = results.get('admin_panels', [])
        if admin_panels:
            print(f"\n⚙️ Admin Panels ({len(admin_panels)}):")
            for panel in admin_panels:
                print(f"   • {panel}")
        else:
            print("\n⚙️ No admin panels found")
        
        print("\n" + "=" * 50)
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

async def test_light_vuln_scan():
    """Test light vulnerability scan"""
    print("🔍 Testing Light Vulnerability Scan")
    print("=" * 50)
    
    target = "httpbin.org"  # Safe test target
    
    try:
        results = await vulnerability_scan_light(target)
        
        if "error" in results:
            print(f"❌ Error: {results['error']}")
            return
        
        print(f"✅ Light vulnerability scan completed for {target}")
        print(f"📊 Scan Type: {results.get('scan_type', 'N/A')}")
        print(f"⏰ Timestamp: {results.get('timestamp', 'N/A')}")
        
        # Web Vulnerabilities
        web_vulns = results.get('web_vulnerabilities', [])
        if web_vulns:
            print(f"\n🌐 Web Vulnerabilities ({len(web_vulns)}):")
            for vuln in web_vulns:
                print(f"   • {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
                print(f"     Description: {vuln.get('description', 'N/A')}")
                if 'url' in vuln:
                    print(f"     URL: {vuln['url']}")
                print()
        else:
            print("\n🌐 No web vulnerabilities found")
        
        # Network Vulnerabilities
        network_vulns = results.get('network_vulnerabilities', [])
        if network_vulns:
            print(f"\n🌍 Network Vulnerabilities ({len(network_vulns)}):")
            for vuln in network_vulns:
                print(f"   • {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
                print(f"     Description: {vuln.get('description', 'N/A')}")
                if 'port' in vuln:
                    print(f"     Port: {vuln['port']}")
                print()
        else:
            print("\n🌍 No network vulnerabilities found")
        
        # Cloud Vulnerabilities
        cloud_vulns = results.get('cloud_vulnerabilities', [])
        if cloud_vulns:
            print(f"\n☁️ Cloud Vulnerabilities ({len(cloud_vulns)}):")
            for vuln in cloud_vulns:
                print(f"   • {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
                print(f"     Description: {vuln.get('description', 'N/A')}")
                if 'url' in vuln:
                    print(f"     URL: {vuln['url']}")
                print()
        else:
            print("\n☁️ No cloud vulnerabilities found")
        
        # Misconfigurations
        misconfigs = results.get('misconfigurations', [])
        if misconfigs:
            print(f"\n⚙️ Misconfigurations ({len(misconfigs)}):")
            for misconfig in misconfigs:
                print(f"   • {misconfig.get('type', 'Unknown')} - {misconfig.get('severity', 'Unknown')}")
                print(f"     Description: {misconfig.get('description', 'N/A')}")
                if 'url' in misconfig:
                    print(f"     URL: {misconfig['url']}")
                print()
        else:
            print("\n⚙️ No misconfigurations found")
        
        print("\n" + "=" * 50)
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

async def test_deep_vuln_scan():
    """Test deep vulnerability scan"""
    print("🔍 Testing Deep Vulnerability Scan")
    print("=" * 50)
    
    target = "httpbin.org"  # Safe test target
    
    try:
        results = await vulnerability_scan_deep(target)
        
        if "error" in results:
            print(f"❌ Error: {results['error']}")
            return
        
        print(f"✅ Deep vulnerability scan completed for {target}")
        print(f"📊 Scan Type: {results.get('scan_type', 'N/A')}")
        print(f"⏰ Timestamp: {results.get('timestamp', 'N/A')}")
        
        # Web Vulnerabilities (Deep)
        web_vulns = results.get('web_vulnerabilities', [])
        if web_vulns:
            print(f"\n🌐 Web Vulnerabilities ({len(web_vulns)}):")
            for vuln in web_vulns:
                print(f"   • {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
                print(f"     Description: {vuln.get('description', 'N/A')}")
                if 'url' in vuln:
                    print(f"     URL: {vuln['url']}")
                print()
        else:
            print("\n🌐 No web vulnerabilities found")
        
        # Advanced Findings
        advanced_findings = results.get('advanced_findings', [])
        if advanced_findings:
            print(f"\n🔬 Advanced Findings ({len(advanced_findings)}):")
            for finding in advanced_findings:
                print(f"   • {finding.get('type', 'Unknown')} - {finding.get('severity', 'Unknown')}")
                print(f"     Description: {finding.get('description', 'N/A')}")
                print()
        else:
            print("\n🔬 No advanced findings")
        
        print("\n" + "=" * 50)
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

async def main():
    """Run all reconnaissance tests"""
    print("🚀 Kai Bug Hunter - Reconnaissance Tools Test")
    print("=" * 60)
    print("Testing the new reconnaissance capabilities...")
    print()
    
    # Test Light Reconnaissance
    await test_light_recon()
    
    # Test Deep Reconnaissance
    await test_deep_recon()
    
    # Test Light Vulnerability Scan
    await test_light_vuln_scan()
    
    # Test Deep Vulnerability Scan
    await test_deep_vuln_scan()
    
    print("🎉 All reconnaissance tests completed!")
    print("=" * 60)
    print("📋 Summary:")
    print("✅ Light Reconnaissance - Quick exposure discovery")
    print("✅ Deep Reconnaissance - In-depth attack surface mapping")
    print("✅ Light Vulnerability Scan - Quick vulnerability detection")
    print("✅ Deep Vulnerability Scan - Comprehensive vulnerability analysis")
    print()
    print("💡 These tools are now available in the Kai dashboard!")
    print("🌐 Access the dashboard at: http://localhost:8000")

if __name__ == "__main__":
    asyncio.run(main()) 