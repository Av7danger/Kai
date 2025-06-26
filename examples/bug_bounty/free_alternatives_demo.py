#!/usr/bin/env python3
"""
Free Bug Bounty Tools Demo - No Burp Suite Pro Required!
Demonstrates our powerful free alternative tools
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

def banner():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                  🔐 FREE BUG BOUNTY FRAMEWORK                ║
    ║                    No Burp Suite Pro Needed!                ║
    ╚══════════════════════════════════════════════════════════════╝
    
    🎯 Available FREE Tools:
    """)

def check_tool_availability():
    """Check which free tools are available"""
    tools = {
        'subfinder': {'cmd': ['subfinder', '-version'], 'desc': 'Subdomain Discovery'},
        'httpx': {'cmd': ['httpx', '-version'], 'desc': 'Fast HTTP Probe'},
        'nuclei': {'cmd': ['nuclei', '-version'], 'desc': 'Vulnerability Scanner'},
        'nmap': {'cmd': ['nmap', '--version'], 'desc': 'Network Mapper'},
        'amass': {'cmd': ['amass', 'version'], 'desc': 'OWASP Amass - DNS Enumeration'},
        'ffuf': {'cmd': ['ffuf', '-V'], 'desc': 'Fast Web Fuzzer'},
        'assetfinder': {'cmd': ['assetfinder', '--help'], 'desc': 'Asset Discovery'},
        'docker': {'cmd': ['docker', '--version'], 'desc': 'OWASP ZAP Container'},
    }
    
    available_tools = []
    
    for tool, config in tools.items():
        try:
            result = subprocess.run(
                config['cmd'], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0 or 'version' in result.stdout.lower() or 'usage' in result.stderr.lower():
                available_tools.append(f"    ✅ {tool}: {config['desc']}")
            else:
                available_tools.append(f"    ❌ {tool}: {config['desc']} (Not found)")
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            available_tools.append(f"    ❌ {tool}: {config['desc']} (Not installed)")
    
    return available_tools

def show_zap_alternative():
    print("""
    🔥 OWASP ZAP - FREE Burp Suite Alternative:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    ✅ Web Application Security Scanner
    ✅ Active & Passive Scanning
    ✅ API Security Testing
    ✅ Authentication Testing
    ✅ Automated Reports
    ✅ Proxy Functionality
    ✅ Spider/Crawler
    ✅ Fuzzing Capabilities
    
    Start with: docker run -p 8080:8080 owasp/zap2docker-weekly
    """)

def show_nuclei_power():
    print("""
    ⚡ Nuclei - Community-Powered Vulnerability Scanner:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    ✅ 8000+ Community Templates
    ✅ CVE Detection
    ✅ Misconfigurations
    ✅ Exposed Panels
    ✅ Subdomain Takeovers
    ✅ Custom Template Creation
    ✅ Fast & Efficient
    
    Example: nuclei -u https://example.com -t cves/
    """)

def show_reconnaissance_suite():
    print("""
    🎯 Reconnaissance Suite:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    📡 Subfinder: Fast subdomain discovery
    🔍 Amass: OWASP DNS enumeration
    🚀 Httpx: HTTP probe & technology detection
    🎪 Assetfinder: Asset discovery
    
    Combo: subfinder -d target.com | httpx -mc 200 | nuclei
    """)

def show_web_tools():
    print("""
    🌐 Web Application Tools:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    🔥 Ffuf: Fast directory/parameter fuzzing
    🗺️  Dirsearch: Web path scanner
    🔐 Nikto: Web vulnerability scanner
    🛡️  Testssl.sh: SSL/TLS security scanner
    
    Example: ffuf -u https://target.com/FUZZ -w wordlist.txt
    """)

def show_dashboard_info():
    print("""
    📊 Web Dashboard Available:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    🌐 URL: http://127.0.0.1:8001
    📋 Features:
       • Real-time scan management
       • Tool integration
       • Results visualization
       • API endpoints
       • Progress tracking
    
    🔗 API Docs: http://127.0.0.1:8001/api/docs
    """)

def show_installation_help():
    print("""
    📦 Quick Installation:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    Run our installer script:
    PowerShell: .\\install_free_tools.ps1
    
    Or install individually:
    • Go tools: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    • Docker: Download from docker.com
    • Python tools: pip install requests beautifulsoup4
    """)

def main():
    banner()
    
    print("Checking tool availability...")
    tools = check_tool_availability()
    for tool in tools:
        print(tool)
    
    show_zap_alternative()
    show_nuclei_power()
    show_reconnaissance_suite()
    show_web_tools()
    show_dashboard_info()
    show_installation_help()
    
    print("""
    🎉 Summary:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    You have a COMPLETE bug bounty framework with FREE tools that are
    just as powerful as commercial alternatives like Burp Suite Pro!
    
    • Web Application Security: OWASP ZAP
    • Vulnerability Scanning: Nuclei (8000+ templates)
    • Reconnaissance: Subfinder + Amass + Httpx
    • Web Fuzzing: Ffuf + Dirsearch
    • Network Scanning: Nmap + Masscan
    • SSL Testing: Testssl.sh + SSLyze
    
    🚀 Start the dashboard: http://127.0.0.1:8001
    📚 Read docs: ./ENHANCED_FRAMEWORK_SUMMARY.md
    
    Happy Bug Hunting! 🐛💰
    """)

if __name__ == "__main__":
    main()
