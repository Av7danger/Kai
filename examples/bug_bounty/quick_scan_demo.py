#!/usr/bin/env python3
"""
Quick Bug Bounty Scan Demo - Using Free Tools
Demonstrates how to perform reconnaissance without Burp Suite Pro
"""

import asyncio
import subprocess
import json
import time
import requests
from datetime import datetime

def run_command(cmd, timeout=30):
    """Run a command safely with timeout"""
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            shell=True
        )
        return {
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Command timed out'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def demo_subfinder(target="example.com"):
    """Demo subfinder for subdomain discovery"""
    print(f"\n🔍 Running Subfinder on {target}...")
    print("=" * 50)
    
    cmd = f"subfinder -d {target} -silent -o subdomains.txt"
    result = run_command(cmd, timeout=60)
    
    if result['success']:
        try:
            with open('subdomains.txt', 'r') as f:
                subdomains = f.read().strip().split('\n')
                print(f"✅ Found {len(subdomains)} subdomains:")
                for i, subdomain in enumerate(subdomains[:10]):  # Show first 10
                    print(f"   {i+1}. {subdomain}")
                if len(subdomains) > 10:
                    print(f"   ... and {len(subdomains) - 10} more")
                return subdomains
        except FileNotFoundError:
            print("❌ No subdomains file created")
    else:
        print(f"❌ Subfinder failed: {result.get('error', 'Unknown error')}")
    
    return []

def demo_httpx(targets):
    """Demo httpx for HTTP probing"""
    if not targets:
        print("\n⚠️  No targets for httpx probe")
        return []
    
    print(f"\n🚀 Running Httpx probe on {len(targets)} targets...")
    print("=" * 50)
    
    # Write targets to file
    with open('targets.txt', 'w') as f:
        f.write('\n'.join(targets))
    
    cmd = "httpx -l targets.txt -silent -mc 200,201,202,204,301,302,307,308,401,403 -o live_hosts.txt"
    result = run_command(cmd, timeout=120)
    
    if result['success']:
        try:
            with open('live_hosts.txt', 'r') as f:
                live_hosts = f.read().strip().split('\n')
                print(f"✅ Found {len(live_hosts)} live hosts:")
                for i, host in enumerate(live_hosts[:5]):  # Show first 5
                    print(f"   {i+1}. {host}")
                if len(live_hosts) > 5:
                    print(f"   ... and {len(live_hosts) - 5} more")
                return live_hosts
        except FileNotFoundError:
            print("❌ No live hosts file created")
    else:
        print(f"❌ Httpx failed: {result.get('error', 'Unknown error')}")
    
    return []

def demo_nmap(target):
    """Demo nmap for port scanning"""
    print(f"\n🗺️  Running Nmap scan on {target}...")
    print("=" * 50)
    
    cmd = f"nmap -T4 -F {target}"  # Fast scan of top 100 ports
    result = run_command(cmd, timeout=60)
    
    if result['success']:
        print("✅ Nmap scan completed:")
        print(result['stdout'])
    else:
        print(f"❌ Nmap failed: {result.get('error', 'Unknown error')}")

def demo_ffuf(target):
    """Demo ffuf for directory fuzzing"""
    print(f"\n🔥 Running Ffuf directory fuzzing on {target}...")
    print("=" * 50)
    
    # Create a small wordlist for demo
    wordlist = ['admin', 'login', 'panel', 'api', 'test', 'backup', 'config', 'uploads']
    with open('demo_wordlist.txt', 'w') as f:
        f.write('\n'.join(wordlist))
    
    cmd = f"ffuf -u {target}/FUZZ -w demo_wordlist.txt -mc 200,201,202,204,301,302,307,308,401,403 -t 10 -s"
    result = run_command(cmd, timeout=30)
    
    if result['success']:
        print("✅ Ffuf scan completed:")
        if result['stdout']:
            print(result['stdout'])
        else:
            print("   No interesting directories found with demo wordlist")
    else:
        print(f"❌ Ffuf failed: {result.get('error', 'Unknown error')}")

def demo_zap_docker():
    """Demo OWASP ZAP via Docker"""
    print(f"\n🛡️  OWASP ZAP Docker Demo...")
    print("=" * 50)
    
    # Check if ZAP container is running
    cmd = "docker ps --filter name=zap --format table"
    result = run_command(cmd, timeout=10)
    
    if result['success'] and 'zap' in result['stdout']:
        print("✅ OWASP ZAP container is running")
        print("   You can access it at: http://localhost:8080")
        print("   API available at: http://localhost:8080/JSON/")
    else:
        print("⚠️  OWASP ZAP container not running")
        print("   Start with: docker run -p 8080:8080 -d owasp/zap2docker-weekly")
        print("   Or use our dashboard to manage ZAP scans")

def demo_dashboard_api():
    """Demo dashboard API functionality"""
    print(f"\n📊 Testing Dashboard API...")
    print("=" * 50)
    
    try:
        # Test health endpoint
        response = requests.get("http://127.0.0.1:8001/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print("✅ Dashboard is healthy:")
            print(f"   Status: {health_data['status']}")
            print(f"   Tools available: {health_data['tools_count']}")
        else:
            print(f"⚠️  Dashboard health check failed: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Dashboard not accessible: {e}")
        print("   Make sure it's running at http://127.0.0.1:8001")

def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                🔐 FREE BUG BOUNTY SCAN DEMO                  ║
    ║                 No Burp Suite Pro Required!                 ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    target_domain = "testphp.vulnweb.com"  # Safe demo target
    print(f"🎯 Target: {target_domain}")
    print("   (Using a safe demo target - testphp.vulnweb.com)")
    
    # Step 1: Subdomain Discovery
    subdomains = demo_subfinder(target_domain)
    
    # Step 2: HTTP Probing
    if subdomains:
        live_hosts = demo_httpx(subdomains[:5])  # Test first 5 subdomains
    else:
        live_hosts = [f"http://{target_domain}"]
    
    # Step 3: Port Scanning
    if live_hosts:
        target_for_nmap = live_hosts[0].replace('http://', '').replace('https://', '')
        demo_nmap(target_for_nmap)
    
    # Step 4: Directory Fuzzing
    if live_hosts:
        demo_ffuf(live_hosts[0])
    
    # Step 5: ZAP Demo
    demo_zap_docker()
    
    # Step 6: Dashboard API
    demo_dashboard_api()
    
    print(f"""
    🎉 Demo Complete!
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    ✅ You've seen how to use FREE tools instead of Burp Suite Pro:
    
    🔍 Reconnaissance: Subfinder → Httpx → Live targets
    🗺️  Port Scanning: Nmap for network mapping  
    🔥 Directory Fuzzing: Ffuf for hidden paths
    🛡️  Web App Security: OWASP ZAP (Docker-based)
    📊 Management: Web Dashboard with API
    
    🚀 Next Steps:
    • Install missing tools: ./install_free_tools.ps1
    • Run comprehensive scans via dashboard: http://127.0.0.1:8001
    • Use nuclei for vulnerability scanning (8000+ templates!)
    • Combine tools in automated workflows
    
    💡 Pro Tip: Chain tools together:
       subfinder -d target.com | httpx | nuclei -t cves/
    
    Happy Bug Hunting! 🐛💰
    """)

if __name__ == "__main__":
    main()
