#!/usr/bin/env python3
"""
Complete Bug Bounty Demonstration - Free Tools Only
Shows the full power of our free alternative to Burp Suite Pro
"""

import asyncio
import subprocess
import json
import time
import os
from datetime import datetime
from pathlib import Path

class FreeBugBountyDemo:
    def __init__(self):
        self.target = "testphp.vulnweb.com"  # Safe demo target
        self.results_dir = Path("demo_results")
        self.results_dir.mkdir(exist_ok=True)
        
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
        
    def run_command(self, cmd, output_file=None, timeout=120):
        """Run command and capture output"""
        try:
            self.log(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
            
            if output_file:
                with open(self.results_dir / output_file, 'w') as f:
                    result = subprocess.run(
                        cmd, stdout=f, stderr=subprocess.PIPE, 
                        text=True, timeout=timeout, shell=isinstance(cmd, str)
                    )
            else:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, 
                    timeout=timeout, shell=isinstance(cmd, str)
                )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout if not output_file else f"Output saved to {output_file}",
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Command timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def phase1_subdomain_discovery(self):
        """Phase 1: Subdomain Discovery with Subfinder"""
        print("\n" + "="*60)
        print("🔍 PHASE 1: SUBDOMAIN DISCOVERY")
        print("="*60)
        
        self.log(f"Discovering subdomains for {self.target}")
        
        # Subfinder
        result = self.run_command(
            ['subfinder', '-d', self.target, '-silent'], 
            'subdomains.txt'
        )
        
        if result['success']:
            try:
                with open(self.results_dir / 'subdomains.txt', 'r') as f:
                    subdomains = f.read().strip().split('\n')
                    subdomains = [s for s in subdomains if s]  # Remove empty lines
                
                self.log(f"✅ Found {len(subdomains)} subdomains")
                for i, subdomain in enumerate(subdomains[:5]):
                    print(f"   {i+1}. {subdomain}")
                if len(subdomains) > 5:
                    print(f"   ... and {len(subdomains) - 5} more")
                
                return subdomains
            except FileNotFoundError:
                self.log("❌ No subdomains found")
                return [self.target]
        else:
            self.log(f"❌ Subfinder failed: {result.get('error', 'Unknown error')}")
            return [self.target]

    def phase2_http_probing(self, targets):
        """Phase 2: HTTP Probing with Httpx"""
        print("\n" + "="*60)
        print("🚀 PHASE 2: HTTP PROBING")
        print("="*60)
        
        # Create targets file
        targets_file = self.results_dir / 'targets.txt'
        with open(targets_file, 'w') as f:
            f.write('\n'.join(targets))
        
        self.log(f"Probing {len(targets)} targets for HTTP services")
        
        result = self.run_command([
            'httpx', '-l', str(targets_file), '-silent', 
            '-mc', '200,201,202,204,301,302,307,308,401,403',
            '-title', '-tech-detect', '-status-code'
        ], 'live_hosts.txt')
        
        if result['success']:
            try:
                with open(self.results_dir / 'live_hosts.txt', 'r') as f:
                    live_hosts = f.read().strip().split('\n')
                    live_hosts = [h for h in live_hosts if h and h.startswith('http')]
                
                self.log(f"✅ Found {len(live_hosts)} live web services")
                for i, host in enumerate(live_hosts[:3]):
                    print(f"   {i+1}. {host}")
                if len(live_hosts) > 3:
                    print(f"   ... and {len(live_hosts) - 3} more")
                
                return live_hosts
            except FileNotFoundError:
                self.log("❌ No live hosts found")
                return [f"http://{self.target}"]
        else:
            self.log(f"❌ Httpx failed: {result.get('error', 'Unknown error')}")
            return [f"http://{self.target}"]

    def phase3_vulnerability_scanning(self, targets):
        """Phase 3: Vulnerability Scanning with Nuclei"""
        print("\n" + "="*60)
        print("⚡ PHASE 3: VULNERABILITY SCANNING")
        print("="*60)
        
        if not targets:
            self.log("No targets for vulnerability scanning")
            return
        
        # Create targets file for nuclei
        nuclei_targets = self.results_dir / 'nuclei_targets.txt'
        with open(nuclei_targets, 'w') as f:
            f.write('\n'.join(targets[:3]))  # Test first 3 targets
        
        self.log(f"Running Nuclei vulnerability scan on {min(3, len(targets))} targets")
        self.log("Using CVE and exposure detection templates...")
        
        # Run nuclei with basic templates
        result = self.run_command([
            'nuclei', '-l', str(nuclei_targets), 
            '-t', 'exposures/', '-t', 'misconfiguration/',
            '-silent', '-j'
        ], 'nuclei_results.json')
        
        if result['success']:
            try:
                # Try to parse results
                with open(self.results_dir / 'nuclei_results.json', 'r') as f:
                    content = f.read().strip()
                    if content:
                        # Count lines (each line is a finding in JSON format)
                        findings = content.split('\n')
                        findings = [f for f in findings if f.strip()]
                        self.log(f"✅ Nuclei scan completed - {len(findings)} findings")
                        
                        # Show first few findings
                        for i, finding in enumerate(findings[:3]):
                            try:
                                data = json.loads(finding)
                                print(f"   {i+1}. {data.get('info', {}).get('name', 'Unknown')} on {data.get('host', 'Unknown')}")
                            except json.JSONDecodeError:
                                print(f"   {i+1}. {finding[:50]}...")
                    else:
                        self.log("✅ Nuclei scan completed - No vulnerabilities found")
            except FileNotFoundError:
                self.log("❌ No nuclei results file found")
        else:
            self.log(f"❌ Nuclei failed: {result.get('error', 'Unknown error')}")

    def phase4_port_scanning(self, target):
        """Phase 4: Port Scanning with Nmap"""
        print("\n" + "="*60)
        print("🗺️ PHASE 4: PORT SCANNING")
        print("="*60)
        
        # Extract hostname from URL if needed
        if target.startswith('http'):
            target = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        self.log(f"Running Nmap scan on {target}")
        
        result = self.run_command([
            'nmap', '-T4', '-F', '--open', target
        ])
        
        if result['success']:
            self.log("✅ Port scan completed")
            # Save and display results
            with open(self.results_dir / 'nmap_results.txt', 'w') as f:
                f.write(result['stdout'])
            
            # Show key findings
            lines = result['stdout'].split('\n')
            for line in lines:
                if '/tcp' in line and 'open' in line:
                    print(f"   📡 {line.strip()}")
        else:
            self.log(f"❌ Nmap failed: {result.get('error', 'Unknown error')}")

    def phase5_directory_fuzzing(self, target):
        """Phase 5: Directory Fuzzing with Ffuf"""
        print("\n" + "="*60)
        print("🔥 PHASE 5: DIRECTORY FUZZING")
        print("="*60)
        
        # Create small wordlist for demo
        demo_wordlist = self.results_dir / 'demo_wordlist.txt'
        common_dirs = [
            'admin', 'login', 'panel', 'api', 'test', 'backup', 
            'config', 'uploads', 'files', 'data', 'db', 'sql',
            'phpmyadmin', 'wp-admin', 'dashboard', 'control'
        ]
        
        with open(demo_wordlist, 'w') as f:
            f.write('\n'.join(common_dirs))
        
        self.log(f"Running directory fuzzing on {target}")
        
        result = self.run_command([
            'ffuf', '-u', f"{target}/FUZZ", '-w', str(demo_wordlist),
            '-mc', '200,201,202,204,301,302,307,308,401,403',
            '-t', '10', '-s'
        ])
        
        if result['success']:
            self.log("✅ Directory fuzzing completed")
            if result['stdout']:
                # Save results
                with open(self.results_dir / 'ffuf_results.txt', 'w') as f:
                    f.write(result['stdout'])
                
                # Show findings
                lines = result['stdout'].split('\n')
                findings = [line for line in lines if 'Status:' in line or 'Size:' in line]
                for finding in findings[:5]:
                    print(f"   🎯 {finding.strip()}")
            else:
                self.log("No interesting directories found with demo wordlist")
        else:
            self.log(f"❌ Ffuf failed: {result.get('error', 'Unknown error')}")

    def show_summary(self):
        """Show scan summary and next steps"""
        print("\n" + "="*60)
        print("📊 SCAN SUMMARY & RESULTS")
        print("="*60)
        
        # List all result files
        result_files = list(self.results_dir.glob('*'))
        
        print(f"\n📁 Results saved in: {self.results_dir}")
        for file in result_files:
            size = file.stat().st_size
            print(f"   📄 {file.name} ({size} bytes)")
        
        print(f"""
🎯 What We Accomplished WITHOUT Burp Suite Pro:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Subdomain Discovery (Subfinder)
✅ HTTP Service Detection (Httpx) 
✅ Vulnerability Scanning (Nuclei)
✅ Port Scanning (Nmap)
✅ Directory Fuzzing (Ffuf)

🚀 Next Steps:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Start OWASP ZAP for web app testing:
   docker run -p 8080:8080 softwaresecurityproject/zap-stable

2. Use the web dashboard for automation:
   http://127.0.0.1:8001

3. Chain tools for comprehensive scanning:
   subfinder -d target.com | httpx | nuclei -t cves/

4. Analyze results and plan manual testing

💡 Pro Tip: Our free stack is MORE powerful than Burp Suite Pro
   because it leverages the entire security community!
        """)

    async def run_complete_demo(self):
        """Run the complete demonstration"""
        print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║            🔐 COMPLETE BUG BOUNTY DEMONSTRATION              ║
    ║                NO BURP SUITE PRO NEEDED!                    ║
    ╚══════════════════════════════════════════════════════════════╝
        """)
        
        self.log(f"Starting comprehensive scan of {self.target}")
        self.log(f"Results will be saved to: {self.results_dir}")
        
        start_time = time.time()
        
        # Phase 1: Subdomain Discovery
        subdomains = self.phase1_subdomain_discovery()
        
        # Phase 2: HTTP Probing
        live_hosts = self.phase2_http_probing(subdomains)
        
        # Phase 3: Vulnerability Scanning
        self.phase3_vulnerability_scanning(live_hosts)
        
        # Phase 4: Port Scanning
        if live_hosts:
            self.phase4_port_scanning(live_hosts[0])
        
        # Phase 5: Directory Fuzzing
        if live_hosts:
            self.phase5_directory_fuzzing(live_hosts[0])
        
        # Summary
        total_time = time.time() - start_time
        self.log(f"Complete scan finished in {total_time:.2f} seconds")
        
        self.show_summary()

def main():
    demo = FreeBugBountyDemo()
    asyncio.run(demo.run_complete_demo())

if __name__ == "__main__":
    main()
