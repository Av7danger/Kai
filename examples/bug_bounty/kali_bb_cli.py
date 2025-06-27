#!/usr/bin/env python3
"""
🐉 KALI LINUX OPTIMIZED BUG BOUNTY CLI
⚡ Ultimate command-line interface for Kali Linux penetration testing
🎯 Integrates with native Kali tools and workflows

Usage:
  ./kali_bb_cli.py scan -t target.com
  ./kali_bb_cli.py recon -l targets.txt
  ./kali_bb_cli.py exploit -i finding_id
  ./kali_bb_cli.py report -c campaign_id
"""

import argparse
import asyncio
import sys
import os
import json
import subprocess
import shlex
from pathlib import Path
from datetime import datetime
import logging
from typing import List, Dict, Any, Optional

# Import our core modules
try:
    from quick_start_config import GEMINI_API_KEY, HUNTER_PROFILE, SYSTEM_CONFIG
    from ultra_optimized_gemini_system import UltraOptimizedGeminiSystem
    from personal_bug_bounty_optimizer import PersonalBugBountyOptimizer
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're in the correct directory with all modules")
    sys.exit(1)

class KaliOptimizedCLI:
    """Kali Linux optimized command-line interface"""
    
    def __init__(self):
        self.setup_environment()
        self.setup_logging()
        self.gemini_system = None
        self.optimizer = PersonalBugBountyOptimizer(HUNTER_PROFILE)
        
    def setup_environment(self):
        """Setup Kali Linux specific environment"""
        # Set API key
        if GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here":
            os.environ['GEMINI_API_KEY'] = GEMINI_API_KEY
            
        # Kali-specific paths
        self.kali_tools = {
            'subfinder': '/usr/bin/subfinder',
            'nuclei': '/usr/bin/nuclei',
            'httpx': '/usr/bin/httpx',
            'nmap': '/usr/bin/nmap',
            'gobuster': '/usr/bin/gobuster',
            'dirsearch': '/usr/bin/dirsearch',
            'sqlmap': '/usr/bin/sqlmap',
            'nikto': '/usr/bin/nikto',
            'ffuf': '/usr/bin/ffuf',
            'amass': '/usr/bin/amass'
        }
        
        # Check available tools
        self.available_tools = {}
        for tool, path in self.kali_tools.items():
            if os.path.exists(path) or self.command_exists(tool):
                self.available_tools[tool] = path
                
        # Create working directories
        self.workspace = Path.home() / 'bug_bounty_workspace'
        self.workspace.mkdir(exist_ok=True)
        
        (self.workspace / 'targets').mkdir(exist_ok=True)
        (self.workspace / 'results').mkdir(exist_ok=True)
        (self.workspace / 'reports').mkdir(exist_ok=True)
        (self.workspace / 'logs').mkdir(exist_ok=True)
        
    def command_exists(self, command: str) -> bool:
        """Check if command exists in PATH"""
        return subprocess.run(['which', command], 
                            capture_output=True, text=True).returncode == 0
    
    def setup_logging(self):
        """Setup logging for CLI operations"""
        log_file = self.workspace / 'logs' / f'kali_bb_{datetime.now().strftime("%Y%m%d")}.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def print_banner(self):
        """Print Kali-style banner"""
        banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║     🐉 KALI LINUX BUG BOUNTY CLI - GEMINI POWERED                ║
    ║        Ultimate penetration testing automation                    ║
    ║           Optimized for Kali Linux workflows                     ║
    ╚═══════════════════════════════════════════════════════════════════╝
        """
        print(f"\033[92m{banner}\033[0m")  # Green color
        
    def print_status(self, message: str, status: str = "INFO"):
        """Print colored status messages"""
        colors = {
            "INFO": "\033[94m",    # Blue
            "SUCCESS": "\033[92m", # Green
            "WARNING": "\033[93m", # Yellow
            "ERROR": "\033[91m",   # Red
            "RESET": "\033[0m"
        }
        
        color = colors.get(status, colors["INFO"])
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] {status}: {message}{colors['RESET']}")
        
    def check_dependencies(self):
        """Check Kali tools and dependencies"""
        self.print_status("Checking Kali Linux dependencies...", "INFO")
        
        print(f"\n🛠️  Available Kali Tools:")
        for tool, path in self.available_tools.items():
            print(f"   ✅ {tool}: {path}")
            
        missing_tools = []
        essential_tools = ['subfinder', 'nuclei', 'httpx', 'nmap']
        
        for tool in essential_tools:
            if tool not in self.available_tools:
                missing_tools.append(tool)
                
        if missing_tools:
            self.print_status(f"Missing essential tools: {', '.join(missing_tools)}", "WARNING")
            print("\n📦 Install missing tools:")
            for tool in missing_tools:
                print(f"   sudo apt install {tool}")
        else:
            self.print_status("All essential tools available!", "SUCCESS")
            
        # Check Python dependencies
        try:
            import google.generativeai
            self.print_status("Gemini AI: Available", "SUCCESS")
        except ImportError:
            self.print_status("Gemini AI: pip install google-generativeai", "WARNING")
            
    async def run_kali_command(self, command: str, cwd: Path = None) -> Dict[str, Any]:
        """Run Kali tool command with proper output handling"""
        if cwd is None:
            cwd = self.workspace
            
        self.print_status(f"Executing: {command}", "INFO")
        
        try:
            # Split command properly for subprocess
            cmd_parts = shlex.split(command)
            
            # Run command
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            
            stdout, stderr = await process.communicate()
            
            result = {
                "command": command,
                "returncode": process.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "success": process.returncode == 0
            }
            
            if result["success"]:
                self.print_status(f"Command completed successfully", "SUCCESS")
            else:
                self.print_status(f"Command failed (exit code: {process.returncode})", "ERROR")
                if result["stderr"]:
                    print(f"Error: {result['stderr'][:200]}")
                    
            return result
            
        except Exception as e:
            self.print_status(f"Command execution error: {str(e)}", "ERROR")
            return {
                "command": command,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }
    
    async def recon_subdomain(self, domain: str) -> List[str]:
        """Advanced subdomain reconnaissance using multiple Kali tools"""
        self.print_status(f"Starting subdomain recon for {domain}", "INFO")
        
        output_file = self.workspace / 'results' / f'{domain}_subdomains.txt'
        all_subdomains = set()
        
        # Subfinder
        if 'subfinder' in self.available_tools:
            cmd = f"subfinder -d {domain} -o {output_file}"
            result = await self.run_kali_command(cmd)
            if result["success"] and result["stdout"]:
                all_subdomains.update(result["stdout"].strip().split('\n'))
        
        # Amass (if available)
        if 'amass' in self.available_tools:
            amass_file = self.workspace / 'results' / f'{domain}_amass.txt'
            cmd = f"amass enum -d {domain} -o {amass_file}"
            result = await self.run_kali_command(cmd)
            if result["success"] and amass_file.exists():
                with open(amass_file, 'r') as f:
                    all_subdomains.update(line.strip() for line in f if line.strip())
        
        # Save consolidated results
        subdomains = sorted(list(all_subdomains))
        with open(output_file, 'w') as f:
            f.write('\n'.join(subdomains))
            
        self.print_status(f"Found {len(subdomains)} subdomains for {domain}", "SUCCESS")
        return subdomains
    
    async def http_probe(self, targets: List[str]) -> List[str]:
        """HTTP probing with httpx"""
        self.print_status(f"HTTP probing {len(targets)} targets", "INFO")
        
        # Create target file
        target_file = self.workspace / 'targets' / 'current_targets.txt'
        with open(target_file, 'w') as f:
            f.write('\n'.join(targets))
        
        output_file = self.workspace / 'results' / 'live_hosts.txt'
        
        if 'httpx' in self.available_tools:
            cmd = f"httpx -l {target_file} -o {output_file} -status-code -title -tech-detect"
            result = await self.run_kali_command(cmd)
            
            if result["success"] and output_file.exists():
                with open(output_file, 'r') as f:
                    live_hosts = [line.strip() for line in f if line.strip()]
                    
                self.print_status(f"Found {len(live_hosts)} live hosts", "SUCCESS")
                return live_hosts
        
        return []
    
    async def vulnerability_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Comprehensive vulnerability scanning"""
        self.print_status(f"Starting vulnerability scan on {len(targets)} targets", "INFO")
        
        results = {
            "nuclei": [],
            "nikto": [],
            "nmap": []
        }
        
        # Create target file
        target_file = self.workspace / 'targets' / 'scan_targets.txt'
        with open(target_file, 'w') as f:
            f.write('\n'.join(targets))
        
        # Nuclei scan
        if 'nuclei' in self.available_tools:
            nuclei_output = self.workspace / 'results' / 'nuclei_results.json'
            cmd = f"nuclei -l {target_file} -o {nuclei_output} -json -stats"
            result = await self.run_kali_command(cmd)
            
            if result["success"] and nuclei_output.exists():
                try:
                    with open(nuclei_output, 'r') as f:
                        for line in f:
                            if line.strip():
                                results["nuclei"].append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        
        # Nikto scan (for web apps)
        if 'nikto' in self.available_tools and len(targets) <= 10:  # Limit for performance
            for target in targets[:5]:  # First 5 targets only
                nikto_output = self.workspace / 'results' / f'nikto_{target.replace("://", "_").replace("/", "_")}.txt'
                cmd = f"nikto -h {target} -output {nikto_output}"
                result = await self.run_kali_command(cmd)
                if result["success"]:
                    results["nikto"].append({"target": target, "output_file": str(nikto_output)})
        
        # Basic nmap scan
        if 'nmap' in self.available_tools:
            for target in targets[:3]:  # First 3 targets only
                # Extract host from URL
                host = target.replace("http://", "").replace("https://", "").split('/')[0]
                nmap_output = self.workspace / 'results' / f'nmap_{host}.xml'
                cmd = f"nmap -sV -sC -oX {nmap_output} {host}"
                result = await self.run_kali_command(cmd)
                if result["success"]:
                    results["nmap"].append({"target": host, "output_file": str(nmap_output)})
        
        # Summarize results
        total_findings = len(results["nuclei"]) + len(results["nikto"]) + len(results["nmap"])
        self.print_status(f"Vulnerability scan completed: {total_findings} findings", "SUCCESS")
        
        return results
    
    async def generate_report(self, campaign_data: Dict[str, Any]) -> str:
        """Generate professional penetration testing report"""
        report_file = self.workspace / 'reports' / f'pentest_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
        
        report_content = f"""# 🐉 Kali Linux Bug Bounty Report
## Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

### 🎯 Campaign Summary
- **Target**: {campaign_data.get('target', 'N/A')}
- **Scan Duration**: {campaign_data.get('duration', 'N/A')}
- **Tools Used**: {', '.join(self.available_tools.keys())}

### 📊 Findings Summary
- **Subdomains Found**: {campaign_data.get('subdomains_count', 0)}
- **Live Hosts**: {campaign_data.get('live_hosts_count', 0)}
- **Vulnerabilities**: {campaign_data.get('vulnerabilities_count', 0)}

### 🔍 Detailed Findings
"""
        
        # Add vulnerability details
        if 'vulnerabilities' in campaign_data:
            for vuln in campaign_data['vulnerabilities'].get('nuclei', []):
                report_content += f"""
#### {vuln.get('info', {}).get('name', 'Unknown Vulnerability')}
- **Severity**: {vuln.get('info', {}).get('severity', 'Unknown')}
- **URL**: {vuln.get('matched-at', 'N/A')}
- **Template**: {vuln.get('template-id', 'N/A')}
"""
        
        report_content += f"""
### 🛠️ Tools and Commands Used
- Subfinder: `subfinder -d target.com`
- Httpx: `httpx -l targets.txt -status-code -title`
- Nuclei: `nuclei -l targets.txt -stats`
- Nikto: `nikto -h target.com`
- Nmap: `nmap -sV -sC target.com`

### 📈 Recommendations
1. Address high/critical severity vulnerabilities immediately
2. Implement proper input validation
3. Keep software and frameworks updated
4. Regular security assessments

---
*Generated by Kali Linux Bug Bounty CLI - Gemini Powered*
"""
        
        with open(report_file, 'w') as f:
            f.write(report_content)
            
        self.print_status(f"Report generated: {report_file}", "SUCCESS")
        return str(report_file)
    
    async def full_recon_scan(self, target: str) -> Dict[str, Any]:
        """Complete reconnaissance and vulnerability scan"""
        start_time = datetime.now()
        self.print_status(f"Starting full recon scan for {target}", "INFO")
        
        campaign_data = {
            "target": target,
            "start_time": start_time,
            "subdomains": [],
            "live_hosts": [],
            "vulnerabilities": {}
        }
        
        try:
            # Step 1: Subdomain enumeration
            subdomains = await self.recon_subdomain(target)
            campaign_data["subdomains"] = subdomains
            campaign_data["subdomains_count"] = len(subdomains)
            
            # Step 2: HTTP probing
            if subdomains:
                live_hosts = await self.http_probe(subdomains[:50])  # Limit for performance
                campaign_data["live_hosts"] = live_hosts
                campaign_data["live_hosts_count"] = len(live_hosts)
                
                # Step 3: Vulnerability scanning
                if live_hosts:
                    vulnerabilities = await self.vulnerability_scan(live_hosts[:20])
                    campaign_data["vulnerabilities"] = vulnerabilities
                    campaign_data["vulnerabilities_count"] = (
                        len(vulnerabilities.get("nuclei", [])) +
                        len(vulnerabilities.get("nikto", [])) +
                        len(vulnerabilities.get("nmap", []))
                    )
            
            # Calculate duration
            end_time = datetime.now()
            campaign_data["duration"] = str(end_time - start_time)
            campaign_data["end_time"] = end_time
            
            # Generate report
            report_file = await self.generate_report(campaign_data)
            campaign_data["report_file"] = report_file
            
            self.print_status(f"Full scan completed in {campaign_data['duration']}", "SUCCESS")
            
            return campaign_data
            
        except Exception as e:
            self.print_status(f"Scan error: {str(e)}", "ERROR")
            return campaign_data
    
    def display_results_summary(self, campaign_data: Dict[str, Any]):
        """Display formatted results summary"""
        print(f"\n🎯 SCAN RESULTS SUMMARY")
        print(f"{'='*50}")
        print(f"Target: {campaign_data.get('target', 'N/A')}")
        print(f"Duration: {campaign_data.get('duration', 'N/A')}")
        print(f"Subdomains: {campaign_data.get('subdomains_count', 0)}")
        print(f"Live Hosts: {campaign_data.get('live_hosts_count', 0)}")
        print(f"Vulnerabilities: {campaign_data.get('vulnerabilities_count', 0)}")
        
        if 'report_file' in campaign_data:
            print(f"Report: {campaign_data['report_file']}")
            
        print(f"Workspace: {self.workspace}")
        print(f"{'='*50}")

def create_parser():
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        description="🐉 Kali Linux Bug Bounty CLI - Gemini Powered",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./kali_bb_cli.py recon example.com              # Full recon scan
  ./kali_bb_cli.py subs example.com               # Subdomain enumeration only
  ./kali_bb_cli.py scan -l targets.txt            # Vulnerability scan from file
  ./kali_bb_cli.py check                          # Check dependencies
  ./kali_bb_cli.py workspace                      # Show workspace info
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Recon command
    recon_parser = subparsers.add_parser('recon', help='Full reconnaissance scan')
    recon_parser.add_argument('target', help='Target domain (e.g., example.com)')
    
    # Subdomains command
    subs_parser = subparsers.add_parser('subs', help='Subdomain enumeration only')
    subs_parser.add_argument('target', help='Target domain')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Vulnerability scan')
    scan_group = scan_parser.add_mutually_exclusive_group(required=True)
    scan_group.add_argument('-t', '--target', help='Single target')
    scan_group.add_argument('-l', '--list', help='Target list file')
    
    # Check command
    subparsers.add_parser('check', help='Check dependencies and tools')
    
    # Workspace command
    subparsers.add_parser('workspace', help='Show workspace information')
    
    return parser

async def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize CLI
    cli = KaliOptimizedCLI()
    cli.print_banner()
    
    try:
        if args.command == 'check':
            cli.check_dependencies()
            
        elif args.command == 'workspace':
            print(f"\n🏠 Workspace Information:")
            print(f"Location: {cli.workspace}")
            print(f"Targets: {cli.workspace / 'targets'}")
            print(f"Results: {cli.workspace / 'results'}")
            print(f"Reports: {cli.workspace / 'reports'}")
            print(f"Logs: {cli.workspace / 'logs'}")
            
        elif args.command == 'recon':
            campaign_data = await cli.full_recon_scan(args.target)
            cli.display_results_summary(campaign_data)
            
        elif args.command == 'subs':
            subdomains = await cli.recon_subdomain(args.target)
            print(f"\n🔍 Found {len(subdomains)} subdomains:")
            for subdomain in subdomains[:20]:  # Show first 20
                print(f"  • {subdomain}")
            if len(subdomains) > 20:
                print(f"  ... and {len(subdomains) - 20} more")
                
        elif args.command == 'scan':
            targets = []
            if args.target:
                targets = [args.target]
            elif args.list:
                with open(args.list, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
                    
            if targets:
                results = await cli.vulnerability_scan(targets)
                print(f"\n🔍 Vulnerability Scan Results:")
                print(f"  Nuclei findings: {len(results.get('nuclei', []))}")
                print(f"  Nikto scans: {len(results.get('nikto', []))}")
                print(f"  Nmap scans: {len(results.get('nmap', []))}")
            else:
                print("❌ No targets specified")
                
    except KeyboardInterrupt:
        cli.print_status("Operation cancelled by user", "WARNING")
    except Exception as e:
        cli.print_status(f"Unexpected error: {str(e)}", "ERROR")

if __name__ == "__main__":
    # Make script executable
    import stat
    script_path = Path(__file__)
    script_path.chmod(script_path.stat().st_mode | stat.S_IEXEC)
    
    # Run async main
    asyncio.run(main())
