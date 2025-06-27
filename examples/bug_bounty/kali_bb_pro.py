#!/usr/bin/env python3
"""
🐉 KALI LINUX PRO BUG BOUNTY CLI - GEMINI POWERED
⚡ Professional-grade command-line interface for serious bug bounty hunters
🎯 Integrates with native Kali tools and Gemini AI for intelligent automation
💰 Optimized for maximum profit and efficiency

Usage Examples:
  ./kali_bb_pro.py quick-hunt target.com                    # Quick automated hunt
  ./kali_bb_pro.py deep-recon -t target.com -p high        # Deep reconnaissance
  ./kali_bb_pro.py exploit-chain -i finding_id             # AI-guided exploitation
  ./kali_bb_pro.py profit-report --monthly                 # Earnings analysis
  ./kali_bb_pro.py ai-assistant "analyze this payload"     # Interactive AI help
"""

import argparse
import asyncio
import sys
import os
import json
import subprocess
import shlex
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
import logging
from typing import List, Dict, Any, Optional, Tuple
import signal
import time
import threading
from concurrent.futures import ThreadPoolExecutor

# Import our core modules
try:
    from quick_start_config import GEMINI_API_KEY, HUNTER_PROFILE, SYSTEM_CONFIG
    from ultra_optimized_gemini_system import UltraOrchestrator
    from personal_bug_bounty_optimizer import PersonalBugBountyOptimizer
    import google.generativeai as genai
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Run: pip install google-generativeai aiohttp aiofiles psutil")
    sys.exit(1)

class KaliProCLI:
    """Professional Kali Linux CLI for bug bounty hunting"""
    
    def __init__(self):
        self.setup_environment()
        self.setup_database()
        self.setup_logging()
        self.setup_ai_system()
        self.running = True
        
        # Performance tracking
        self.start_time = time.time()
        self.commands_executed = 0
        self.findings_discovered = 0
        self.estimated_earnings = 0.0
        
    def setup_environment(self):
        """Setup Kali Linux professional environment"""
        # Set API key
        if GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here":
            os.environ['GEMINI_API_KEY'] = GEMINI_API_KEY
            genai.configure(api_key=GEMINI_API_KEY)
        else:
            print("❌ Please set your Gemini API key in quick_start_config.py")
            sys.exit(1)
            
        # Professional Kali tools suite
        self.kali_tools = {
            # Subdomain Discovery
            'subfinder': {'path': '/usr/bin/subfinder', 'category': 'recon'},
            'amass': {'path': '/usr/bin/amass', 'category': 'recon'},
            'assetfinder': {'path': '/usr/bin/assetfinder', 'category': 'recon'},
            'findomain': {'path': '/usr/bin/findomain', 'category': 'recon'},
            
            # HTTP Discovery
            'httpx': {'path': '/usr/bin/httpx', 'category': 'discovery'},
            'httprobe': {'path': '/usr/bin/httprobe', 'category': 'discovery'},
            
            # Vulnerability Scanning
            'nuclei': {'path': '/usr/bin/nuclei', 'category': 'vuln_scan'},
            'nmap': {'path': '/usr/bin/nmap', 'category': 'port_scan'},
            'nikto': {'path': '/usr/bin/nikto', 'category': 'web_scan'},
            
            # Directory/File Discovery
            'gobuster': {'path': '/usr/bin/gobuster', 'category': 'discovery'},
            'dirsearch': {'path': '/usr/bin/dirsearch', 'category': 'discovery'},
            'ffuf': {'path': '/usr/bin/ffuf', 'category': 'fuzzing'},
            'feroxbuster': {'path': '/usr/bin/feroxbuster', 'category': 'discovery'},
            
            # Exploitation
            'sqlmap': {'path': '/usr/bin/sqlmap', 'category': 'exploit'},
            'commix': {'path': '/usr/bin/commix', 'category': 'exploit'},
            'xsshunter': {'path': '/usr/bin/xsshunter', 'category': 'exploit'},
            
            # Analysis
            'gau': {'path': '/usr/bin/gau', 'category': 'analysis'},
            'waybackurls': {'path': '/usr/bin/waybackurls', 'category': 'analysis'},
            'gospider': {'path': '/usr/bin/gospider', 'category': 'crawling'},
            'katana': {'path': '/usr/bin/katana', 'category': 'crawling'},
            
            # Network
            'masscan': {'path': '/usr/bin/masscan', 'category': 'port_scan'},
            'zmap': {'path': '/usr/bin/zmap', 'category': 'discovery'}
        }
        
        # Check available tools
        self.available_tools = {}
        for tool, info in self.kali_tools.items():
            if os.path.exists(info['path']) or self.command_exists(tool):
                self.available_tools[tool] = info
                
        # Create professional workspace
        self.workspace = Path.home() / 'bb_pro_workspace'
        self.workspace.mkdir(exist_ok=True)
        
        # Create organized directories
        subdirs = [
            'targets', 'results', 'reports', 'logs', 'exploits', 
            'payloads', 'screenshots', 'evidence', 'wordlists',
            'scripts', 'campaigns', 'intelligence'
        ]
        for subdir in subdirs:
            (self.workspace / subdir).mkdir(exist_ok=True)
            
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def setup_database(self):
        """Setup SQLite database for professional tracking"""
        db_path = self.workspace / 'bb_pro.db'
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        
        # Create tables
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                target TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT,
                findings_count INTEGER DEFAULT 0,
                estimated_payout REAL DEFAULT 0.0,
                actual_payout REAL DEFAULT 0.0,
                notes TEXT
            );
            
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                campaign_id INTEGER,
                target TEXT,
                vulnerability_type TEXT,
                severity TEXT,
                confidence REAL,
                description TEXT,
                proof_of_concept TEXT,
                estimated_bounty REAL,
                actual_bounty REAL,
                status TEXT,
                discovered_at TIMESTAMP,
                reported_at TIMESTAMP,
                paid_at TIMESTAMP,
                FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
            );
            
            CREATE TABLE IF NOT EXISTS tool_executions (
                id INTEGER PRIMARY KEY,
                campaign_id INTEGER,
                tool_name TEXT,
                command TEXT,
                success BOOLEAN,
                duration REAL,
                output_size INTEGER,
                executed_at TIMESTAMP,
                FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
            );
            
            CREATE TABLE IF NOT EXISTS ai_interactions (
                id INTEGER PRIMARY KEY,
                campaign_id INTEGER,
                interaction_type TEXT,
                input_text TEXT,
                output_text TEXT,
                confidence REAL,
                tokens_used INTEGER,
                cost REAL,
                executed_at TIMESTAMP,
                FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
            );
        ''')
        self.db.commit()
        
    def setup_logging(self):
        """Setup professional logging"""
        log_file = self.workspace / 'logs' / f'bb_pro_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_ai_system(self):
        """Setup Gemini AI system"""
        try:
            self.gemini_system = UltraOrchestrator()
            self.optimizer = PersonalBugBountyOptimizer(HUNTER_PROFILE)
            self.ai_model = genai.GenerativeModel('gemini-1.5-flash')
            self.print_status("Gemini AI system initialized", "SUCCESS")
        except Exception as e:
            self.print_status(f"AI system initialization failed: {e}", "ERROR")
            self.ai_model = None
        
    def command_exists(self, command: str) -> bool:
        """Check if command exists in PATH"""
        try:
            # Windows-compatible version
            if os.name == 'nt':  # Windows
                result = subprocess.run(['where', command], 
                                      capture_output=True, text=True)
                return result.returncode == 0
            else:  # Unix-like systems
                result = subprocess.run(['which', command], 
                                      capture_output=True, text=True)
                return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.print_status(f"Received signal {signum}, shutting down gracefully...", "WARNING")
        self.running = False
        self.cleanup()
        sys.exit(0)
        
    def cleanup(self):
        """Cleanup resources"""
        if hasattr(self, 'db'):
            self.db.close()
        self.print_status("Cleanup completed", "INFO")
        
    def print_banner(self):
        """Print professional banner"""
        banner = f"""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║     🐉 KALI LINUX PRO BUG BOUNTY CLI - GEMINI POWERED           ║
    ║        Professional-grade penetration testing automation          ║
    ║         💰 Optimized for maximum profit and efficiency           ║
    ║                                                                   ║
    ║   Profile: {HUNTER_PROFILE['experience_level'].title():>10} | Target: ${HUNTER_PROFILE['monthly_target']:,}/month        ║
    ║   Session: {self.commands_executed:>3} commands | {self.findings_discovered:>2} findings | ${self.estimated_earnings:>6.0f} est.  ║
    ╚═══════════════════════════════════════════════════════════════════╝
        """
        print(f"\033[92m{banner}\033[0m")
        
    def print_status(self, message: str, status: str = "INFO", save_to_db: bool = False):
        """Print colored status messages"""
        colors = {
            "INFO": "\033[94m",      # Blue
            "SUCCESS": "\033[92m",   # Green
            "WARNING": "\033[93m",   # Yellow
            "ERROR": "\033[91m",     # Red
            "CRITICAL": "\033[95m",  # Magenta
            "FINDING": "\033[96m",   # Cyan
            "RESET": "\033[0m"
        }
        
        color = colors.get(status, colors["INFO"])
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"{color}[{timestamp}] {status}: {message}{colors['RESET']}"
        
        print(formatted_message)
        self.logger.info(f"{status}: {message}")
        
    def print_tool_status(self):
        """Print available tools by category"""
        categories = {}
        for tool, info in self.available_tools.items():
            category = info['category']
            if category not in categories:
                categories[category] = []
            categories[category].append(tool)
            
        print(f"\n🛠️  Available Kali Tools ({len(self.available_tools)} total):")
        for category, tools in categories.items():
            print(f"   📂 {category.title()}: {', '.join(tools)}")
            
        missing_essential = []
        essential_tools = ['subfinder', 'nuclei', 'httpx', 'nmap', 'gobuster']
        for tool in essential_tools:
            if tool not in self.available_tools:
                missing_essential.append(tool)
                
        if missing_essential:
            self.print_status(f"Missing essential tools: {', '.join(missing_essential)}", "WARNING")
        else:
            self.print_status("All essential tools available!", "SUCCESS")
            
    async def ai_analyze(self, context: str, question: str) -> str:
        """Get AI analysis from Gemini"""
        if not self.ai_model:
            return "AI system not available"
            
        try:
            prompt = f"""
            You are a professional bug bounty hunter AI assistant. Analyze the following context and answer the question.
            
            Context: {context}
            Question: {question}
            
            Provide a practical, actionable response focused on bug bounty hunting and profitable vulnerability discovery.
            """
            
            response = await asyncio.to_thread(
                self.ai_model.generate_content,
                prompt
            )
            
            return response.text
            
        except Exception as e:
            self.print_status(f"AI analysis failed: {e}", "ERROR")
            return f"AI analysis failed: {e}"
    
    async def run_kali_command(self, command: str, timeout: int = 300, 
                              cwd: Optional[Path] = None, capture_output: bool = True) -> Dict[str, Any]:
        """Run Kali tool command with professional handling"""
        if cwd is None:
            cwd = self.workspace
            
        self.print_status(f"Executing: {command}", "INFO")
        start_time = time.time()
        
        try:
            cmd_parts = shlex.split(command)
            
            if capture_output:
                process = await asyncio.create_subprocess_exec(
                    *cmd_parts,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), timeout=timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    raise TimeoutError(f"Command timed out after {timeout} seconds")
            else:
                process = await asyncio.create_subprocess_exec(
                    *cmd_parts,
                    cwd=cwd
                )
                await process.wait()
                stdout = stderr = b""
                
            duration = time.time() - start_time
            self.commands_executed += 1
            
            result = {
                "command": command,
                "returncode": process.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore') if stdout else "",
                "stderr": stderr.decode('utf-8', errors='ignore') if stderr else "",
                "success": process.returncode == 0,
                "duration": duration
            }
            
            # Log to database
            tool_name = cmd_parts[0] if cmd_parts else "unknown"
            self.db.execute('''
                INSERT INTO tool_executions 
                (tool_name, command, success, duration, output_size, executed_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (tool_name, command, result["success"], duration, 
                  len(result["stdout"]), datetime.now()))
            self.db.commit()
            
            if result["success"]:
                self.print_status(f"Command completed in {duration:.1f}s", "SUCCESS")
            else:
                self.print_status(f"Command failed (exit code: {process.returncode})", "ERROR")
                
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            self.print_status(f"Command execution error: {str(e)}", "ERROR")
            return {
                "command": command,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False,
                "duration": duration
            }
    
    async def quick_hunt(self, target: str) -> Dict[str, Any]:
        """Automated quick hunting session"""
        campaign_name = f"quick_hunt_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        campaign_id = self.create_campaign(campaign_name, target)
        
        self.print_status(f"Starting quick hunt on {target}", "INFO")
        
        hunt_results = {
            "target": target,
            "campaign_id": campaign_id,
            "subdomains": [],
            "live_hosts": [],
            "vulnerabilities": [],
            "high_value_findings": [],
            "estimated_earnings": 0.0
        }
        
        try:
            # Phase 1: Subdomain Discovery
            self.print_status("Phase 1: Subdomain Discovery", "INFO")
            hunt_results["subdomains"] = await self.discover_subdomains(target)
            
            # Phase 2: HTTP Probing
            self.print_status("Phase 2: HTTP Service Discovery", "INFO")
            if hunt_results["subdomains"]:
                hunt_results["live_hosts"] = await self.probe_http_services(hunt_results["subdomains"])
            
            # Phase 3: Quick Vulnerability Scan
            self.print_status("Phase 3: Vulnerability Scanning", "INFO")
            if hunt_results["live_hosts"]:
                hunt_results["vulnerabilities"] = await self.quick_vuln_scan(hunt_results["live_hosts"])
            
            # Phase 4: AI Analysis
            self.print_status("Phase 4: AI-Powered Analysis", "INFO")
            hunt_results["high_value_findings"] = await self.analyze_findings_with_ai(hunt_results)
            
            # Calculate estimated earnings
            hunt_results["estimated_earnings"] = self.calculate_estimated_earnings(hunt_results)
            self.estimated_earnings += hunt_results["estimated_earnings"]
            
            # Update campaign
            self.update_campaign(campaign_id, 
                               findings_count=len(hunt_results["vulnerabilities"]),
                               estimated_payout=hunt_results["estimated_earnings"])
            
            self.print_hunt_summary(hunt_results)
            
        except Exception as e:
            self.print_status(f"Quick hunt failed: {e}", "ERROR")
            
        return hunt_results
    
    async def discover_subdomains(self, domain: str) -> List[str]:
        """Advanced subdomain discovery using multiple tools"""
        all_subdomains = set()
        
        # Subfinder
        if 'subfinder' in self.available_tools:
            result = await self.run_kali_command(f"subfinder -d {domain} -silent")
            if result["success"]:
                all_subdomains.update(line.strip() for line in result["stdout"].split('\n') if line.strip())
        
        # Amass
        if 'amass' in self.available_tools:
            result = await self.run_kali_command(f"amass enum -d {domain} -silent")
            if result["success"]:
                all_subdomains.update(line.strip() for line in result["stdout"].split('\n') if line.strip())
        
        # Assetfinder
        if 'assetfinder' in self.available_tools:
            result = await self.run_kali_command(f"assetfinder --subs-only {domain}")
            if result["success"]:
                all_subdomains.update(line.strip() for line in result["stdout"].split('\n') if line.strip())
        
        subdomains = sorted(list(all_subdomains))
        self.print_status(f"Discovered {len(subdomains)} subdomains", "SUCCESS")
        
        # Save results
        subdomain_file = self.workspace / 'results' / f'{domain}_subdomains.txt'
        with open(subdomain_file, 'w') as f:
            f.write('\n'.join(subdomains))
            
        return subdomains
    
    async def probe_http_services(self, targets: List[str]) -> List[str]:
        """HTTP service discovery and probing"""
        if not targets:
            return []
            
        # Create target file
        target_file = self.workspace / 'targets' / 'probe_targets.txt'
        with open(target_file, 'w') as f:
            f.write('\n'.join(targets))
        
        live_hosts = []
        
        if 'httpx' in self.available_tools:
            output_file = self.workspace / 'results' / 'live_hosts.txt'
            cmd = f"httpx -l {target_file} -o {output_file} -silent -status-code -title -tech-detect -follow-redirects"
            result = await self.run_kali_command(cmd)
            
            if result["success"] and output_file.exists():
                with open(output_file, 'r') as f:
                    live_hosts = [line.strip() for line in f if line.strip()]
        
        self.print_status(f"Found {len(live_hosts)} live HTTP services", "SUCCESS")
        return live_hosts
    
    async def quick_vuln_scan(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Quick vulnerability scanning with Nuclei"""
        if not targets or 'nuclei' not in self.available_tools:
            return []
            
        # Create target file
        target_file = self.workspace / 'targets' / 'vuln_targets.txt'
        with open(target_file, 'w') as f:
            f.write('\n'.join(targets))
        
        vulnerabilities = []
        output_file = self.workspace / 'results' / 'nuclei_findings.json'
        
        # Run Nuclei with high-severity templates
        cmd = f"nuclei -l {target_file} -o {output_file} -json -severity high,critical,medium -silent"
        result = await self.run_kali_command(cmd, timeout=600)
        
        if result["success"] and output_file.exists():
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            vuln_data = json.loads(line)
                            vulnerabilities.append(vuln_data)
                            self.findings_discovered += 1
            except json.JSONDecodeError:
                pass
        
        self.print_status(f"Found {len(vulnerabilities)} potential vulnerabilities", "FINDING")
        return vulnerabilities
    
    async def analyze_findings_with_ai(self, hunt_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI-powered analysis of findings"""
        if not self.ai_model or not hunt_results["vulnerabilities"]:
            return []
            
        high_value_findings = []
        
        for vuln in hunt_results["vulnerabilities"]:
            context = f"Vulnerability: {vuln.get('info', {}).get('name', 'Unknown')}\n"
            context += f"Severity: {vuln.get('info', {}).get('severity', 'Unknown')}\n"
            context += f"Target: {vuln.get('host', 'Unknown')}\n"
            context += f"Description: {vuln.get('info', {}).get('description', 'No description')}\n"
            
            question = "Analyze this vulnerability for bug bounty potential. What's the estimated bounty value and exploitation complexity?"
            
            analysis = await self.ai_analyze(context, question)
            
            # Parse AI response for bounty estimation
            estimated_bounty = self.extract_bounty_estimate(analysis)
            
            if estimated_bounty > 100:  # High-value threshold
                high_value_findings.append({
                    "vulnerability": vuln,
                    "ai_analysis": analysis,
                    "estimated_bounty": estimated_bounty,
                    "priority": "high" if estimated_bounty > 1000 else "medium"
                })
        
        return high_value_findings
    
    def extract_bounty_estimate(self, ai_text: str) -> float:
        """Extract bounty estimate from AI analysis"""
        import re
        
        # Look for dollar amounts in the text
        patterns = [
            r'\$(\d+(?:,\d{3})*(?:\.\d{2})?)',
            r'(\d+(?:,\d{3})*)\s*dollars?',
            r'bounty.*?(\d+)',
            r'worth.*?(\d+)',
            r'estimate.*?(\d+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, ai_text.lower())
            if matches:
                try:
                    amount = float(matches[0].replace(',', ''))
                    return amount
                except ValueError:
                    continue
        
        # Default estimation based on keywords
        if 'critical' in ai_text.lower():
            return 2500
        elif 'high' in ai_text.lower():
            return 1000
        elif 'medium' in ai_text.lower():
            return 500
        else:
            return 100
    
    def calculate_estimated_earnings(self, hunt_results: Dict[str, Any]) -> float:
        """Calculate estimated earnings from hunt results"""
        total_estimate = 0.0
        
        for finding in hunt_results["high_value_findings"]:
            total_estimate += finding["estimated_bounty"]
        
        # Add bonus for volume
        if len(hunt_results["vulnerabilities"]) > 10:
            total_estimate *= 1.2  # 20% bonus for comprehensive findings
            
        return total_estimate
    
    def create_campaign(self, name: str, target: str) -> int:
        """Create new campaign in database"""
        cursor = self.db.execute('''
            INSERT INTO campaigns (name, target, start_time, status)
            VALUES (?, ?, ?, ?)
        ''', (name, target, datetime.now(), 'active'))
        self.db.commit()
        return cursor.lastrowid or 0
    
    def update_campaign(self, campaign_id: int, **kwargs):
        """Update campaign with results"""
        set_clauses = []
        values = []
        
        for key, value in kwargs.items():
            set_clauses.append(f"{key} = ?")
            values.append(value)
        
        if set_clauses:
            values.append(campaign_id)
            query = f"UPDATE campaigns SET {', '.join(set_clauses)} WHERE id = ?"
            self.db.execute(query, values)
            self.db.commit()
    
    def print_hunt_summary(self, hunt_results: Dict[str, Any]):
        """Print comprehensive hunt summary"""
        print(f"\n🎯 HUNT SUMMARY FOR {hunt_results['target'].upper()}")
        print("=" * 60)
        print(f"📊 Subdomains Discovered: {len(hunt_results['subdomains'])}")
        print(f"🌐 Live HTTP Services: {len(hunt_results['live_hosts'])}")
        print(f"🔍 Vulnerabilities Found: {len(hunt_results['vulnerabilities'])}")
        print(f"💎 High-Value Findings: {len(hunt_results['high_value_findings'])}")
        print(f"💰 Estimated Earnings: ${hunt_results['estimated_earnings']:.2f}")
        
        if hunt_results['high_value_findings']:
            print(f"\n🚨 HIGH-VALUE FINDINGS:")
            for i, finding in enumerate(hunt_results['high_value_findings'], 1):
                vuln = finding['vulnerability']
                print(f"   {i}. {vuln.get('info', {}).get('name', 'Unknown')} - ${finding['estimated_bounty']:.0f}")
                print(f"      Target: {vuln.get('host', 'Unknown')}")
                print(f"      Severity: {vuln.get('info', {}).get('severity', 'Unknown')}")
        
        print("=" * 60)
    
    async def interactive_assistant(self):
        """Interactive AI assistant mode"""
        self.print_status("Starting interactive AI assistant mode", "INFO")
        print("💬 Type 'exit' to quit, 'help' for commands")
        
        while self.running:
            try:
                user_input = input("\n🤖 BB-AI> ").strip()
                
                if user_input.lower() == 'exit':
                    break
                elif user_input.lower() == 'help':
                    self.print_assistant_help()
                elif user_input:
                    response = await self.ai_analyze("Bug bounty hunting context", user_input)
                    print(f"\n💡 AI Response:\n{response}")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.print_status(f"Assistant error: {e}", "ERROR")
    
    def print_assistant_help(self):
        """Print assistant help"""
        help_text = """
🤖 AI Assistant Commands:
  • Ask any bug bounty question
  • "analyze payload: <your_payload>" - Analyze a payload
  • "exploit ideas for: <vulnerability>" - Get exploitation ideas
  • "bounty estimate for: <vuln_type>" - Get bounty estimates
  • "help" - Show this help
  • "exit" - Exit assistant mode
        """
        print(help_text)

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="🐉 Kali Linux Pro Bug Bounty CLI - Gemini Powered",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s quick-hunt target.com
  %(prog)s deep-recon -t target.com
  %(prog)s ai-assistant
  %(prog)s status
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Quick hunt command
    quick_parser = subparsers.add_parser('quick-hunt', help='Automated quick hunting')
    quick_parser.add_argument('target', help='Target domain to hunt')
    quick_parser.add_argument('--timeout', type=int, default=1800, help='Hunt timeout in seconds')
    
    # Deep recon command
    recon_parser = subparsers.add_parser('deep-recon', help='Deep reconnaissance')
    recon_parser.add_argument('-t', '--target', required=True, help='Target domain')
    recon_parser.add_argument('-p', '--priority', choices=['low', 'medium', 'high'], 
                             default='medium', help='Scan priority')
    
    # AI assistant command
    subparsers.add_parser('ai-assistant', help='Interactive AI assistant')
    
    # Status command
    subparsers.add_parser('status', help='Show system status')
    
    # Tools command
    subparsers.add_parser('tools', help='Show available tools')
    
    args = parser.parse_args()
    
    # Initialize CLI
    cli = KaliProCLI()
    cli.print_banner()
    
    try:
        if args.command == 'quick-hunt':
            result = asyncio.run(cli.quick_hunt(args.target))
            
        elif args.command == 'deep-recon':
            cli.print_status(f"Deep recon not implemented yet", "WARNING")
            
        elif args.command == 'ai-assistant':
            asyncio.run(cli.interactive_assistant())
            
        elif args.command == 'status':
            cli.print_tool_status()
            session_time = time.time() - cli.start_time
            print(f"\n📈 Session Stats:")
            print(f"   Runtime: {session_time/60:.1f} minutes")
            print(f"   Commands: {cli.commands_executed}")
            print(f"   Findings: {cli.findings_discovered}")
            print(f"   Estimated: ${cli.estimated_earnings:.2f}")
            
        elif args.command == 'tools':
            cli.print_tool_status()
            
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        cli.print_status("Operation cancelled by user", "WARNING")
    except Exception as e:
        cli.print_status(f"Fatal error: {e}", "ERROR")
        raise
    finally:
        cli.cleanup()

if __name__ == "__main__":
    main()
