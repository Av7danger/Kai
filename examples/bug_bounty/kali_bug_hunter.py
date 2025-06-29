#!/usr/bin/env python3
"""
🐛 Kali Bug Hunter - Simplified Bug Bounty Framework
Optimized for Kali Linux with streamlined interface

Features:
- Reconnaissance tools (subdomain, port scanning, vulnerability scanning)
- AI-powered analysis and reporting
- Automated monitoring and alerting
- Bug submission and payout tracking
- Exploitation testing (safe mode)
- Modern web dashboard
- Kali Linux optimization
"""

import os
import sys
import json
import time
import sqlite3
import threading
import subprocess
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
import yaml
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class Target:
    """Target information"""
    id: str
    domain: str
    program_name: str
    reward_range: str
    status: str  # pending, scanning, completed, failed
    created_at: datetime
    last_scan: Optional[datetime] = None
    vulnerabilities_found: int = 0
    risk_score: float = 0.0

@dataclass
class Vulnerability:
    """Vulnerability information"""
    id: str
    target_id: str
    title: str
    description: str
    severity: str  # low, medium, high, critical
    cvss_score: float
    discovered_at: datetime
    status: str  # open, fixed, accepted, rejected
    proof_of_concept: str = ""
    remediation: str = ""

@dataclass
class ScanSession:
    """Scan session information"""
    id: str
    target_id: str
    scan_type: str  # quick, comprehensive, custom
    status: str  # running, completed, failed
    start_time: datetime
    end_time: Optional[datetime] = None
    progress: float = 0.0
    results: Dict[str, Any] = None

@dataclass
class BugReport:
    """Bug report information"""
    id: str
    vulnerability_id: str
    platform: str  # hackerone, bugcrowd, custom
    title: str
    description: str
    severity: str
    submitted_at: datetime
    status: str  # pending, accepted, rejected, duplicate
    reward: float = 0.0

class KaliBugHunter:
    """Main bug hunting application optimized for Kali Linux"""
    
    def __init__(self, config_path: str = 'kali_config.yml'):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Database
        self.db_path = 'kali_bug_hunter.db'
        self._init_database()
        
        # Data storage
        self.targets: Dict[str, Target] = {}
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.scan_sessions: Dict[str, ScanSession] = {}
        self.bug_reports: Dict[str, BugReport] = {}
        
        # Load existing data
        self._load_data()
        
        # Create output directories
        self.output_dir = Path('kali_results')
        self.output_dir.mkdir(exist_ok=True)
        
        for subdir in ['reports', 'scans', 'payloads', 'exports']:
            (self.output_dir / subdir).mkdir(exist_ok=True)
        
        # Initialize Kali tools
        self._init_kali_tools()
        
        logger.info("Kali Bug Hunter initialized successfully")
    
    def _load_config(self) -> Dict:
        """Load configuration"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default configuration optimized for Kali Linux"""
        return {
            'kali': {
                'tools_path': '/usr/bin',
                'enable_kali_tools': True,
                'auto_update': True
            },
            'scanning': {
                'default_scan_type': 'comprehensive',
                'max_concurrent_scans': 3,
                'scan_timeout': 3600,
                'enable_ai_analysis': True
            },
            'tools': {
                'nmap': True,
                'nuclei': True,
                'ffuf': True,
                'subfinder': True,
                'amass': True,
                'httpx': True
            },
            'ai': {
                'provider': 'openai',  # openai, anthropic, gemini
                'api_key': '',
                'model': 'gpt-4',
                'enable_auto_analysis': True
            },
            'dashboard': {
                'port': 5000,
                'host': '0.0.0.0',
                'debug': False,
                'theme': 'dark'
            }
        }
    
    def _init_database(self):
        """Initialize database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Targets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                program_name TEXT,
                reward_range TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT,
                last_scan TEXT,
                vulnerabilities_found INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0.0
            )
        ''')
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                target_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                discovered_at TEXT,
                status TEXT DEFAULT 'open',
                proof_of_concept TEXT,
                remediation TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        # Scan sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id TEXT PRIMARY KEY,
                target_id TEXT,
                scan_type TEXT,
                status TEXT,
                start_time TEXT,
                end_time TEXT,
                progress REAL DEFAULT 0.0,
                results TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        # Bug reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bug_reports (
                id TEXT PRIMARY KEY,
                vulnerability_id TEXT,
                platform TEXT,
                title TEXT,
                description TEXT,
                severity TEXT,
                submitted_at TEXT,
                status TEXT DEFAULT 'pending',
                reward REAL DEFAULT 0.0,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_data(self):
        """Load data from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Load targets
        cursor.execute('SELECT * FROM targets')
        for row in cursor.fetchall():
            target = Target(
                id=row[0],
                domain=row[1],
                program_name=row[2],
                reward_range=row[3],
                status=row[4],
                created_at=datetime.fromisoformat(row[5]),
                last_scan=datetime.fromisoformat(row[6]) if row[6] else None,
                vulnerabilities_found=row[7],
                risk_score=row[8]
            )
            self.targets[target.id] = target
        
        # Load vulnerabilities
        cursor.execute('SELECT * FROM vulnerabilities')
        for row in cursor.fetchall():
            vuln = Vulnerability(
                id=row[0],
                target_id=row[1],
                title=row[2],
                description=row[3],
                severity=row[4],
                cvss_score=row[5],
                discovered_at=datetime.fromisoformat(row[6]),
                status=row[7],
                proof_of_concept=row[8],
                remediation=row[9]
            )
            self.vulnerabilities[vuln.id] = vuln
        
        # Load scan sessions
        cursor.execute('SELECT * FROM scan_sessions')
        for row in cursor.fetchall():
            session = ScanSession(
                id=row[0],
                target_id=row[1],
                scan_type=row[2],
                status=row[3],
                start_time=datetime.fromisoformat(row[4]),
                end_time=datetime.fromisoformat(row[5]) if row[5] else None,
                progress=row[6],
                results=json.loads(row[7]) if row[7] else {}
            )
            self.scan_sessions[session.id] = session
        
        # Load bug reports
        cursor.execute('SELECT * FROM bug_reports')
        for row in cursor.fetchall():
            report = BugReport(
                id=row[0],
                vulnerability_id=row[1],
                platform=row[2],
                title=row[3],
                description=row[4],
                severity=row[5],
                submitted_at=datetime.fromisoformat(row[6]),
                status=row[7],
                reward=row[8]
            )
            self.bug_reports[report.id] = report
        
        conn.close()
    
    def _init_kali_tools(self):
        """Initialize Kali Linux tools"""
        self.kali_tools = {}
        
        if not self.config['kali']['enable_kali_tools']:
            return
        
        # Expanded tool list
        tools_to_check = [
            # Recon
            'nmap', 'masscan', 'subfinder', 'amass', 'theharvester', 'dnsrecon', 'whatweb', 'wafw00f',
            'gobuster', 'dirb', 'assetfinder', 'eyewitness', 'spiderfoot',
            # Vuln scan
            'nuclei', 'httpx', 'nikto', 'wpscan', 'joomscan', 'sqlmap', 'xsser', 'arachni', 'ffuf', 'dalfox',
            # Exploitation
            'metasploit-framework', 'hydra', 'medusa', 'patator', 'crackmapexec', 'responder', 'impacket-scripts',
            # Post-exploitation/analysis
            'hashcat', 'john', 'binwalk', 'strings', 'exiftool', 'steghide', 'foremost', 'volatility', 'radare2', 'gdb',
            # Wireless/network
            'aircrack-ng', 'reaver', 'bettercap', 'kismet',
            # OSINT/other
            'recon-ng', 'sherlock', 'social-engineer-toolkit'
        ]
        
        for tool in tools_to_check:
            try:
                result = subprocess.run([tool, '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.kali_tools[tool] = True
                    logger.info(f"Kali tool available: {tool}")
                else:
                    self.kali_tools[tool] = False
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.kali_tools[tool] = False
        
        logger.info(f"Kali tools initialized: {sum(self.kali_tools.values())} available")
    
    def add_target(self, domain: str, program_name: str = "", reward_range: str = "") -> str:
        """Add a new target"""
        target_id = f"target_{int(time.time())}"
        
        target = Target(
            id=target_id,
            domain=domain,
            program_name=program_name,
            reward_range=reward_range,
            status='pending',
            created_at=datetime.now()
        )
        
        self.targets[target_id] = target
        self._save_target(target)
        
        logger.info(f"Target added: {domain}")
        return target_id
    
    def start_scan(self, target_id: str, scan_type: str = "comprehensive", selected_tools: List[str] = []) -> str:
        """Start a scan on a target"""
        if target_id not in self.targets:
            raise ValueError(f"Target {target_id} not found")
        
        # Check if scan is already running
        running_scans = [s for s in self.scan_sessions.values() 
                        if s.target_id == target_id and s.status == 'running']
        if running_scans:
            raise ValueError(f"Scan already running for target {target_id}")
        
        session_id = f"scan_{int(time.time())}"
        
        session = ScanSession(
            id=session_id,
            target_id=target_id,
            scan_type=scan_type,
            status='running',
            start_time=datetime.now(),
            results={}
        )
        
        self.scan_sessions[session_id] = session
        self._save_scan_session(session)
        
        # Start scan in background thread
        scan_thread = threading.Thread(target=self._run_scan, args=(session_id, selected_tools))
        scan_thread.daemon = True
        scan_thread.start()
        
        logger.info(f"Scan started: {session_id} for {self.targets[target_id].domain}")
        return session_id
    
    def _run_scan(self, session_id: str, selected_tools: List[str] = None):
        """Run scan in background thread"""
        session = self.scan_sessions[session_id]
        target = self.targets[session.target_id]
        
        # Set default tools based on scan type if none selected
        if not selected_tools:
            if session.scan_type == 'quick':
                selected_tools = ['nmap', 'httpx', 'nuclei']
            elif session.scan_type == 'comprehensive':
                selected_tools = ['subfinder', 'nmap', 'httpx', 'nuclei', 'nikto', 'wpscan', 'joomscan']
            else:  # custom
                selected_tools = ['nmap', 'httpx', 'nuclei']  # fallback
        
        try:
            results = {}
            
            # Enhanced reconnaissance phase
            if 'subfinder' in selected_tools and self.kali_tools.get('subfinder'):
                results['subdomains'] = self._run_subfinder(target.domain)
                session.progress = 10
            
            if 'theharvester' in selected_tools and self.kali_tools.get('theharvester'):
                results['harvester'] = self._run_theharvester(target.domain)
                session.progress = 15
            
            if 'dnsrecon' in selected_tools and self.kali_tools.get('dnsrecon'):
                results['dns_recon'] = self._run_dnsrecon(target.domain)
                session.progress = 20
            
            if 'assetfinder' in selected_tools and self.kali_tools.get('assetfinder'):
                results['assets'] = self._run_assetfinder(target.domain)
                session.progress = 25
            
            # Technology fingerprinting
            if 'whatweb' in selected_tools and self.kali_tools.get('whatweb'):
                results['technologies'] = self._run_whatweb(target.domain)
                session.progress = 30
            
            if 'wafw00f' in selected_tools and self.kali_tools.get('wafw00f'):
                results['waf_detection'] = self._run_wafw00f(target.domain)
                session.progress = 35
            
            # Port scanning
            if 'nmap' in selected_tools and self.kali_tools.get('nmap'):
                results['ports'] = self._run_nmap(target.domain)
                session.progress = 40
            
            if 'masscan' in selected_tools and self.kali_tools.get('masscan'):
                results['masscan_ports'] = self._run_masscan(target.domain)
                session.progress = 45
            
            # Web discovery
            if 'httpx' in selected_tools and self.kali_tools.get('httpx'):
                results['web_targets'] = self._run_httpx(target.domain)
                session.progress = 50
            
            if 'gobuster' in selected_tools and self.kali_tools.get('gobuster'):
                results['directories'] = self._run_gobuster(target.domain)
                session.progress = 55
            
            if 'dirb' in selected_tools and self.kali_tools.get('dirb'):
                results['dirb_results'] = self._run_dirb(target.domain)
                session.progress = 60
            
            # Vulnerability scanning
            if 'nuclei' in selected_tools and self.kali_tools.get('nuclei'):
                results['vulnerabilities'] = self._run_nuclei(target.domain)
                session.progress = 65
            
            if 'nikto' in selected_tools and self.kali_tools.get('nikto'):
                results['nikto_scan'] = self._run_nikto(target.domain)
                session.progress = 70
            
            if 'wpscan' in selected_tools and self.kali_tools.get('wpscan'):
                results['wordpress_scan'] = self._run_wpscan(target.domain)
                session.progress = 75
            
            if 'joomscan' in selected_tools and self.kali_tools.get('joomscan'):
                results['joomla_scan'] = self._run_joomscan(target.domain)
                session.progress = 80
            
            if 'xsser' in selected_tools and self.kali_tools.get('xsser'):
                results['xss_scan'] = self._run_xsser(target.domain)
                session.progress = 85
            
            if 'dalfox' in selected_tools and self.kali_tools.get('dalfox'):
                results['xss_dalfox'] = self._run_dalfox(target.domain)
                session.progress = 90
            
            # Advanced scanning (if comprehensive scan)
            if session.scan_type == 'comprehensive':
                if 'arachni' in selected_tools and self.kali_tools.get('arachni'):
                    results['arachni_scan'] = self._run_arachni(target.domain)
                    session.progress = 95
            
            # AI analysis
            if self.config['ai']['enable_auto_analysis']:
                results['ai_analysis'] = self._analyze_results(results)
                session.progress = 100
            
            # Update session
            session.status = 'completed'
            session.end_time = datetime.now()
            session.results = results
            self._save_scan_session(session)
            
            # Update target
            target.last_scan = datetime.now()
            target.status = 'completed'
            target.vulnerabilities_found = len(results.get('vulnerabilities', []))
            self._save_target(target)
            
            # Create vulnerability records
            self._create_vulnerabilities(target.id, results.get('vulnerabilities', []))
            
            logger.info(f"Scan completed: {session_id}")
            
        except Exception as e:
            logger.error(f"Scan failed: {session_id} - {e}")
            session.status = 'failed'
            session.end_time = datetime.now()
            self._save_scan_session(session)
    
    def _run_subfinder(self, domain: str) -> List[str]:
        """Run subfinder for subdomain enumeration"""
        try:
            result = subprocess.run([
                'subfinder', '-d', domain, '-silent'
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return result.stdout.strip().split('\n')
            return []
        except Exception as e:
            logger.error(f"Subfinder failed: {e}")
            return []
    
    def _run_nmap(self, domain: str) -> Dict[str, Any]:
        """Run nmap for port scanning"""
        try:
            result = subprocess.run([
                'nmap', '-sS', '-sV', '-O', '--top-ports', '1000', domain
            ], capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                # Parse nmap output (simplified)
                return {
                    'raw_output': result.stdout,
                    'ports_found': len([line for line in result.stdout.split('\n') 
                                      if 'open' in line])
                }
            return {}
        except Exception as e:
            logger.error(f"Nmap failed: {e}")
            return {}
    
    def _run_httpx(self, domain: str) -> List[str]:
        """Run httpx for web discovery"""
        try:
            result = subprocess.run([
                'httpx', '-l', f'{domain}', '-silent', '-status-code'
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return result.stdout.strip().split('\n')
            return []
        except Exception as e:
            logger.error(f"Httpx failed: {e}")
            return []
    
    def _run_nuclei(self, domain: str) -> List[Dict[str, Any]]:
        """Run nuclei for vulnerability scanning"""
        try:
            result = subprocess.run([
                'nuclei', '-u', domain, '-silent', '-json'
            ], capture_output=True, text=True, timeout=900)
            
            if result.returncode == 0:
                vulnerabilities = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            vuln = json.loads(line)
                            vulnerabilities.append(vuln)
                        except json.JSONDecodeError:
                            continue
                return vulnerabilities
            return []
        except Exception as e:
            logger.error(f"Nuclei failed: {e}")
            return []
    
    def _analyze_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan results with AI"""
        try:
            # Simplified AI analysis (in production, use actual AI API)
            analysis = {
                'risk_score': 0.0,
                'recommendations': [],
                'summary': 'Scan completed successfully'
            }
            
            # Calculate risk score based on findings
            vuln_count = len(results.get('vulnerabilities', []))
            if vuln_count > 10:
                analysis['risk_score'] = 0.9
            elif vuln_count > 5:
                analysis['risk_score'] = 0.7
            elif vuln_count > 0:
                analysis['risk_score'] = 0.5
            
            # Generate recommendations
            if vuln_count > 0:
                analysis['recommendations'].append(f"Found {vuln_count} vulnerabilities - review immediately")
            
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {'error': str(e)}
    
    def _create_vulnerabilities(self, target_id: str, vuln_data: List[Dict[str, Any]]):
        """Create vulnerability records from scan results"""
        for vuln in vuln_data:
            vuln_id = f"vuln_{int(time.time())}_{len(self.vulnerabilities)}"
            
            vulnerability = Vulnerability(
                id=vuln_id,
                target_id=target_id,
                title=vuln.get('info', {}).get('name', 'Unknown Vulnerability'),
                description=vuln.get('info', {}).get('description', ''),
                severity=vuln.get('info', {}).get('severity', 'medium'),
                cvss_score=float(vuln.get('info', {}).get('cvss-score', 0)),
                discovered_at=datetime.now(),
                status='open',
                proof_of_concept=vuln.get('matched-at', ''),
                remediation=vuln.get('info', {}).get('remediation', '')
            )
            
            self.vulnerabilities[vuln_id] = vulnerability
            self._save_vulnerability(vulnerability)
    
    def get_scan_status(self, session_id: str) -> Optional[ScanSession]:
        """Get scan session status"""
        return self.scan_sessions.get(session_id)
    
    def get_target_stats(self) -> Dict[str, Any]:
        """Get target statistics"""
        total_targets = len(self.targets)
        active_scans = len([s for s in self.scan_sessions.values() if s.status == 'running'])
        total_vulnerabilities = len(self.vulnerabilities)
        total_reports = len(self.bug_reports)
        
        return {
            'total_targets': total_targets,
            'active_scans': active_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'total_reports': total_reports,
            'kali_tools_available': sum(self.kali_tools.values())
        }
    
    def generate_report(self, target_id: str = None) -> str:
        """Generate comprehensive report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = self.output_dir / 'reports' / f'bug_hunter_report_{timestamp}.html'
        
        # Generate HTML report
        html_content = self._generate_html_report(target_id)
        
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        return str(report_path)
    
    def _generate_html_report(self, target_id: str = None) -> str:
        """Generate HTML report"""
        targets_to_report = [self.targets[target_id]] if target_id else list(self.targets.values())
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Kali Bug Hunter Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #ffffff; }}
                .header {{ background: #2c3e50; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
                .section {{ background: #2d2d2d; padding: 15px; margin: 10px 0; border-radius: 8px; }}
                .vuln-high {{ color: #e74c3c; }}
                .vuln-medium {{ color: #f39c12; }}
                .vuln-low {{ color: #27ae60; }}
                .stats {{ display: flex; gap: 20px; }}
                .stat {{ background: #34495e; padding: 15px; border-radius: 8px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🐛 Kali Bug Hunter Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Summary Statistics</h2>
                <div class="stats">
                    <div class="stat">
                        <h3>{len(targets_to_report)}</h3>
                        <p>Targets</p>
                    </div>
                    <div class="stat">
                        <h3>{len(self.vulnerabilities)}</h3>
                        <p>Vulnerabilities</p>
                    </div>
                    <div class="stat">
                        <h3>{len(self.bug_reports)}</h3>
                        <p>Bug Reports</p>
                    </div>
                </div>
            </div>
        """
        
        for target in targets_to_report:
            target_vulns = [v for v in self.vulnerabilities.values() if v.target_id == target.id]
            
            html += f"""
            <div class="section">
                <h2>Target: {target.domain}</h2>
                <p><strong>Program:</strong> {target.program_name}</p>
                <p><strong>Status:</strong> {target.status}</p>
                <p><strong>Vulnerabilities Found:</strong> {len(target_vulns)}</p>
                
                <h3>Vulnerabilities</h3>
            """
            
            for vuln in target_vulns:
                severity_class = f"vuln-{vuln.severity}"
                html += f"""
                <div class="section">
                    <h4 class="{severity_class}">{vuln.title}</h4>
                    <p><strong>Severity:</strong> {vuln.severity.upper()}</p>
                    <p><strong>CVSS Score:</strong> {vuln.cvss_score}</p>
                    <p><strong>Description:</strong> {vuln.description}</p>
                    <p><strong>Status:</strong> {vuln.status}</p>
                </div>
                """
            
            html += "</div>"
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def _save_target(self, target: Target):
        """Save target to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO targets 
            (id, domain, program_name, reward_range, status, created_at, last_scan, vulnerabilities_found, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            target.id, target.domain, target.program_name, target.reward_range,
            target.status, target.created_at.isoformat(),
            target.last_scan.isoformat() if target.last_scan else None,
            target.vulnerabilities_found, target.risk_score
        ))
        
        conn.commit()
        conn.close()
    
    def _save_vulnerability(self, vulnerability: Vulnerability):
        """Save vulnerability to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO vulnerabilities 
            (id, target_id, title, description, severity, cvss_score, discovered_at, status, proof_of_concept, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            vulnerability.id, vulnerability.target_id, vulnerability.title,
            vulnerability.description, vulnerability.severity, vulnerability.cvss_score,
            vulnerability.discovered_at.isoformat(), vulnerability.status,
            vulnerability.proof_of_concept, vulnerability.remediation
        ))
        
        conn.commit()
        conn.close()
    
    def _save_scan_session(self, session: ScanSession):
        """Save scan session to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO scan_sessions 
            (id, target_id, scan_type, status, start_time, end_time, progress, results)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.id, session.target_id, session.scan_type, session.status,
            session.start_time.isoformat(),
            session.end_time.isoformat() if session.end_time else None,
            session.progress, json.dumps(session.results) if session.results else '{}'
        ))
        
        conn.commit()
        conn.close()

    # Placeholders for new tool runners
    def _run_theharvester(self, domain: str) -> str:
        try:
            result = subprocess.run(['theharvester', '-d', domain, '-b', 'all'], capture_output=True, text=True, timeout=300)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"theHarvester failed: {e}")
            return ''

    def _run_dnsrecon(self, domain: str) -> str:
        try:
            result = subprocess.run(['dnsrecon', '-d', domain], capture_output=True, text=True, timeout=300)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"dnsrecon failed: {e}")
            return ''

    def _run_masscan(self, domain: str) -> str:
        try:
            result = subprocess.run(['masscan', domain, '-p1-65535', '--rate', '1000'], capture_output=True, text=True, timeout=300)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"masscan failed: {e}")
            return ''

    def _run_whatweb(self, domain: str) -> str:
        try:
            result = subprocess.run(['whatweb', domain], capture_output=True, text=True, timeout=120)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"whatweb failed: {e}")
            return ''

    def _run_wafw00f(self, domain: str) -> str:
        try:
            result = subprocess.run(['wafw00f', domain], capture_output=True, text=True, timeout=120)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"wafw00f failed: {e}")
            return ''

    def _run_nikto(self, domain: str) -> str:
        try:
            result = subprocess.run(['nikto', '-h', domain], capture_output=True, text=True, timeout=600)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"nikto failed: {e}")
            return ''

    def _run_wpscan(self, domain: str) -> str:
        try:
            result = subprocess.run(['wpscan', '--url', domain, '--disable-tls-checks'], capture_output=True, text=True, timeout=600)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"wpscan failed: {e}")
            return ''

    def _run_joomscan(self, domain: str) -> str:
        try:
            result = subprocess.run(['joomscan', '--url', domain], capture_output=True, text=True, timeout=600)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"joomscan failed: {e}")
            return ''

    def _run_xsser(self, domain: str) -> str:
        try:
            result = subprocess.run(['xsser', '--url', domain], capture_output=True, text=True, timeout=600)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"xsser failed: {e}")
            return ''

    def _run_arachni(self, domain: str) -> str:
        try:
            result = subprocess.run(['arachni', domain], capture_output=True, text=True, timeout=900)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"arachni failed: {e}")
            return ''

    def _run_dalfox(self, domain: str) -> str:
        try:
            result = subprocess.run(['dalfox', 'url', domain], capture_output=True, text=True, timeout=600)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"dalfox failed: {e}")
            return ''

    def _run_gobuster(self, domain: str) -> str:
        try:
            result = subprocess.run(['gobuster', 'dir', '-u', domain, '-w', '/usr/share/wordlists/dirb/common.txt'], capture_output=True, text=True, timeout=600)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"gobuster failed: {e}")
            return ''

    def _run_dirb(self, domain: str) -> str:
        try:
            result = subprocess.run(['dirb', domain], capture_output=True, text=True, timeout=600)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"dirb failed: {e}")
            return ''

    def _run_assetfinder(self, domain: str) -> str:
        try:
            result = subprocess.run(['assetfinder', domain], capture_output=True, text=True, timeout=300)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"assetfinder failed: {e}")
            return ''

    def _run_eyewitness(self, domain: str) -> str:
        try:
            result = subprocess.run(['eyewitness', '--web', domain], capture_output=True, text=True, timeout=600)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"eyewitness failed: {e}")
            return ''

    def _run_spiderfoot(self, domain: str) -> str:
        try:
            result = subprocess.run(['spiderfoot', '-s', domain], capture_output=True, text=True, timeout=900)
            return result.stdout if result.returncode == 0 else ''
        except Exception as e:
            logger.error(f"spiderfoot failed: {e}")
            return ''

# Global application instance
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'kali-bug-hunter-secret-key')

# Global bug hunter instance
bug_hunter = None

def initialize_bug_hunter(config_path: str = 'kali_config.yml'):
    """Initialize the global bug hunter instance"""
    global bug_hunter
    bug_hunter = KaliBugHunter(config_path)
    return bug_hunter

def get_bug_hunter() -> KaliBugHunter:
    """Get the global bug hunter instance"""
    if bug_hunter is None:
        raise RuntimeError("Bug hunter not initialized. Call initialize_bug_hunter() first.")
    return bug_hunter

@app.route('/')
def dashboard():
    """Main dashboard"""
    hunter = get_bug_hunter()
    stats = hunter.get_target_stats()
    
    return render_template('kali_dashboard.html', 
                         stats=stats,
                         targets=list(hunter.targets.values()),
                         vulnerabilities=list(hunter.vulnerabilities.values()),
                         kali_tools=hunter.kali_tools)

@app.route('/api/targets', methods=['GET', 'POST'])
def api_targets():
    """API endpoint for targets"""
    hunter = get_bug_hunter()
    
    if request.method == 'POST':
        data = request.get_json()
        target_id = hunter.add_target(
            domain=data['domain'],
            program_name=data.get('program_name', ''),
            reward_range=data.get('reward_range', '')
        )
        return jsonify({'success': True, 'target_id': target_id})
    
    return jsonify([asdict(target) for target in hunter.targets.values()])

@app.route('/api/scan/<target_id>', methods=['POST'])
def api_scan(target_id):
    """API endpoint for starting scans"""
    hunter = get_bug_hunter()
    
    try:
        data = request.get_json()
        scan_type = data.get('scan_type', 'comprehensive')
        selected_tools = data.get('selected_tools', [])
        
        session_id = hunter.start_scan(target_id, scan_type, selected_tools)
        return jsonify({'success': True, 'session_id': session_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/scan/status/<session_id>')
def api_scan_status(session_id):
    """API endpoint for scan status"""
    hunter = get_bug_hunter()
    session = hunter.get_scan_status(session_id)
    
    if session:
        return jsonify(asdict(session))
    else:
        return jsonify({'error': 'Session not found'})

@app.route('/api/report')
def api_report():
    """API endpoint for generating reports"""
    hunter = get_bug_hunter()
    target_id = request.args.get('target_id')
    
    try:
        report_path = hunter.generate_report(target_id)
        return jsonify({'success': True, 'report_path': report_path})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    # Initialize bug hunter
    initialize_bug_hunter()
    
    # Run the Flask app
    config = get_bug_hunter().config['dashboard']
    app.run(host=config['host'], port=config['port'], debug=config['debug']) 