"""
Enhanced Free Security Tools Integration
Comprehensive integration with powerful open-source security tools
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import time
import requests

logger = logging.getLogger('enhanced_free_tools')

@dataclass
class ToolResult:
    """Enhanced tool result structure"""
    tool_name: str
    target: str
    success: bool
    execution_time: float
    data: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    error: Optional[str] = None
    raw_output: Optional[str] = None

class EnhancedSecurityToolsManager:
    """Manager for enhanced free security tools"""
    
    def __init__(self, tools_config: Optional[Dict] = None):
        self.config = tools_config or {}
        self.temp_dir = tempfile.mkdtemp(prefix='enhanced_security_')
        self.results_cache = {}
        
        # Tool configurations with free alternatives
        self.tools = {
            'reconnaissance': {
                'subfinder': {'timeout': 120, 'threads': 50},
                'amass': {'timeout': 300, 'passive': True},
                'assetfinder': {'timeout': 60},
                'findomain': {'timeout': 90}
            },
            'port_scanning': {
                'nmap': {'timeout': 300, 'top_ports': 1000},
                'masscan': {'timeout': 180, 'rate': 1000},
                'rustscan': {'timeout': 120, 'batch_size': 5000}
            },
            'web_scanning': {
                'httpx': {'timeout': 60, 'threads': 100},
                'waybackurls': {'timeout': 90},
                'gau': {'timeout': 120},  # Get All URLs
                'hakrawler': {'timeout': 150}
            },
            'vulnerability_scanning': {
                'nuclei': {'timeout': 600, 'rate_limit': 150},
                'nikto': {'timeout': 300},
                'sqlmap': {'timeout': 600, 'risk': 1, 'level': 1},
                'xssstrike': {'timeout': 240}
            },
            'content_discovery': {
                'ffuf': {'timeout': 300, 'threads': 40},
                'gobuster': {'timeout': 240, 'threads': 30},
                'dirsearch': {'timeout': 180}
            }
        }
    
    async def install_tools(self) -> Dict[str, bool]:
        """Install missing security tools"""
        installation_results = {}
        
        # Go-based tools
        go_tools = {
            'subfinder': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'nuclei': 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'amass': 'github.com/owasp-amass/amass/v4/...@master',
            'assetfinder': 'github.com/tomnomnom/assetfinder@latest',
            'waybackurls': 'github.com/tomnomnom/waybackurls@latest',
            'gau': 'github.com/lc/gau/v2/cmd/gau@latest',
            'ffuf': 'github.com/ffuf/ffuf@latest',
            'hakrawler': 'github.com/hakluke/hakrawler@latest'
        }
        
        # Install Go tools
        for tool, package in go_tools.items():
            try:
                logger.info(f"Installing {tool}...")
                result = subprocess.run(
                    ['go', 'install', '-v', package],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                installation_results[tool] = result.returncode == 0
                if result.returncode == 0:
                    logger.info(f"✅ {tool} installed successfully")
                else:
                    logger.error(f"❌ Failed to install {tool}: {result.stderr}")
            except Exception as e:
                logger.error(f"❌ Error installing {tool}: {e}")
                installation_results[tool] = False
        
        # Python-based tools
        python_tools = {
            'sqlmap': 'sqlmap',
            'dirsearch': 'dirsearch'
        }
        
        for tool, package in python_tools.items():
            try:
                logger.info(f"Installing {tool}...")
                result = subprocess.run(
                    ['pip', 'install', package],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                installation_results[tool] = result.returncode == 0
                if result.returncode == 0:
                    logger.info(f"✅ {tool} installed successfully")
                else:
                    logger.error(f"❌ Failed to install {tool}: {result.stderr}")
            except Exception as e:
                logger.error(f"❌ Error installing {tool}: {e}")
                installation_results[tool] = False
        
        return installation_results
    
    async def run_subdomain_enumeration(self, domain: str) -> ToolResult:
        """Comprehensive subdomain enumeration"""
        start_time = time.time()
        all_subdomains = set()
        tool_results = {}
        
        try:
            # Subfinder
            try:
                cmd = ['subfinder', '-d', domain, '-silent', '-o', f'{self.temp_dir}/subfinder.txt']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.returncode == 0 and os.path.exists(f'{self.temp_dir}/subfinder.txt'):
                    with open(f'{self.temp_dir}/subfinder.txt', 'r') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                        all_subdomains.update(subdomains)
                        tool_results['subfinder'] = len(subdomains)
            except Exception as e:
                logger.error(f"Subfinder error: {e}")
                tool_results['subfinder'] = 0
            
            # Assetfinder
            try:
                cmd = ['assetfinder', '--subs-only', domain]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                    all_subdomains.update(subdomains)
                    tool_results['assetfinder'] = len(subdomains)
            except Exception as e:
                logger.error(f"Assetfinder error: {e}")
                tool_results['assetfinder'] = 0
            
            # Amass passive
            try:
                cmd = ['amass', 'enum', '-passive', '-d', domain, '-o', f'{self.temp_dir}/amass.txt']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode == 0 and os.path.exists(f'{self.temp_dir}/amass.txt'):
                    with open(f'{self.temp_dir}/amass.txt', 'r') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                        all_subdomains.update(subdomains)
                        tool_results['amass'] = len(subdomains)
            except Exception as e:
                logger.error(f"Amass error: {e}")
                tool_results['amass'] = 0
            
            execution_time = time.time() - start_time
            unique_subdomains = list(all_subdomains)
            
            return ToolResult(
                tool_name="subdomain_enumeration",
                target=domain,
                success=len(unique_subdomains) > 0,
                execution_time=execution_time,
                data={
                    'total_subdomains': len(unique_subdomains),
                    'subdomains': unique_subdomains[:50],  # Limit output
                    'tool_results': tool_results
                },
                vulnerabilities=[]
            )
            
        except Exception as e:
            return ToolResult(
                tool_name="subdomain_enumeration",
                target=domain,
                success=False,
                execution_time=time.time() - start_time,
                data={},
                vulnerabilities=[],
                error=str(e)
            )
    
    async def run_port_scanning(self, target: str) -> ToolResult:
        """Enhanced port scanning"""
        start_time = time.time()
        
        try:
            # Use nmap for comprehensive port scanning
            cmd = [
                'nmap', '-sS', '-T4', '-p-',
                '--max-retries', '1',
                '--max-scan-delay', '20ms',
                '--min-rate', '5000',
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            open_ports = []
            services = {}
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port = parts[0].split('/')[0]
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            open_ports.append(int(port))
                            services[port] = service
            
            return ToolResult(
                tool_name="port_scanning",
                target=target,
                success=len(open_ports) > 0,
                execution_time=time.time() - start_time,
                data={
                    'open_ports': open_ports,
                    'services': services,
                    'total_open_ports': len(open_ports)
                },
                vulnerabilities=[]
            )
            
        except Exception as e:
            return ToolResult(
                tool_name="port_scanning", 
                target=target,
                success=False,
                execution_time=time.time() - start_time,
                data={},
                vulnerabilities=[],
                error=str(e)
            )
    
    async def run_web_enumeration(self, target: str) -> ToolResult:
        """Web application enumeration"""
        start_time = time.time()
        
        try:
            results = {}
            
            # Httpx for live web services
            try:
                cmd = ['httpx', '-target', target, '-silent', '-json']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            try:
                                data = json.loads(line)
                                results['web_info'] = {
                                    'url': data.get('url'),
                                    'status_code': data.get('status-code'),
                                    'title': data.get('title'),
                                    'tech': data.get('tech', []),
                                    'server': data.get('webserver'),
                                    'content_length': data.get('content-length')
                                }
                                break
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                logger.error(f"Httpx error: {e}")
            
            # Directory discovery with ffuf
            try:
                wordlist_path = "/usr/share/wordlists/dirb/common.txt"
                if not os.path.exists(wordlist_path):
                    # Use a simple built-in wordlist
                    wordlist_path = f"{self.temp_dir}/simple_wordlist.txt"
                    with open(wordlist_path, 'w') as f:
                        common_dirs = [
                            'admin', 'api', 'login', 'dashboard', 'config',
                            'backup', 'test', 'dev', 'staging', 'uploads',
                            'images', 'js', 'css', 'assets', 'files'
                        ]
                        f.write('\n'.join(common_dirs))
                
                cmd = [
                    'ffuf', '-u', f"{target}/FUZZ",
                    '-w', wordlist_path,
                    '-fc', '404',
                    '-sf',
                    '-o', f'{self.temp_dir}/ffuf.json',
                    '-of', 'json'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                if result.returncode == 0 and os.path.exists(f'{self.temp_dir}/ffuf.json'):
                    with open(f'{self.temp_dir}/ffuf.json', 'r') as f:
                        ffuf_data = json.load(f)
                        results['directories'] = ffuf_data.get('results', [])[:20]  # Limit results
                        
            except Exception as e:
                logger.error(f"Ffuf error: {e}")
            
            return ToolResult(
                tool_name="web_enumeration",
                target=target,
                success=bool(results),
                execution_time=time.time() - start_time,
                data=results,
                vulnerabilities=[]
            )
            
        except Exception as e:
            return ToolResult(
                tool_name="web_enumeration",
                target=target,
                success=False,
                execution_time=time.time() - start_time,
                data={},
                vulnerabilities=[],
                error=str(e)
            )
    
    async def run_nuclei_scan(self, target: str) -> ToolResult:
        """Nuclei vulnerability scanning"""
        start_time = time.time()
        
        try:
            # Update nuclei templates first
            subprocess.run(['nuclei', '-update-templates'], capture_output=True, timeout=60)
            
            cmd = [
                'nuclei', '-target', target,
                '-json',
                '-rate-limit', '150',
                '-timeout', '5',
                '-retries', '1',
                '-severity', 'critical,high,medium',
                '-o', f'{self.temp_dir}/nuclei.json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            vulnerabilities = []
            if os.path.exists(f'{self.temp_dir}/nuclei.json'):
                with open(f'{self.temp_dir}/nuclei.json', 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                vuln = json.loads(line)
                                vulnerabilities.append({
                                    'template_id': vuln.get('template-id'),
                                    'name': vuln.get('info', {}).get('name'),
                                    'severity': vuln.get('info', {}).get('severity'),
                                    'url': vuln.get('matched-at'),
                                    'description': vuln.get('info', {}).get('description'),
                                    'reference': vuln.get('info', {}).get('reference', [])
                                })
                            except json.JSONDecodeError:
                                continue
            
            return ToolResult(
                tool_name="nuclei_scan",
                target=target,
                success=True,
                execution_time=time.time() - start_time,
                data={
                    'total_vulnerabilities': len(vulnerabilities),
                    'severities': self._count_severities(vulnerabilities)
                },
                vulnerabilities=vulnerabilities
            )
            
        except Exception as e:
            return ToolResult(
                tool_name="nuclei_scan",
                target=target,
                success=False,
                execution_time=time.time() - start_time,
                data={},
                vulnerabilities=[],
                error=str(e)
            )
    
    def _count_severities(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            if severity in severities:
                severities[severity] += 1
        return severities
    
    async def comprehensive_security_scan(self, target: str) -> Dict[str, Any]:
        """Run comprehensive security assessment"""
        logger.info(f"Starting comprehensive security scan for {target}")
        
        results = {
            'target': target,
            'start_time': time.time(),
            'scan_id': f"enhanced_{int(time.time())}",
            'results': {},
            'summary': {}
        }
        
        try:
            # Phase 1: Reconnaissance
            logger.info("Phase 1: Subdomain enumeration...")
            if '://' not in target:
                domain = target
            else:
                domain = target.split('://')[1].split('/')[0]
            
            subdomain_result = await self.run_subdomain_enumeration(domain)
            results['results']['subdomains'] = subdomain_result.__dict__
            
            # Phase 2: Port scanning
            logger.info("Phase 2: Port scanning...")
            port_result = await self.run_port_scanning(target)
            results['results']['ports'] = port_result.__dict__
            
            # Phase 3: Web enumeration
            logger.info("Phase 3: Web enumeration...")
            web_result = await self.run_web_enumeration(target)
            results['results']['web'] = web_result.__dict__
            
            # Phase 4: Vulnerability scanning
            logger.info("Phase 4: Vulnerability scanning...")
            nuclei_result = await self.run_nuclei_scan(target)
            results['results']['vulnerabilities'] = nuclei_result.__dict__
            
            # Generate summary
            results['summary'] = {
                'total_subdomains': subdomain_result.data.get('total_subdomains', 0),
                'open_ports': len(port_result.data.get('open_ports', [])),
                'vulnerabilities_found': len(nuclei_result.vulnerabilities),
                'critical_vulns': sum(1 for v in nuclei_result.vulnerabilities if v.get('severity') == 'critical'),
                'high_vulns': sum(1 for v in nuclei_result.vulnerabilities if v.get('severity') == 'high'),
                'scan_duration': time.time() - results['start_time'],
                'success': all([
                    subdomain_result.success,
                    port_result.success,
                    web_result.success,
                    nuclei_result.success
                ])
            }
            
            results['end_time'] = time.time()
            logger.info(f"Comprehensive scan completed for {target}")
            
            return results
            
        except Exception as e:
            logger.error(f"Comprehensive scan failed: {e}")
            results['error'] = str(e)
            results['end_time'] = time.time()
            return results

# Global instance
enhanced_tools = EnhancedSecurityToolsManager()

async def run_enhanced_security_scan(target: str) -> Dict[str, Any]:
    """High-level function for enhanced security scanning"""
    return await enhanced_tools.comprehensive_security_scan(target)

if __name__ == "__main__":
    # Demo
    async def demo():
        target = "example.com"
        print(f"Running enhanced security scan on {target}")
        
        result = await run_enhanced_security_scan(target)
        print(f"Scan results: {json.dumps(result['summary'], indent=2)}")
    
    asyncio.run(demo())
