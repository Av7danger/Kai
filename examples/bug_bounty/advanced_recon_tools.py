#!/usr/bin/env python3
"""
🔍 Advanced Reconnaissance Tools for Bug Bounty Framework
Comprehensive reconnaissance and asset discovery tools

Features:
- Subdomain enumeration (Amass, Subfinder, Assetfinder)
- Live host detection (Httpx, Naabu, Masscan)
- Technology fingerprinting (Wappalyzer, Nmap)
- Port scanning and service detection
- Asset discovery and enumeration
- DNS reconnaissance
- Certificate transparency monitoring
- Cloud asset discovery
"""

import os
import sys
import subprocess
import json
import csv
import asyncio
import aiohttp
import aiofiles
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime
import logging
import yaml
import requests
from urllib.parse import urlparse, urljoin
import dns.resolver
import socket
import ssl
import OpenSSL
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

logger = logging.getLogger(__name__)

@dataclass
class ReconResult:
    """Reconnaissance result data"""
    target: str
    subdomain: str
    ip: str
    port: int
    service: str
    technology: str
    status_code: int
    title: str
    headers: Dict[str, str]
    certificate: Dict[str, Any]
    screenshot: str
    timestamp: str

class AdvancedReconTools:
    """Advanced reconnaissance and asset discovery tools"""
    
    def __init__(self, output_dir: str = 'recon_results'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        for subdir in ['subdomains', 'live_hosts', 'screenshots', 'reports']:
            (self.output_dir / subdir).mkdir(exist_ok=True)
        
        # Tool configurations
        self.tools_config = self._load_tools_config()
        
        # Results storage
        self.results = []
        self.subdomains = set()
        self.live_hosts = set()
        self.technologies = {}
    
    def _load_tools_config(self) -> Dict:
        """Load tools configuration"""
        config = {
            'amass': {
                'enabled': True,
                'command': 'amass',
                'args': ['enum', '-passive', '-norecursive', '-noalts'],
                'timeout': 300
            },
            'subfinder': {
                'enabled': True,
                'command': 'subfinder',
                'args': ['-silent', '-timeout', '30'],
                'timeout': 180
            },
            'assetfinder': {
                'enabled': True,
                'command': 'assetfinder',
                'args': ['--subs-only'],
                'timeout': 120
            },
            'httpx': {
                'enabled': True,
                'command': 'httpx',
                'args': ['-silent', '-status-code', '-title', '-tech-detect', '-screenshot'],
                'timeout': 60
            },
            'naabu': {
                'enabled': True,
                'command': 'naabu',
                'args': ['-silent', '-rate', '1000'],
                'timeout': 120
            },
            'masscan': {
                'enabled': True,
                'command': 'masscan',
                'args': ['--rate', '1000', '-p', '80,443,8080,8443'],
                'timeout': 300
            },
            'nuclei': {
                'enabled': True,
                'command': 'nuclei',
                'args': ['-silent', '-severity', 'low,medium,high,critical'],
                'timeout': 600
            },
            'nmap': {
                'enabled': True,
                'command': 'nmap',
                'args': ['-sS', '-sV', '-O', '--script=vuln'],
                'timeout': 300
            }
        }
        
        return config
    
    def check_tool_availability(self) -> Dict[str, bool]:
        """Check which tools are available"""
        availability = {}
        
        for tool_name, config in self.tools_config.items():
            try:
                result = subprocess.run([config['command'], '--help'], 
                                      capture_output=True, timeout=10)
                availability[tool_name] = result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                availability[tool_name] = False
        
        return availability
    
    def enumerate_subdomains(self, domain: str, tools: List[str] = None) -> Set[str]:
        """Enumerate subdomains using multiple tools"""
        if tools is None:
            tools = ['amass', 'subfinder', 'assetfinder']
        
        all_subdomains = set()
        
        for tool in tools:
            if tool not in self.tools_config:
                logger.warning(f"Tool {tool} not configured")
                continue
            
            try:
                subdomains = self._run_subdomain_tool(tool, domain)
                all_subdomains.update(subdomains)
                logger.info(f"{tool}: Found {len(subdomains)} subdomains")
            except Exception as e:
                logger.error(f"Error running {tool}: {e}")
        
        # Save results
        self._save_subdomains(domain, all_subdomains)
        self.subdomains.update(all_subdomains)
        
        return all_subdomains
    
    def _run_subdomain_tool(self, tool: str, domain: str) -> Set[str]:
        """Run a specific subdomain enumeration tool"""
        config = self.tools_config[tool]
        command = [config['command']] + config['args'] + [domain]
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, 
                                  timeout=config['timeout'])
            
            if result.returncode == 0:
                subdomains = set()
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and domain in line:
                        subdomains.add(line.strip())
                return subdomains
            else:
                logger.error(f"{tool} failed: {result.stderr}")
                return set()
                
        except subprocess.TimeoutExpired:
            logger.error(f"{tool} timed out")
            return set()
        except Exception as e:
            logger.error(f"Error running {tool}: {e}")
            return set()
    
    def find_live_hosts(self, targets: List[str], tools: List[str] = None) -> Set[str]:
        """Find live hosts from a list of targets"""
        if tools is None:
            tools = ['httpx', 'naabu']
        
        live_hosts = set()
        
        for tool in tools:
            if tool not in self.tools_config:
                logger.warning(f"Tool {tool} not configured")
                continue
            
            try:
                hosts = self._run_live_host_tool(tool, targets)
                live_hosts.update(hosts)
                logger.info(f"{tool}: Found {len(hosts)} live hosts")
            except Exception as e:
                logger.error(f"Error running {tool}: {e}")
        
        # Save results
        self._save_live_hosts(live_hosts)
        self.live_hosts.update(live_hosts)
        
        return live_hosts
    
    def _run_live_host_tool(self, tool: str, targets: List[str]) -> Set[str]:
        """Run a specific live host detection tool"""
        config = self.tools_config[tool]
        
        if tool == 'httpx':
            # Create input file
            input_file = self.output_dir / 'targets.txt'
            with open(input_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
            
            command = [config['command']] + config['args'] + ['-l', str(input_file)]
            
        elif tool == 'naabu':
            # Create input file
            input_file = self.output_dir / 'hosts.txt'
            with open(input_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
            
            command = [config['command']] + config['args'] + ['-l', str(input_file)]
        
        else:
            return set()
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, 
                                  timeout=config['timeout'])
            
            if result.returncode == 0:
                live_hosts = set()
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        live_hosts.add(line.strip())
                return live_hosts
            else:
                logger.error(f"{tool} failed: {result.stderr}")
                return set()
                
        except subprocess.TimeoutExpired:
            logger.error(f"{tool} timed out")
            return set()
        except Exception as e:
            logger.error(f"Error running {tool}: {e}")
            return set()
    
    def port_scan(self, hosts: List[str], ports: str = "80,443,8080,8443") -> Dict[str, List[int]]:
        """Port scan hosts using masscan and nmap"""
        port_results = {}
        
        # Use masscan for fast port scanning
        try:
            masscan_config = self.tools_config['masscan']
            command = [masscan_config['command']] + masscan_config['args'] + ['-p', ports] + hosts
            
            result = subprocess.run(command, capture_output=True, text=True, 
                                  timeout=masscan_config['timeout'])
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if 'open' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            host = parts[5]
                            port = int(parts[3].split('/')[0])
                            if host not in port_results:
                                port_results[host] = []
                            port_results[host].append(port)
        except Exception as e:
            logger.error(f"Masscan failed: {e}")
        
        # Use nmap for detailed service detection
        for host, open_ports in port_results.items():
            try:
                nmap_config = self.tools_config['nmap']
                ports_str = ','.join(map(str, open_ports))
                command = [nmap_config['command']] + nmap_config['args'] + ['-p', ports_str, host]
                
                result = subprocess.run(command, capture_output=True, text=True, 
                                      timeout=nmap_config['timeout'])
                
                if result.returncode == 0:
                    # Parse nmap output for service information
                    services = self._parse_nmap_output(result.stdout)
                    port_results[host] = services
                    
            except Exception as e:
                logger.error(f"Nmap failed for {host}: {e}")
        
        return port_results
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmap output for service information"""
        services = []
        
        for line in output.split('\n'):
            if 'open' in line and 'tcp' in line:
                parts = line.split()
                if len(parts) >= 4:
                    port = int(parts[0].split('/')[0])
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    version = parts[3] if len(parts) > 3 else ''
                    
                    services.append({
                        'port': port,
                        'service': service,
                        'version': version,
                        'state': 'open'
                    })
        
        return services
    
    def technology_fingerprinting(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        """Perform technology fingerprinting on URLs"""
        technologies = {}
        
        for url in urls:
            try:
                tech_info = self._fingerprint_url(url)
                technologies[url] = tech_info
            except Exception as e:
                logger.error(f"Fingerprinting failed for {url}: {e}")
        
        self.technologies.update(technologies)
        return technologies
    
    def _fingerprint_url(self, url: str) -> Dict[str, Any]:
        """Fingerprint a single URL"""
        tech_info = {
            'url': url,
            'server': '',
            'technologies': [],
            'headers': {},
            'certificate': {},
            'status_code': 0
        }
        
        try:
            # Get HTTP headers
            response = requests.get(url, timeout=10, allow_redirects=True)
            tech_info['status_code'] = response.status_code
            tech_info['headers'] = dict(response.headers)
            
            # Extract server information
            tech_info['server'] = response.headers.get('Server', '')
            
            # Basic technology detection
            technologies = []
            
            # Check for common technologies
            if 'X-Powered-By' in response.headers:
                technologies.append(response.headers['X-Powered-By'])
            
            if 'PHP' in response.headers.get('Server', ''):
                technologies.append('PHP')
            
            if 'nginx' in response.headers.get('Server', '').lower():
                technologies.append('Nginx')
            
            if 'apache' in response.headers.get('Server', '').lower():
                technologies.append('Apache')
            
            if 'wordpress' in response.text.lower():
                technologies.append('WordPress')
            
            if 'django' in response.text.lower():
                technologies.append('Django')
            
            if 'react' in response.text.lower():
                technologies.append('React')
            
            if 'jquery' in response.text.lower():
                technologies.append('jQuery')
            
            tech_info['technologies'] = list(set(technologies))
            
            # Get SSL certificate information
            if url.startswith('https://'):
                cert_info = self._get_ssl_certificate(url)
                tech_info['certificate'] = cert_info
            
        except Exception as e:
            logger.error(f"Error fingerprinting {url}: {e}")
        
        return tech_info
    
    def _get_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """Get SSL certificate information"""
        try:
            parsed = urlparse(url)
            context = ssl.create_default_context()
            
            with socket.create_connection((parsed.hostname, parsed.port or 443)) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            logger.error(f"Error getting SSL certificate for {url}: {e}")
            return {}
    
    def vulnerability_scan(self, targets: List[str], tools: List[str] = None) -> List[Dict[str, Any]]:
        """Run vulnerability scans on targets"""
        if tools is None:
            tools = ['nuclei']
        
        vulnerabilities = []
        
        for tool in tools:
            if tool not in self.tools_config:
                logger.warning(f"Tool {tool} not configured")
                continue
            
            try:
                vulns = self._run_vulnerability_tool(tool, targets)
                vulnerabilities.extend(vulns)
                logger.info(f"{tool}: Found {len(vulns)} vulnerabilities")
            except Exception as e:
                logger.error(f"Error running {tool}: {e}")
        
        return vulnerabilities
    
    def _run_vulnerability_tool(self, tool: str, targets: List[str]) -> List[Dict[str, Any]]:
        """Run a specific vulnerability scanning tool"""
        config = self.tools_config[tool]
        
        if tool == 'nuclei':
            # Create input file
            input_file = self.output_dir / 'vuln_targets.txt'
            with open(input_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
            
            command = [config['command']] + config['args'] + ['-l', str(input_file)]
            
        else:
            return []
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, 
                                  timeout=config['timeout'])
            
            if result.returncode == 0:
                vulns = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            vulns.append(vuln_data)
                        except json.JSONDecodeError:
                            # Parse non-JSON output
                            vulns.append({'raw_output': line})
                return vulns
            else:
                logger.error(f"{tool} failed: {result.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            logger.error(f"{tool} timed out")
            return []
        except Exception as e:
            logger.error(f"Error running {tool}: {e}")
            return []
    
    def comprehensive_recon(self, domain: str) -> Dict[str, Any]:
        """Run comprehensive reconnaissance on a domain"""
        logger.info(f"Starting comprehensive reconnaissance on {domain}")
        
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'live_hosts': [],
            'port_scan': {},
            'technologies': {},
            'vulnerabilities': [],
            'summary': {}
        }
        
        try:
            # 1. Subdomain enumeration
            logger.info("Step 1: Subdomain enumeration")
            subdomains = self.enumerate_subdomains(domain)
            results['subdomains'] = list(subdomains)
            
            # 2. Live host detection
            logger.info("Step 2: Live host detection")
            live_hosts = self.find_live_hosts(list(subdomains))
            results['live_hosts'] = list(live_hosts)
            
            # 3. Port scanning
            logger.info("Step 3: Port scanning")
            port_results = self.port_scan(list(live_hosts))
            results['port_scan'] = port_results
            
            # 4. Technology fingerprinting
            logger.info("Step 4: Technology fingerprinting")
            urls = [f"http://{host}" for host in live_hosts]
            urls.extend([f"https://{host}" for host in live_hosts])
            tech_results = self.technology_fingerprinting(urls)
            results['technologies'] = tech_results
            
            # 5. Vulnerability scanning
            logger.info("Step 5: Vulnerability scanning")
            vulns = self.vulnerability_scan(list(live_hosts))
            results['vulnerabilities'] = vulns
            
            # Generate summary
            results['summary'] = {
                'total_subdomains': len(subdomains),
                'total_live_hosts': len(live_hosts),
                'total_vulnerabilities': len(vulns),
                'unique_technologies': len(set([tech for url_tech in tech_results.values() 
                                              for tech in url_tech.get('technologies', [])]))
            }
            
            # Save comprehensive results
            self._save_comprehensive_results(domain, results)
            
            logger.info(f"Comprehensive reconnaissance completed for {domain}")
            logger.info(f"Summary: {results['summary']}")
            
        except Exception as e:
            logger.error(f"Comprehensive reconnaissance failed for {domain}: {e}")
        
        return results
    
    def _save_subdomains(self, domain: str, subdomains: Set[str]):
        """Save subdomain results"""
        output_file = self.output_dir / 'subdomains' / f"{domain}_subdomains.txt"
        with open(output_file, 'w') as f:
            for subdomain in sorted(subdomains):
                f.write(f"{subdomain}\n")
        
        # Also save as JSON
        json_file = self.output_dir / 'subdomains' / f"{domain}_subdomains.json"
        with open(json_file, 'w') as f:
            json.dump({
                'domain': domain,
                'subdomains': list(subdomains),
                'count': len(subdomains),
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)
    
    def _save_live_hosts(self, live_hosts: Set[str]):
        """Save live host results"""
        output_file = self.output_dir / 'live_hosts' / f"live_hosts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(output_file, 'w') as f:
            for host in sorted(live_hosts):
                f.write(f"{host}\n")
    
    def _save_comprehensive_results(self, domain: str, results: Dict[str, Any]):
        """Save comprehensive reconnaissance results"""
        output_file = self.output_dir / 'reports' / f"{domain}_comprehensive_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    def get_recon_statistics(self) -> Dict[str, Any]:
        """Get reconnaissance statistics"""
        return {
            'total_subdomains': len(self.subdomains),
            'total_live_hosts': len(self.live_hosts),
            'total_technologies': len(self.technologies),
            'tools_available': self.check_tool_availability(),
            'last_scan': datetime.now().isoformat()
        }

# Global recon tools instance
recon_tools = None

def initialize_recon_tools(output_dir: str = 'recon_results'):
    """Initialize the global reconnaissance tools instance"""
    global recon_tools
    recon_tools = AdvancedReconTools(output_dir)
    return recon_tools

def get_recon_tools() -> AdvancedReconTools:
    """Get the global reconnaissance tools instance"""
    if recon_tools is None:
        raise RuntimeError("Recon tools not initialized. Call initialize_recon_tools() first.")
    return recon_tools 