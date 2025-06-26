"""
Real Security Tools Integration for Enhanced Bug Bounty Framework
Implementing actual integration with real security tools: Subfinder, Nuclei, Httpx
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
import shlex

logger = logging.getLogger('real_security_tools')

@dataclass
class ToolResult:
    """Standardized result format for security tools"""
    tool_name: str
    success: bool
    execution_time: float
    data: Dict[str, Any]
    error: Optional[str] = None
    raw_output: Optional[str] = None

class SecurityToolManager:
    """Manager for real security tools integration"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.tools_path = self.config.get('tools_path', '/usr/local/bin')
        self.temp_dir = tempfile.mkdtemp(prefix='bug_bounty_')
        self.logger = logging.getLogger('security_tools')
        
        # Tool configurations
        self.tool_configs = {
            'subfinder': {
                'binary': 'subfinder',
                'timeout': self.config.get('subfinder_timeout', 60),
                'threads': self.config.get('subfinder_threads', 50),
                'sources': self.config.get('subfinder_sources', ['crtsh', 'virustotal', 'dnsdumpster'])
            },
            'nuclei': {
                'binary': 'nuclei',
                'timeout': self.config.get('nuclei_timeout', 300),
                'rate_limit': self.config.get('nuclei_rate_limit', 100),
                'templates_path': self.config.get('nuclei_templates_path', '/root/nuclei-templates')
            },
            'httpx': {
                'binary': 'httpx',
                'timeout': self.config.get('httpx_timeout', 30),
                'threads': self.config.get('httpx_threads', 100),
                'follow_redirects': self.config.get('httpx_follow_redirects', True)
            },
            'amass': {
                'binary': 'amass',
                'timeout': self.config.get('amass_timeout', 600),
                'passive': self.config.get('amass_passive', True)
            }
        }
    
    async def run_command(self, command: List[str], timeout: int = 60, 
                         input_data: Optional[str] = None) -> ToolResult:
        """Run a command with proper error handling and timeout"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Create process
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                cwd=self.temp_dir
            )
            
            # Run with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input_data.encode() if input_data else None),
                    timeout=timeout
                )
                return_code = process.returncode
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                execution_time = asyncio.get_event_loop().time() - start_time
                return ToolResult(
                    tool_name=command[0],
                    success=False,
                    execution_time=execution_time,
                    data={},
                    error=f"Command timed out after {timeout} seconds"
                )
            
            execution_time = asyncio.get_event_loop().time() - start_time
            
            # Parse output
            stdout_str = stdout.decode('utf-8', errors='ignore')
            stderr_str = stderr.decode('utf-8', errors='ignore')
            
            success = return_code == 0
            
            return ToolResult(
                tool_name=command[0],
                success=success,
                execution_time=execution_time,
                data={'stdout': stdout_str, 'stderr': stderr_str, 'return_code': return_code},
                error=stderr_str if not success else None,
                raw_output=stdout_str
            )
            
        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            return ToolResult(
                tool_name=command[0] if command else 'unknown',
                success=False,
                execution_time=execution_time,
                data={},
                error=str(e)
            )

class SubfinderIntegration:
    """Integration with Subfinder for subdomain enumeration"""
    
    def __init__(self, manager: SecurityToolManager):
        self.manager = manager
        self.config = manager.tool_configs['subfinder']
        self.logger = logging.getLogger('subfinder')
    
    async def enumerate_subdomains(self, domain: str, 
                                 additional_sources: Optional[List[str]] = None) -> ToolResult:
        """Run subfinder to enumerate subdomains"""
        self.logger.info(f"🔍 Running Subfinder for domain: {domain}")
        
        # Build command
        command = [self.config['binary'], '-d', domain, '-silent', '-json']
        
        # Add sources
        sources = additional_sources or self.config['sources']
        if sources:
            command.extend(['-sources', ','.join(sources)])
        
        # Add threading
        command.extend(['-t', str(self.config['threads'])])
        
        # Add output format
        output_file = os.path.join(self.manager.temp_dir, f'subfinder_{domain}.json')
        command.extend(['-o', output_file])
        
        # Execute command
        result = await self.manager.run_command(command, timeout=self.config['timeout'])
        
        if result.success:
            # Parse subfinder output
            subdomains = []
            try:
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    data = json.loads(line)
                                    subdomains.append(data.get('host', line))
                                except json.JSONDecodeError:
                                    # Handle plain text output
                                    subdomains.append(line)
                
                result.data.update({
                    'subdomains': list(set(subdomains)),  # Remove duplicates
                    'subdomain_count': len(set(subdomains)),
                    'output_file': output_file
                })
                
                self.logger.info(f"✅ Subfinder found {len(set(subdomains))} subdomains for {domain}")
                
            except Exception as e:
                self.logger.error(f"❌ Error parsing Subfinder output: {e}")
                result.error = f"Output parsing error: {e}"
                result.success = False
        else:
            self.logger.error(f"❌ Subfinder execution failed: {result.error}")
        
        return result
    
    async def enumerate_from_list(self, domains: List[str]) -> Dict[str, ToolResult]:
        """Enumerate subdomains for multiple domains"""
        tasks = []
        for domain in domains:
            task = self.enumerate_subdomains(domain)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        domain_results = {}
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                domain_results[domains[i]] = ToolResult(
                    tool_name='subfinder',
                    success=False,
                    execution_time=0,
                    data={},
                    error=str(result)
                )
            else:
                domain_results[domains[i]] = result
        
        return domain_results

class HttpxIntegration:
    """Integration with Httpx for HTTP probing"""
    
    def __init__(self, manager: SecurityToolManager):
        self.manager = manager
        self.config = manager.tool_configs['httpx']
        self.logger = logging.getLogger('httpx')
    
    async def probe_hosts(self, hosts: List[str], ports: Optional[List[int]] = None) -> ToolResult:
        """Probe hosts for HTTP services"""
        self.logger.info(f"🌐 Running Httpx for {len(hosts)} hosts")
        
        # Create input file
        input_file = os.path.join(self.manager.temp_dir, 'httpx_input.txt')
        with open(input_file, 'w') as f:
            for host in hosts:
                f.write(f"{host}\n")
        
        # Build command
        command = [
            self.config['binary'],
            '-l', input_file,
            '-silent',
            '-json',
            '-threads', str(self.config['threads']),
            '-timeout', str(self.config['timeout'])
        ]
        
        # Add ports if specified
        if ports:
            port_str = ','.join(map(str, ports))
            command.extend(['-ports', port_str])
        
        # Add follow redirects
        if self.config['follow_redirects']:
            command.append('-follow-redirects')
        
        # Add additional probes
        command.extend([
            '-status-code',
            '-title',
            '-tech-detect',
            '-content-length'
        ])
        
        # Execute command
        result = await self.manager.run_command(command, timeout=self.config['timeout'])
        
        if result.success:
            # Parse httpx output
            live_hosts = []
            technologies = []
            
            try:
                if result.raw_output:
                    for line in result.raw_output.split('\n'):
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                
                                host_info = {
                                    'url': data.get('url'),
                                    'status_code': data.get('status_code'),
                                    'title': data.get('title'),
                                    'content_length': data.get('content_length'),
                                    'technologies': data.get('tech', [])
                                }
                                
                                live_hosts.append(host_info)
                                
                                # Collect technologies
                                if data.get('tech'):
                                    technologies.extend(data['tech'])
                                    
                            except json.JSONDecodeError:
                                # Handle simple URL output
                                if line.startswith('http'):
                                    live_hosts.append({'url': line})
                
                result.data.update({
                    'live_hosts': live_hosts,
                    'live_host_count': len(live_hosts),
                    'technologies': list(set(technologies)),
                    'technology_count': len(set(technologies))
                })
                
                self.logger.info(f"✅ Httpx found {len(live_hosts)} live hosts")
                
            except Exception as e:
                self.logger.error(f"❌ Error parsing Httpx output: {e}")
                result.error = f"Output parsing error: {e}"
                result.success = False
        else:
            self.logger.error(f"❌ Httpx execution failed: {result.error}")
        
        return result
    
    async def probe_single_host(self, host: str) -> ToolResult:
        """Probe a single host"""
        return await self.probe_hosts([host])

class NucleiIntegration:
    """Integration with Nuclei for vulnerability scanning"""
    
    def __init__(self, manager: SecurityToolManager):
        self.manager = manager
        self.config = manager.tool_configs['nuclei']
        self.logger = logging.getLogger('nuclei')
    
    async def scan_targets(self, targets: List[str], 
                          templates: Optional[List[str]] = None,
                          severity: Optional[List[str]] = None) -> ToolResult:
        """Run nuclei vulnerability scan"""
        self.logger.info(f"🎯 Running Nuclei scan for {len(targets)} targets")
        
        # Create targets file
        targets_file = os.path.join(self.manager.temp_dir, 'nuclei_targets.txt')
        with open(targets_file, 'w') as f:
            for target in targets:
                f.write(f"{target}\n")
        
        # Build command
        command = [
            self.config['binary'],
            '-l', targets_file,
            '-json',
            '-silent',
            '-rate-limit', str(self.config['rate_limit'])
        ]
        
        # Add templates
        if templates:
            template_str = ','.join(templates)
            command.extend(['-t', template_str])
        else:
            # Use default template directory
            if os.path.exists(self.config['templates_path']):
                command.extend(['-t', self.config['templates_path']])
        
        # Add severity filter
        if severity:
            severity_str = ','.join(severity)
            command.extend(['-severity', severity_str])
        
        # Add timeout
        command.extend(['-timeout', str(self.config['timeout'])])
        
        # Execute command
        result = await self.manager.run_command(command, timeout=self.config['timeout'])
        
        if result.success:
            # Parse nuclei output
            vulnerabilities = []
            
            try:
                if result.raw_output:
                    for line in result.raw_output.split('\n'):
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                
                                vuln = {
                                    'template_id': data.get('template-id'),
                                    'template_name': data.get('info', {}).get('name'),
                                    'severity': data.get('info', {}).get('severity'),
                                    'description': data.get('info', {}).get('description'),
                                    'url': data.get('matched-at'),
                                    'host': data.get('host'),
                                    'type': data.get('type'),
                                    'timestamp': data.get('timestamp'),
                                    'raw_data': data
                                }
                                
                                vulnerabilities.append(vuln)
                                
                            except json.JSONDecodeError:
                                continue
                
                # Categorize vulnerabilities by severity
                severity_count = {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
                for vuln in vulnerabilities:
                    sev = vuln.get('severity', 'info').lower()
                    if sev in severity_count:
                        severity_count[sev] += 1
                
                result.data.update({
                    'vulnerabilities': vulnerabilities,
                    'vulnerability_count': len(vulnerabilities),
                    'severity_breakdown': severity_count,
                    'high_critical_count': severity_count['high'] + severity_count['critical']
                })
                
                self.logger.info(f"✅ Nuclei found {len(vulnerabilities)} vulnerabilities")
                
            except Exception as e:
                self.logger.error(f"❌ Error parsing Nuclei output: {e}")
                result.error = f"Output parsing error: {e}"
                result.success = False
        else:
            self.logger.error(f"❌ Nuclei execution failed: {result.error}")
        
        return result
    
    async def update_templates(self) -> ToolResult:
        """Update Nuclei templates"""
        self.logger.info("🔄 Updating Nuclei templates")
        
        command = [self.config['binary'], '-update-templates']
        
        result = await self.manager.run_command(command, timeout=300)  # 5 minutes timeout
        
        if result.success:
            self.logger.info("✅ Nuclei templates updated successfully")
        else:
            self.logger.error(f"❌ Failed to update Nuclei templates: {result.error}")
        
        return result

class EnhancedSecurityToolsOrchestrator:
    """Orchestrator for running multiple security tools in sequence"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.manager = SecurityToolManager(config)
        self.subfinder = SubfinderIntegration(self.manager)
        self.httpx = HttpxIntegration(self.manager)
        self.nuclei = NucleiIntegration(self.manager)
        self.logger = logging.getLogger('security_orchestrator')
    
    async def comprehensive_scan(self, target_domain: str, 
                               scan_config: Optional[Dict] = None) -> Dict[str, ToolResult]:
        """Run comprehensive security scan using multiple tools"""
        scan_config = scan_config or {}
        results = {}
        
        self.logger.info(f"🚀 Starting comprehensive scan for {target_domain}")
        
        try:
            # Phase 1: Subdomain Enumeration
            self.logger.info("📡 Phase 1: Subdomain Enumeration")
            subfinder_result = await self.subfinder.enumerate_subdomains(target_domain)
            results['subfinder'] = subfinder_result
            
            # Get discovered subdomains
            subdomains = []
            if subfinder_result.success:
                subdomains = subfinder_result.data.get('subdomains', [])
                # Add the main domain if not present
                if target_domain not in subdomains:
                    subdomains.append(target_domain)
            else:
                # Fallback to main domain only
                subdomains = [target_domain]
            
            # Phase 2: HTTP Probing
            self.logger.info(f"🌐 Phase 2: HTTP Probing ({len(subdomains)} hosts)")
            httpx_result = await self.httpx.probe_hosts(subdomains)
            results['httpx'] = httpx_result
            
            # Get live hosts
            live_hosts = []
            if httpx_result.success:
                live_host_data = httpx_result.data.get('live_hosts', [])
                live_hosts = [host.get('url') for host in live_host_data if host.get('url')]
            
            if not live_hosts:
                # Fallback to basic HTTP/HTTPS for main domain
                live_hosts = [f"http://{target_domain}", f"https://{target_domain}"]
            
            # Phase 3: Vulnerability Scanning
            if scan_config.get('run_nuclei', True) and live_hosts:
                self.logger.info(f"🎯 Phase 3: Vulnerability Scanning ({len(live_hosts)} targets)")
                
                # Limit targets for nuclei to avoid excessive scanning
                max_nuclei_targets = scan_config.get('max_nuclei_targets', 20)
                nuclei_targets = live_hosts[:max_nuclei_targets]
                
                nuclei_result = await self.nuclei.scan_targets(
                    nuclei_targets,
                    templates=scan_config.get('nuclei_templates'),
                    severity=scan_config.get('nuclei_severity', ['medium', 'high', 'critical'])
                )
                results['nuclei'] = nuclei_result
            
            # Generate summary
            summary = self._generate_scan_summary(results)
            results['summary'] = ToolResult(
                tool_name='summary',
                success=True,
                execution_time=sum(r.execution_time for r in results.values()),
                data=summary
            )
            
            self.logger.info(f"✅ Comprehensive scan completed for {target_domain}")
            
        except Exception as e:
            self.logger.error(f"❌ Comprehensive scan failed: {e}")
            results['error'] = ToolResult(
                tool_name='orchestrator',
                success=False,
                execution_time=0,
                data={},
                error=str(e)
            )
        
        return results
    
    def _generate_scan_summary(self, results: Dict[str, ToolResult]) -> Dict[str, Any]:
        """Generate summary of scan results"""
        summary = {
            'total_execution_time': sum(r.execution_time for r in results.values()),
            'successful_tools': sum(1 for r in results.values() if r.success),
            'failed_tools': sum(1 for r in results.values() if not r.success),
            'subdomain_count': 0,
            'live_host_count': 0,
            'vulnerability_count': 0,
            'high_critical_vulns': 0
        }
        
        # Extract metrics from individual tools
        if 'subfinder' in results and results['subfinder'].success:
            summary['subdomain_count'] = results['subfinder'].data.get('subdomain_count', 0)
        
        if 'httpx' in results and results['httpx'].success:
            summary['live_host_count'] = results['httpx'].data.get('live_host_count', 0)
        
        if 'nuclei' in results and results['nuclei'].success:
            summary['vulnerability_count'] = results['nuclei'].data.get('vulnerability_count', 0)
            summary['high_critical_vulns'] = results['nuclei'].data.get('high_critical_count', 0)
        
        return summary
    
    async def cleanup(self):
        """Clean up temporary files"""
        try:
            import shutil
            if os.path.exists(self.manager.temp_dir):
                shutil.rmtree(self.manager.temp_dir)
                self.logger.info("🧹 Cleaned up temporary files")
        except Exception as e:
            self.logger.warning(f"⚠️  Cleanup warning: {e}")

# Global instance for easy access
security_tools = EnhancedSecurityToolsOrchestrator()

# Convenience functions
async def run_subfinder(domain: str) -> ToolResult:
    """Run subfinder for a domain"""
    return await security_tools.subfinder.enumerate_subdomains(domain)

async def run_httpx(hosts: List[str]) -> ToolResult:
    """Run httpx for hosts"""
    return await security_tools.httpx.probe_hosts(hosts)

async def run_nuclei(targets: List[str], severity: Optional[List[str]] = None) -> ToolResult:
    """Run nuclei for targets"""
    return await security_tools.nuclei.scan_targets(targets, severity=severity)

async def comprehensive_security_scan(domain: str, config: Optional[Dict] = None) -> Dict[str, ToolResult]:
    """Run comprehensive security scan"""
    return await security_tools.comprehensive_scan(domain, config)

if __name__ == "__main__":
    # Demo the real security tools integration
    async def demo():
        print("🚀 Real Security Tools Integration Demo")
        print("=" * 50)
        
        # Test domain (use a safe test domain)
        test_domain = "testfire.net"
        
        # Run comprehensive scan
        results = await comprehensive_security_scan(test_domain, {
            'run_nuclei': True,
            'max_nuclei_targets': 5,
            'nuclei_severity': ['medium', 'high']
        })
        
        # Display results
        for tool_name, result in results.items():
            print(f"\n{tool_name.upper()} Results:")
            print(f"Success: {result.success}")
            print(f"Execution Time: {result.execution_time:.2f}s")
            
            if result.success and result.data:
                if 'subdomains' in result.data:
                    print(f"Subdomains Found: {result.data['subdomain_count']}")
                if 'live_hosts' in result.data:
                    print(f"Live Hosts: {result.data['live_host_count']}")
                if 'vulnerabilities' in result.data:
                    print(f"Vulnerabilities: {result.data['vulnerability_count']}")
            
            if result.error:
                print(f"Error: {result.error}")
        
        # Cleanup
        await security_tools.cleanup()
    
    asyncio.run(demo())
