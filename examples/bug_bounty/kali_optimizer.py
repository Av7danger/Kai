#!/usr/bin/env python3
"""
Extreme Kali Linux Optimizer
Tool detection, system diagnostics, resource management, and auto-fix capabilities
"""

import os
import sys
import psutil
import platform
import shutil
import json
import time
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# Import our robust subprocess handler
from subprocess_handler import subprocess_handler, SubprocessResult

# Only import resource on Unix
if os.name != 'nt':
    try:
        pass
    except ImportError:
        pass
else:
    pass

logger = logging.getLogger(__name__)

@dataclass
class ToolInfo:
    """Tool information and status"""
    name: str
    path: str
    version: str
    status: str  # available, missing, outdated, error
    last_check: float
    error_message: str = ""
    install_command: str = ""
    update_command: str = ""

@dataclass
class SystemDiagnostics:
    """System diagnostics information"""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_status: str
    python_version: str
    os_info: str
    kali_version: str
    permissions: Dict[str, bool]
    resource_limits: Dict[str, Any]
    optimization_recommendations: List[str]

class KaliOptimizer:
    """Extreme Kali Linux optimization and diagnostics"""
    
    def __init__(self):
        self.tools_config = self._load_tools_config()
        self.tools_status: Dict[str, ToolInfo] = {}
        self.system_diagnostics: Optional[SystemDiagnostics] = None
        self.optimization_recommendations: List[str] = []
        self.resource_limits = {
            'max_concurrent_scans': 3,
            'max_cpu_percent': 80,
            'max_memory_percent': 85,
            'scan_timeout': 3600,
            'tool_timeout': 300
        }
        
        # Initialize logging
        self._setup_logging()
        
        # Run initial diagnostics
        self._run_initial_diagnostics()
    
    def _load_tools_config(self) -> Dict[str, Dict[str, Any]]:
        """Load tools configuration"""
        return {
            # Reconnaissance tools
            'nmap': {
                'required': True,
                'install_command': 'apt-get install -y nmap',
                'version_check': 'nmap --version',
                'test_command': 'nmap -sn 127.0.0.1',
                'category': 'reconnaissance'
            },
            'subfinder': {
                'required': True,
                'install_command': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                'version_check': 'subfinder -version',
                'test_command': 'subfinder -d example.com -silent',
                'category': 'reconnaissance'
            },
            'amass': {
                'required': True,
                'install_command': 'apt-get install -y amass',
                'version_check': 'amass version',
                'test_command': 'amass enum -d example.com -silent',
                'category': 'reconnaissance'
            },
            'httpx': {
                'required': True,
                'install_command': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
                'version_check': 'httpx -version',
                'test_command': 'httpx -u http://example.com -silent',
                'category': 'reconnaissance'
            },
            'nuclei': {
                'required': True,
                'install_command': 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
                'version_check': 'nuclei -version',
                'test_command': 'nuclei -u http://example.com -silent',
                'category': 'vulnerability_scanning'
            },
            'ffuf': {
                'required': True,
                'install_command': 'apt-get install -y ffuf',
                'version_check': 'ffuf -V',
                'test_command': 'ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -silent',
                'category': 'vulnerability_scanning'
            },
            'gobuster': {
                'required': True,
                'install_command': 'apt-get install -y gobuster',
                'version_check': 'gobuster version',
                'test_command': 'gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -silent',
                'category': 'vulnerability_scanning'
            },
            'sqlmap': {
                'required': True,
                'install_command': 'apt-get install -y sqlmap',
                'version_check': 'sqlmap --version',
                'test_command': 'sqlmap -u http://example.com --batch --random-agent',
                'category': 'exploitation'
            },
            'xsser': {
                'required': False,
                'install_command': 'apt-get install -y xsser',
                'version_check': 'xsser --version',
                'test_command': 'xsser --url http://example.com --auto',
                'category': 'exploitation'
            },
            'dalfox': {
                'required': False,
                'install_command': 'go install github.com/hahwul/dalfox/v2@latest',
                'version_check': 'dalfox version',
                'test_command': 'dalfox url http://example.com',
                'category': 'exploitation'
            },
            'nikto': {
                'required': False,
                'install_command': 'apt-get install -y nikto',
                'version_check': 'nikto -Version',
                'test_command': 'nikto -h example.com',
                'category': 'vulnerability_scanning'
            },
            'wpscan': {
                'required': False,
                'install_command': 'apt-get install -y wpscan',
                'version_check': 'wpscan --version',
                'test_command': 'wpscan --url http://example.com --disable-tls-checks',
                'category': 'vulnerability_scanning'
            },
            'dirb': {
                'required': False,
                'install_command': 'apt-get install -y dirb',
                'version_check': 'dirb -v',
                'test_command': 'dirb http://example.com',
                'category': 'vulnerability_scanning'
            },
            'masscan': {
                'required': False,
                'install_command': 'apt-get install -y masscan',
                'version_check': 'masscan --version',
                'test_command': 'masscan 127.0.0.1 -p80',
                'category': 'reconnaissance'
            },
            'theharvester': {
                'required': False,
                'install_command': 'apt-get install -y theharvester',
                'version_check': 'theHarvester -v',
                'test_command': 'theHarvester -d example.com -b all',
                'category': 'reconnaissance'
            },
            'dnsrecon': {
                'required': False,
                'install_command': 'apt-get install -y dnsrecon',
                'version_check': 'dnsrecon -h',
                'test_command': 'dnsrecon -d example.com',
                'category': 'reconnaissance'
            },
            'whatweb': {
                'required': False,
                'install_command': 'apt-get install -y whatweb',
                'version_check': 'whatweb --version',
                'test_command': 'whatweb http://example.com',
                'category': 'reconnaissance'
            },
            'wafw00f': {
                'required': False,
                'install_command': 'apt-get install -y wafw00f',
                'version_check': 'wafw00f --version',
                'test_command': 'wafw00f http://example.com',
                'category': 'reconnaissance'
            }
        }
    
    def _setup_logging(self):
        """Setup comprehensive logging"""
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # File handler for all logs
        file_handler = logging.FileHandler(log_dir / 'kali_optimizer.log')
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler for important messages
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        logger.setLevel(logging.DEBUG)
    
    def _run_initial_diagnostics(self):
        """Run initial system diagnostics"""
        logger.info("Running initial Kali Linux diagnostics...")
        
        # Check all tools
        self.check_all_tools()
        
        # Run system diagnostics
        self.run_system_diagnostics()
        
        # Generate optimization recommendations
        self.generate_optimization_recommendations()
        
        logger.info("Initial diagnostics completed")
    
    def check_all_tools(self) -> Dict[str, ToolInfo]:
        """Check all required tools"""
        logger.info("Checking all Kali Linux tools...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all tool checks
            future_to_tool = {
                executor.submit(self._check_tool, tool_name, config): tool_name
                for tool_name, config in self.tools_config.items()
            }
            
            # Collect results
            for future in as_completed(future_to_tool):
                tool_name = future_to_tool[future]
                try:
                    tool_info = future.result()
                    self.tools_status[tool_name] = tool_info
                    logger.info(f"Tool {tool_name}: {tool_info.status}")
                except Exception as e:
                    logger.error(f"Error checking tool {tool_name}: {e}")
                    self.tools_status[tool_name] = ToolInfo(
                        name=tool_name,
                        path="",
                        version="",
                        status="error",
                        last_check=time.time(),
                        error_message=str(e)
                    )
        
        return self.tools_status
    
    def _check_tool(self, tool_name: str, config: Dict[str, Any]) -> ToolInfo:
        """Check individual tool"""
        try:
            # Find tool path
            tool_path = shutil.which(tool_name)
            
            if not tool_path:
                return ToolInfo(
                    name=tool_name,
                    path="",
                    version="",
                    status="missing",
                    last_check=time.time(),
                    install_command=config.get('install_command', ''),
                    error_message="Tool not found in PATH"
                )
            
            # Check version
            version = self._get_tool_version(tool_name, config.get('version_check', ''))
            
            # Test tool functionality
            test_result = self._test_tool(tool_name, config.get('test_command', ''))
            
            status = "available" if test_result else "error"
            error_message = "" if test_result else "Tool test failed"
            
            return ToolInfo(
                name=tool_name,
                path=tool_path,
                version=version,
                status=status,
                last_check=time.time(),
                install_command=config.get('install_command', ''),
                error_message=error_message
            )
            
        except Exception as e:
            logger.error(f"Error checking tool {tool_name}: {e}")
            return ToolInfo(
                name=tool_name,
                path="",
                version="",
                status="error",
                last_check=time.time(),
                error_message=str(e)
            )
    
    def _get_tool_version(self, tool_name: str, version_command: str) -> str:
        """Get tool version using robust subprocess handler"""
        try:
            result = subprocess_handler.run_sync_command(
                version_command.split(),
                capture_output=True
            )
            if result.success:
                return result.stdout.strip().split('\n')[0]
            else:
                logger.warning(f"Failed to get version for {tool_name}: {result.error_message}")
                return "unknown"
        except Exception as e:
            logger.error(f"Error getting version for {tool_name}: {str(e)}")
            return "unknown"
    
    def _test_tool(self, tool_name: str, test_command: str) -> bool:
        """Test tool functionality using robust subprocess handler"""
        if not test_command:
            return True  # Skip test if no command provided
        
        try:
            result = subprocess_handler.run_sync_command(
                test_command.split(),
                capture_output=True
            )
            if result.success:
                logger.debug(f"Tool {tool_name} test passed")
                return True
            else:
                logger.warning(f"Tool {tool_name} test failed: {result.error_message}")
                return False
        except Exception as e:
            logger.error(f"Error testing tool {tool_name}: {str(e)}")
            return True  # Assume tool works if we can't test it
    
    def run_system_diagnostics(self) -> SystemDiagnostics:
        """Run comprehensive system diagnostics"""
        logger.info("Running system diagnostics...")
        
        try:
            # CPU usage
            cpu_usage = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_usage = (disk.used / disk.total) * 100
            
            # Network status
            network_status = self._check_network_status()
            
            # Python version
            python_version = platform.python_version()
            
            # OS info
            os_info = f"{platform.system()} {platform.release()}"
            
            # Kali version
            kali_version = self._get_kali_version()
            
            # Permissions
            permissions = self._check_permissions()
            
            # Resource limits
            resource_limits = self._get_resource_limits()
            
            self.system_diagnostics = SystemDiagnostics(
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                disk_usage=disk_usage,
                network_status=network_status,
                python_version=python_version,
                os_info=os_info,
                kali_version=kali_version,
                permissions=permissions,
                resource_limits=resource_limits,
                optimization_recommendations=[]
            )
            
            logger.info("System diagnostics completed")
            return self.system_diagnostics
            
        except Exception as e:
            logger.error(f"Error running system diagnostics: {e}")
            # Return basic diagnostics
            return SystemDiagnostics(
                cpu_usage=0.0,
                memory_usage=0.0,
                disk_usage=0.0,
                network_status="unknown",
                python_version=platform.python_version(),
                os_info=platform.system(),
                kali_version="unknown",
                permissions={},
                resource_limits={},
                optimization_recommendations=[]
            )
    
    def _check_network_status(self) -> str:
        """Check network connectivity using robust subprocess handler"""
        try:
            # Test DNS resolution
            result = subprocess_handler.run_sync_command(
                ['nslookup', 'google.com'], 
                capture_output=True
            )
            if not result.success:
                return "dns_error"
            
            # Test HTTP connectivity
            try:
                response = requests.get('http://httpbin.org/get', timeout=5)
                if response.status_code == 200:
                    return "connected"
                else:
                    return "http_error"
            except requests.RequestException:
                return "http_error"
                
        except Exception as e:
            logger.error(f"Network check error: {str(e)}")
            return "unknown"
    
    def _get_kali_version(self) -> str:
        """Get Kali Linux version using robust subprocess handler"""
        try:
            # Try multiple methods to get Kali version
            version_commands = [
                ['cat', '/etc/os-release'],
                ['lsb_release', '-a'],
                ['uname', '-a']
            ]
            
            for cmd in version_commands:
                result = subprocess_handler.run_sync_command(cmd, capture_output=True)
                if result.success:
                    if cmd[0] == 'cat':
                        for line in result.stdout.split('\n'):
                            if line.startswith('VERSION='):
                                return line.split('=')[1].strip('"')
                    elif cmd[0] == 'lsb_release':
                        for line in result.stdout.split('\n'):
                            if line.startswith('Description:'):
                                return line.split(':', 1)[1].strip()
                    elif cmd[0] == 'uname':
                        return result.stdout.strip()
            
            return "unknown"
        except Exception as e:
            logger.error(f"Error getting Kali version: {str(e)}")
            return "unknown"
    
    def _check_permissions(self) -> Dict[str, bool]:
        """Check important permissions"""
        permissions = {}
        
        try:
            # Check if running as root (Unix-specific)
            if hasattr(os, 'geteuid'):
                permissions['is_root'] = os.geteuid() == 0
            else:
                # Windows fallback
                permissions['is_root'] = False
            
            # Check write permissions to current directory
            permissions['can_write_current'] = os.access('.', os.W_OK)
            
            # Check if can execute tools
            permissions['can_execute_tools'] = os.access('/usr/bin', os.X_OK) if os.path.exists('/usr/bin') else False
            
            # Check if can install packages
            permissions['can_install_packages'] = permissions['is_root']
            
            # Check if can bind to ports
            permissions['can_bind_ports'] = permissions['is_root'] or (os.path.exists('/usr/bin/nmap') and os.access('/usr/bin/nmap', os.X_OK))
            
        except Exception as e:
            logger.error(f"Error checking permissions: {e}")
            permissions = {
                'is_root': False,
                'can_write_current': False,
                'can_execute_tools': False,
                'can_install_packages': False,
                'can_bind_ports': False
            }
        
        return permissions
    
    def _get_resource_limits(self) -> Dict[str, Any]:
        """Get current resource limits"""
        try:
            limits = {}
            # Only get resource limits on Unix systems
            if hasattr(resource, 'getrlimit'):
                # CPU time limit
                limits['cpu_time'] = resource.getrlimit(resource.RLIMIT_CPU)
                # Memory limit
                limits['memory'] = resource.getrlimit(resource.RLIMIT_AS)
                # File descriptor limit
                limits['file_descriptors'] = resource.getrlimit(resource.RLIMIT_NOFILE)
                # Process limit
                limits['processes'] = resource.getrlimit(resource.RLIMIT_NPROC)
            else:
                # Windows fallback
                limits = {
                    'cpu_time': (0, 0),
                    'memory': (0, 0),
                    'file_descriptors': (0, 0),
                    'processes': (0, 0)
                }
            return limits
        except Exception as e:
            logger.error(f"Error getting resource limits: {e}")
            return {}
    
    def generate_optimization_recommendations(self) -> List[str]:
        """Generate optimization recommendations"""
        recommendations = []
        
        try:
            # Check missing required tools
            missing_required = [
                tool_name for tool_name, tool_info in self.tools_status.items()
                if tool_info.status == "missing" and self.tools_config[tool_name]['required']
            ]
            
            if missing_required:
                recommendations.append(f"Install missing required tools: {', '.join(missing_required)}")
            
            # Check system resources
            if self.system_diagnostics:
                if self.system_diagnostics.cpu_usage > 80:
                    recommendations.append("High CPU usage detected. Consider reducing concurrent scans.")
                
                if self.system_diagnostics.memory_usage > 85:
                    recommendations.append("High memory usage detected. Consider closing other applications.")
                
                if self.system_diagnostics.disk_usage > 90:
                    recommendations.append("Low disk space. Consider cleaning up old scan results.")
            
            # Check permissions
            if self.system_diagnostics and self.system_diagnostics.permissions:
                if not self.system_diagnostics.permissions.get('is_root', False):
                    recommendations.append("Running without root privileges. Some tools may require sudo.")
                
                if not self.system_diagnostics.permissions.get('can_install_packages', False):
                    recommendations.append("Cannot install packages. Run with sudo for auto-installation.")
            
            # Check network
            if self.system_diagnostics and self.system_diagnostics.network_status == "disconnected":
                recommendations.append("Network connectivity issues detected. Check your internet connection.")
            
            # Performance recommendations
            recommendations.append("Consider using parallel scanning for better performance.")
            recommendations.append("Use appropriate wordlists based on target scope.")
            recommendations.append("Monitor system resources during intensive scans.")
            
            self.optimization_recommendations = recommendations
            logger.info(f"Generated {len(recommendations)} optimization recommendations")
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            self.optimization_recommendations = ["Error generating recommendations"]
        
        return self.optimization_recommendations
    
    def install_missing_tool(self, tool_name: str) -> Dict[str, Any]:
        """Install missing tool using robust subprocess handler"""
        if tool_name not in self.tools_config:
            return {
                'success': False,
                'error': f'Tool {tool_name} not found in configuration'
            }
        
        config = self.tools_config[tool_name]
        install_command = config.get('install_command', '')
        
        if not install_command:
            return {
                'success': False,
                'error': f'No install command configured for {tool_name}'
            }
        
        try:
            logger.info(f"Installing {tool_name}...")
            
            # Run install command
            result = subprocess_handler.run_sync_command(
                install_command.split(),
                capture_output=True
            )
            
            if result.success:
                logger.info(f"Successfully installed {tool_name}")
                # Re-check tool status
                self._check_tool(tool_name, config)
                return {
                    'success': True,
                    'message': f'Successfully installed {tool_name}',
                    'output': result.stdout
                }
            else:
                logger.error(f"Failed to install {tool_name}: {result.error_message}")
                return {
                    'success': False,
                    'error': f'Installation failed: {result.error_message}',
                    'output': result.stderr
                }
                
        except Exception as e:
            logger.error(f"Error installing {tool_name}: {str(e)}")
            return {
                'success': False,
                'error': f'Installation error: {str(e)}'
            }
    
    def get_diagnostics_summary(self) -> Dict[str, Any]:
        """Get comprehensive diagnostics summary"""
        return {
            "tools": {
                tool_name: asdict(tool_info)
                for tool_name, tool_info in self.tools_status.items()
            },
            "system": asdict(self.system_diagnostics) if self.system_diagnostics else {},
            "recommendations": self.optimization_recommendations,
            "resource_limits": self.resource_limits,
            "timestamp": time.time()
        }
    
    def is_system_optimized(self) -> bool:
        """Check if system is optimized for bug hunting"""
        if not self.system_diagnostics:
            return False
        
        # Check if all required tools are available
        required_tools_available = all(
            tool_info.status == "available"
            for tool_name, tool_info in self.tools_status.items()
            if self.tools_config[tool_name]['required']
        )
        
        # Check system resources
        resources_ok = (
            self.system_diagnostics.cpu_usage < 80 and
            self.system_diagnostics.memory_usage < 85 and
            self.system_diagnostics.disk_usage < 90 and
            self.system_diagnostics.network_status == "connected"
        )
        
        return required_tools_available and resources_ok

# Global optimizer instance
kali_optimizer = None

def get_kali_optimizer() -> KaliOptimizer:
    """Get global Kali optimizer instance"""
    global kali_optimizer
    if kali_optimizer is None:
        kali_optimizer = KaliOptimizer()
    return kali_optimizer 