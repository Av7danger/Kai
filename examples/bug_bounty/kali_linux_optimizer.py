#!/usr/bin/env python3
"""
🦈 Kali Linux Optimizer for Bug Bounty Framework
Specialized optimizations and tool management for Kali Linux environments

Features:
- Kali Linux system optimization
- Security tool installation and management
- Payload generation and management
- Penetration testing tool integration
- System hardening and configuration
"""

import os
import sys
import subprocess
import logging
import json
import yaml
import requests
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import shutil
import tarfile
import zipfile
from urllib.parse import urlparse
import threading
import time

logger = logging.getLogger(__name__)

@dataclass
class SecurityTool:
    """Security tool configuration"""
    name: str
    description: str
    category: str
    install_command: str
    update_command: str
    config_path: Optional[str] = None
    dependencies: List[str] = None
    payload_templates: List[str] = None
    enabled: bool = True

class KaliLinuxOptimizer:
    """Kali Linux system optimization and tool management"""
    
    def __init__(self, config_path: str = 'kali_config.yml'):
        self.config_path = config_path
        self.config = self._load_config()
        self.tools_dir = Path('kali_tools')
        self.payloads_dir = Path('payloads')
        self.wordlists_dir = Path('wordlists')
        self.scripts_dir = Path('scripts')
        
        # Create directories
        for directory in [self.tools_dir, self.payloads_dir, self.wordlists_dir, self.scripts_dir]:
            directory.mkdir(exist_ok=True)
        
        # Security tools registry
        self.security_tools = self._initialize_tools()
        
    def _load_config(self) -> Dict:
        """Load Kali Linux configuration"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default Kali Linux configuration"""
        return {
            'system': {
                'update_packages': True,
                'install_essentials': True,
                'configure_network': True,
                'harden_system': True
            },
            'tools': {
                'install_default_tools': True,
                'custom_tools': [],
                'update_frequency': 'weekly'
            },
            'payloads': {
                'enable_payload_generation': True,
                'payload_categories': ['web', 'network', 'mobile', 'social'],
                'custom_payloads': []
            },
            'wordlists': {
                'download_popular': True,
                'custom_wordlists': []
            },
            'scripts': {
                'enable_automation': True,
                'custom_scripts': []
            }
        }
    
    def _initialize_tools(self) -> Dict[str, SecurityTool]:
        """Initialize security tools registry"""
        tools = {
            # Web Application Testing
            'burpsuite': SecurityTool(
                name='Burp Suite',
                description='Web application security testing platform',
                category='web',
                install_command='apt-get install -y burpsuite',
                update_command='apt-get update && apt-get upgrade -y burpsuite',
                config_path='/usr/share/burpsuite/',
                dependencies=['java'],
                payload_templates=['xss', 'sqli', 'rce', 'ssrf']
            ),
            'owasp-zap': SecurityTool(
                name='OWASP ZAP',
                description='Web application security scanner',
                category='web',
                install_command='apt-get install -y zaproxy',
                update_command='apt-get update && apt-get upgrade -y zaproxy',
                config_path='/usr/share/zaproxy/',
                dependencies=['java'],
                payload_templates=['xss', 'sqli', 'rce', 'ssrf', 'xxe']
            ),
            'sqlmap': SecurityTool(
                name='SQLMap',
                description='SQL injection and database takeover tool',
                category='web',
                install_command='apt-get install -y sqlmap',
                update_command='apt-get update && apt-get upgrade -y sqlmap',
                config_path='/usr/share/sqlmap/',
                dependencies=['python3'],
                payload_templates=['sqli', 'blind_sqli', 'time_based_sqli']
            ),
            'nikto': SecurityTool(
                name='Nikto',
                description='Web server scanner',
                category='web',
                install_command='apt-get install -y nikto',
                update_command='apt-get update && apt-get upgrade -y nikto',
                config_path='/usr/share/nikto/',
                dependencies=['perl'],
                payload_templates=['web_scan', 'vulnerability_scan']
            ),
            
            # Network Testing
            'nmap': SecurityTool(
                name='Nmap',
                description='Network discovery and security auditing',
                category='network',
                install_command='apt-get install -y nmap',
                update_command='apt-get update && apt-get upgrade -y nmap',
                config_path='/usr/share/nmap/',
                dependencies=[],
                payload_templates=['port_scan', 'service_detection', 'os_detection']
            ),
            'masscan': SecurityTool(
                name='Masscan',
                description='Fast port scanner',
                category='network',
                install_command='apt-get install -y masscan',
                update_command='apt-get update && apt-get upgrade -y masscan',
                config_path='/usr/share/masscan/',
                dependencies=[],
                payload_templates=['port_scan', 'service_detection']
            ),
            'wireshark': SecurityTool(
                name='Wireshark',
                description='Network protocol analyzer',
                category='network',
                install_command='apt-get install -y wireshark',
                update_command='apt-get update && apt-get upgrade -y wireshark',
                config_path='/usr/share/wireshark/',
                dependencies=['libpcap'],
                payload_templates=['packet_analysis', 'traffic_capture']
            ),
            
            # Exploitation Tools
            'metasploit': SecurityTool(
                name='Metasploit Framework',
                description='Penetration testing framework',
                category='exploitation',
                install_command='apt-get install -y metasploit-framework',
                update_command='apt-get update && apt-get upgrade -y metasploit-framework',
                config_path='/usr/share/metasploit-framework/',
                dependencies=['ruby', 'postgresql'],
                payload_templates=['reverse_shell', 'bind_shell', 'meterpreter']
            ),
            'exploitdb': SecurityTool(
                name='Exploit Database',
                description='Database of exploits and vulnerable software',
                category='exploitation',
                install_command='apt-get install -y exploitdb',
                update_command='apt-get update && apt-get upgrade -y exploitdb',
                config_path='/usr/share/exploitdb/',
                dependencies=[],
                payload_templates=['exploit_search', 'vulnerability_search']
            ),
            
            # Password Attacks
            'hashcat': SecurityTool(
                name='Hashcat',
                description='Advanced password recovery',
                category='password',
                install_command='apt-get install -y hashcat',
                update_command='apt-get update && apt-get upgrade -y hashcat',
                config_path='/usr/share/hashcat/',
                dependencies=['ocl-icd-opencl-dev'],
                payload_templates=['hash_cracking', 'password_analysis']
            ),
            'john': SecurityTool(
                name='John the Ripper',
                description='Password cracker',
                category='password',
                install_command='apt-get install -y john',
                update_command='apt-get update && apt-get upgrade -y john',
                config_path='/usr/share/john/',
                dependencies=[],
                payload_templates=['hash_cracking', 'password_analysis']
            ),
            
            # Wireless Testing
            'aircrack-ng': SecurityTool(
                name='Aircrack-ng',
                description='Wireless network security suite',
                category='wireless',
                install_command='apt-get install -y aircrack-ng',
                update_command='apt-get update && apt-get upgrade -y aircrack-ng',
                config_path='/usr/share/aircrack-ng/',
                dependencies=['libpcap'],
                payload_templates=['wifi_audit', 'packet_capture']
            ),
            'reaver': SecurityTool(
                name='Reaver',
                description='WPS PIN recovery tool',
                category='wireless',
                install_command='apt-get install -y reaver',
                update_command='apt-get update && apt-get upgrade -y reaver',
                config_path='/usr/share/reaver/',
                dependencies=['aircrack-ng'],
                payload_templates=['wps_attack', 'pin_recovery']
            ),
            
            # Social Engineering
            'set': SecurityTool(
                name='Social Engineering Toolkit',
                description='Social engineering attack framework',
                category='social',
                install_command='apt-get install -y set',
                update_command='apt-get update && apt-get upgrade -y set',
                config_path='/usr/share/set/',
                dependencies=['python3'],
                payload_templates=['phishing', 'credential_harvesting']
            ),
            'beef': SecurityTool(
                name='BeEF',
                description='Browser exploitation framework',
                category='social',
                install_command='apt-get install -y beef-xss',
                update_command='apt-get update && apt-get upgrade -y beef-xss',
                config_path='/usr/share/beef-xss/',
                dependencies=['ruby'],
                payload_templates=['xss_hook', 'browser_exploitation']
            ),
            
            # Mobile Testing
            'apktool': SecurityTool(
                name='APKTool',
                description='Android APK reverse engineering',
                category='mobile',
                install_command='apt-get install -y apktool',
                update_command='apt-get update && apt-get upgrade -y apktool',
                config_path='/usr/share/apktool/',
                dependencies=['java'],
                payload_templates=['apk_analysis', 'reverse_engineering']
            ),
            'jadx': SecurityTool(
                name='JADX',
                description='Android APK decompiler',
                category='mobile',
                install_command='apt-get install -y jadx',
                update_command='apt-get update && apt-get upgrade -y jadx',
                config_path='/usr/share/jadx/',
                dependencies=['java'],
                payload_templates=['apk_decompilation', 'code_analysis']
            )
        }
        
        return tools
    
    def optimize_system(self):
        """Optimize Kali Linux system for bug bounty work"""
        logger.info("Starting Kali Linux system optimization...")
        
        try:
            # Update system packages
            if self.config['system']['update_packages']:
                self._update_system_packages()
            
            # Install essential packages
            if self.config['system']['install_essentials']:
                self._install_essential_packages()
            
            # Configure network
            if self.config['system']['configure_network']:
                self._configure_network()
            
            # Harden system
            if self.config['system']['harden_system']:
                self._harden_system()
            
            logger.info("Kali Linux system optimization completed")
            
        except Exception as e:
            logger.error(f"System optimization failed: {e}")
            raise
    
    def _update_system_packages(self):
        """Update system packages"""
        logger.info("Updating system packages...")
        
        commands = [
            'apt-get update',
            'apt-get upgrade -y',
            'apt-get dist-upgrade -y',
            'apt-get autoremove -y',
            'apt-get autoclean'
        ]
        
        for command in commands:
            subprocess.run(command.split(), check=True)
    
    def _install_essential_packages(self):
        """Install essential packages for bug bounty work"""
        logger.info("Installing essential packages...")
        
        essential_packages = [
            'git', 'curl', 'wget', 'vim', 'nano', 'tmux', 'htop',
            'python3-pip', 'python3-venv', 'ruby', 'nodejs', 'npm',
            'docker.io', 'docker-compose', 'virtualbox', 'vagrant',
            'build-essential', 'cmake', 'pkg-config', 'libssl-dev',
            'libffi-dev', 'python3-dev', 'libxml2-dev', 'libxslt1-dev',
            'zlib1g-dev', 'libjpeg-dev', 'libpng-dev', 'libfreetype6-dev',
            'libsqlite3-dev', 'libreadline-dev', 'libncurses5-dev',
            'libbz2-dev', 'liblzma-dev', 'libgdbm-dev', 'libnss3-dev'
        ]
        
        for package in essential_packages:
            try:
                subprocess.run(['apt-get', 'install', '-y', package], check=True)
                logger.info(f"Installed: {package}")
            except subprocess.CalledProcessError:
                logger.warning(f"Failed to install: {package}")
    
    def _configure_network(self):
        """Configure network for penetration testing"""
        logger.info("Configuring network...")
        
        # Configure network interfaces
        network_config = """
# Network configuration for penetration testing
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
    post-up iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

auto wlan0
iface wlan0 inet dhcp
    wireless-essid "Kali"
    wireless-mode managed
"""
        
        with open('/etc/network/interfaces', 'w') as f:
            f.write(network_config)
    
    def _harden_system(self):
        """Harden system security"""
        logger.info("Hardening system security...")
        
        # Configure firewall
        firewall_rules = [
            'iptables -F',
            'iptables -X',
            'iptables -t nat -F',
            'iptables -t nat -X',
            'iptables -t mangle -F',
            'iptables -t mangle -X',
            'iptables -P INPUT DROP',
            'iptables -P FORWARD DROP',
            'iptables -P OUTPUT ACCEPT',
            'iptables -A INPUT -i lo -j ACCEPT',
            'iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT',
            'iptables -A INPUT -p tcp --dport 22 -j ACCEPT',
            'iptables -A INPUT -p tcp --dport 80 -j ACCEPT',
            'iptables -A INPUT -p tcp --dport 443 -j ACCEPT'
        ]
        
        for rule in firewall_rules:
            subprocess.run(rule.split(), check=True)
        
        # Save firewall rules
        subprocess.run(['iptables-save', '>', '/etc/iptables/rules.v4'], shell=True)
    
    def install_security_tools(self, tools: List[str] = None):
        """Install security tools"""
        logger.info("Installing security tools...")
        
        if tools is None:
            tools = list(self.security_tools.keys())
        
        for tool_name in tools:
            if tool_name in self.security_tools:
                tool = self.security_tools[tool_name]
                if tool.enabled:
                    try:
                        self._install_tool(tool)
                    except Exception as e:
                        logger.error(f"Failed to install {tool_name}: {e}")
    
    def _install_tool(self, tool: SecurityTool):
        """Install a specific security tool"""
        logger.info(f"Installing {tool.name}...")
        
        # Install dependencies
        if tool.dependencies:
            for dep in tool.dependencies:
                try:
                    subprocess.run(['apt-get', 'install', '-y', dep], check=True)
                except subprocess.CalledProcessError:
                    logger.warning(f"Failed to install dependency: {dep}")
        
        # Install tool
        try:
            subprocess.run(tool.install_command.split(), check=True)
            logger.info(f"Successfully installed {tool.name}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install {tool.name}: {e}")
            raise
    
    def update_tools(self):
        """Update all installed security tools"""
        logger.info("Updating security tools...")
        
        for tool_name, tool in self.security_tools.items():
            if tool.enabled and tool.update_command:
                try:
                    subprocess.run(tool.update_command.split(), check=True)
                    logger.info(f"Updated {tool.name}")
                except subprocess.CalledProcessError:
                    logger.warning(f"Failed to update {tool.name}")
    
    def get_tool_status(self) -> Dict:
        """Get status of all security tools"""
        status = {}
        
        for tool_name, tool in self.security_tools.items():
            try:
                # Check if tool is installed
                result = subprocess.run(['which', tool_name], capture_output=True, text=True)
                installed = result.returncode == 0
                
                # Get version if installed
                version = None
                if installed:
                    try:
                        version_result = subprocess.run([tool_name, '--version'], 
                                                      capture_output=True, text=True)
                        version = version_result.stdout.strip().split('\n')[0]
                    except:
                        version = "Installed"
                
                status[tool_name] = {
                    'installed': installed,
                    'version': version,
                    'category': tool.category,
                    'description': tool.description
                }
                
            except Exception as e:
                status[tool_name] = {
                    'installed': False,
                    'version': None,
                    'category': tool.category,
                    'description': tool.description,
                    'error': str(e)
                }
        
        return status
    
    def create_tool_shortcuts(self):
        """Create desktop shortcuts for security tools"""
        logger.info("Creating tool shortcuts...")
        
        desktop_dir = Path.home() / 'Desktop'
        shortcuts_dir = desktop_dir / 'Security Tools'
        shortcuts_dir.mkdir(exist_ok=True)
        
        for tool_name, tool in self.security_tools.items():
            if tool.enabled:
                shortcut_path = shortcuts_dir / f"{tool.name}.desktop"
                
                shortcut_content = f"""[Desktop Entry]
Version=1.0
Type=Application
Name={tool.name}
Comment={tool.description}
Exec={tool_name}
Icon=applications-system
Terminal=true
Categories=Security;PenetrationTesting;
"""
                
                with open(shortcut_path, 'w') as f:
                    f.write(shortcut_content)
                
                # Make executable
                os.chmod(shortcut_path, 0o755)
    
    def optimize_performance(self):
        """Optimize system performance for security testing"""
        logger.info("Optimizing system performance...")
        
        # Configure system limits
        limits_config = """
# Security testing performance limits
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
root soft nofile 65536
root hard nofile 65536
"""
        
        with open('/etc/security/limits.conf', 'a') as f:
            f.write(limits_config)
        
        # Configure sysctl for better performance
        sysctl_config = """
# Network performance
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1

# Security settings
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
"""
        
        with open('/etc/sysctl.conf', 'a') as f:
            f.write(sysctl_config)
        
        # Apply sysctl changes
        subprocess.run(['sysctl', '-p'], check=True)
    
    def create_workspace(self):
        """Create organized workspace for bug bounty work"""
        logger.info("Creating organized workspace...")
        
        workspace_dirs = [
            'workspace',
            'workspace/targets',
            'workspace/reports',
            'workspace/evidence',
            'workspace/scripts',
            'workspace/wordlists',
            'workspace/payloads',
            'workspace/screenshots',
            'workspace/notes'
        ]
        
        for directory in workspace_dirs:
            Path(directory).mkdir(parents=True, exist_ok=True)
        
        # Create workspace configuration
        workspace_config = {
            'workspace_path': str(Path.cwd() / 'workspace'),
            'targets_dir': 'targets',
            'reports_dir': 'reports',
            'evidence_dir': 'evidence',
            'scripts_dir': 'scripts',
            'wordlists_dir': 'wordlists',
            'payloads_dir': 'payloads',
            'screenshots_dir': 'screenshots',
            'notes_dir': 'notes'
        }
        
        with open('workspace/config.json', 'w') as f:
            json.dump(workspace_config, f, indent=2)
    
    def get_system_info(self) -> Dict:
        """Get comprehensive system information"""
        info = {
            'system': {
                'os': self._get_os_info(),
                'kernel': self._get_kernel_info(),
                'cpu': self._get_cpu_info(),
                'memory': self._get_memory_info(),
                'disk': self._get_disk_info(),
                'network': self._get_network_info()
            },
            'tools': self.get_tool_status(),
            'workspace': {
                'path': str(Path.cwd() / 'workspace'),
                'exists': (Path.cwd() / 'workspace').exists()
            }
        }
        
        return info
    
    def _get_os_info(self) -> Dict:
        """Get OS information"""
        try:
            with open('/etc/os-release', 'r') as f:
                lines = f.readlines()
                os_info = {}
                for line in lines:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_info[key] = value.strip('"')
                return os_info
        except:
            return {'error': 'Could not read OS info'}
    
    def _get_kernel_info(self) -> str:
        """Get kernel information"""
        try:
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return 'Unknown'
    
    def _get_cpu_info(self) -> Dict:
        """Get CPU information"""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                lines = f.readlines()
                cpu_info = {}
                for line in lines:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        cpu_info[key.strip()] = value.strip()
                return cpu_info
        except:
            return {'error': 'Could not read CPU info'}
    
    def _get_memory_info(self) -> Dict:
        """Get memory information"""
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                memory_info = {}
                for line in lines:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        memory_info[key.strip()] = value.strip()
                return memory_info
        except:
            return {'error': 'Could not read memory info'}
    
    def _get_disk_info(self) -> Dict:
        """Get disk information"""
        try:
            result = subprocess.run(['df', '-h'], capture_output=True, text=True)
            return {'df_output': result.stdout}
        except:
            return {'error': 'Could not read disk info'}
    
    def _get_network_info(self) -> Dict:
        """Get network information"""
        try:
            result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
            return {'ip_addr': result.stdout}
        except:
            return {'error': 'Could not read network info'}

# Global optimizer instance
kali_optimizer = None

def initialize_kali_optimizer(config_path: str = 'kali_config.yml'):
    """Initialize the global Kali Linux optimizer"""
    global kali_optimizer
    kali_optimizer = KaliLinuxOptimizer(config_path)
    return kali_optimizer

def get_kali_optimizer() -> KaliLinuxOptimizer:
    """Get the global Kali Linux optimizer instance"""
    if kali_optimizer is None:
        raise RuntimeError("Kali optimizer not initialized. Call initialize_kali_optimizer() first.")
    return kali_optimizer 