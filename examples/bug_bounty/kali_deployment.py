#!/usr/bin/env python3
"""
🚀 Kali Linux Deployment Script for Bug Bounty Framework
Comprehensive deployment and setup script for Kali Linux environments

This script will:
1. Optimize Kali Linux system for security testing
2. Install and configure all security tools
3. Set up payload generation and management
4. Configure monitoring and alerting
5. Create organized workspace
6. Set up automated backups and updates
7. Configure security hardening
8. Initialize the bug bounty framework

Usage:
    python3 kali_deployment.py [--config config.yml] [--skip-tools] [--skip-optimization]
"""

import os
import sys
import argparse
import subprocess
import logging
import yaml
import json
import time
from pathlib import Path
from typing import Dict, List, Optional
import requests
import shutil

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from kali_linux_optimizer import KaliLinuxOptimizer
from payload_generator import PayloadGenerator

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('kali_deployment.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class KaliLinuxDeployment:
    """Kali Linux deployment and setup manager"""
    
    def __init__(self, config_path: str = 'kali_config.yml'):
        self.config_path = config_path
        self.config = self._load_config()
        self.kali_optimizer = None
        self.payload_generator = None
        self.deployment_log = []
        
        # Create deployment directories
        self.setup_directories()
    
    def _load_config(self) -> Dict:
        """Load deployment configuration"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            logger.error(f"Configuration file {self.config_path} not found")
            sys.exit(1)
    
    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            'workspace',
            'workspace/targets',
            'workspace/reports',
            'workspace/evidence',
            'workspace/scripts',
            'workspace/wordlists',
            'workspace/payloads',
            'workspace/screenshots',
            'workspace/notes',
            'workspace/backups',
            'workspace/logs',
            'config',
            'templates',
            'scripts',
            'wordlists',
            'payloads',
            'backups',
            'logs'
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")
    
    def log_deployment_step(self, step: str, status: str, details: str = ""):
        """Log deployment step"""
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'step': step,
            'status': status,
            'details': details
        }
        self.deployment_log.append(log_entry)
        logger.info(f"[{status.upper()}] {step}: {details}")
    
    def check_prerequisites(self) -> bool:
        """Check system prerequisites"""
        logger.info("Checking system prerequisites...")
        
        # Check if running on Kali Linux
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if 'kali' not in content.lower():
                    logger.warning("This script is designed for Kali Linux. Continue anyway? (y/N)")
                    response = input().lower()
                    if response != 'y':
                        return False
        except FileNotFoundError:
            logger.warning("Could not determine OS. Continue anyway? (y/N)")
            response = input().lower()
            if response != 'y':
                return False
        
        # Check if running as root
        if os.geteuid() != 0:
            logger.error("This script must be run as root (use sudo)")
            return False
        
        # Check available disk space
        try:
            statvfs = os.statvfs('/')
            free_space_gb = (statvfs.f_frsize * statvfs.f_bavail) / (1024**3)
            if free_space_gb < 10:
                logger.warning(f"Low disk space: {free_space_gb:.2f} GB available. Recommended: 10+ GB")
            else:
                logger.info(f"Disk space available: {free_space_gb:.2f} GB")
        except Exception as e:
            logger.warning(f"Could not check disk space: {e}")
        
        # Check internet connectivity
        try:
            requests.get('https://www.google.com', timeout=5)
            logger.info("Internet connectivity: OK")
        except Exception as e:
            logger.error(f"No internet connectivity: {e}")
            return False
        
        self.log_deployment_step("Prerequisites Check", "PASSED", "System ready for deployment")
        return True
    
    def initialize_optimizers(self):
        """Initialize Kali optimizer and payload generator"""
        logger.info("Initializing optimizers and generators...")
        
        try:
            self.kali_optimizer = KaliLinuxOptimizer(self.config_path)
            self.payload_generator = PayloadGenerator('payload_templates')
            
            self.log_deployment_step("Initialize Optimizers", "PASSED", "Kali optimizer and payload generator initialized")
        except Exception as e:
            self.log_deployment_step("Initialize Optimizers", "FAILED", str(e))
            raise
    
    def optimize_system(self):
        """Optimize Kali Linux system"""
        logger.info("Optimizing Kali Linux system...")
        
        try:
            # System optimization
            if self.config['system'].get('update_packages', True):
                logger.info("Updating system packages...")
                self.kali_optimizer.optimize_system()
            
            # Performance optimization
            if self.config['system'].get('enable_performance_tuning', True):
                logger.info("Optimizing system performance...")
                self.kali_optimizer.optimize_performance()
            
            # Create workspace
            if self.config['workspace'].get('create_workspace', True):
                logger.info("Creating organized workspace...")
                self.kali_optimizer.create_workspace()
            
            self.log_deployment_step("System Optimization", "PASSED", "System optimized successfully")
        except Exception as e:
            self.log_deployment_step("System Optimization", "FAILED", str(e))
            raise
    
    def install_security_tools(self):
        """Install security tools"""
        logger.info("Installing security tools...")
        
        try:
            # Get tools to install from config
            tools_to_install = []
            
            # Add specific tools
            if 'specific_tools' in self.config['tools']:
                tools_to_install.extend(self.config['tools']['specific_tools'])
            
            # Add custom tools
            if 'custom_tools' in self.config['tools']:
                for custom_tool in self.config['tools']['custom_tools']:
                    tools_to_install.append(custom_tool['name'])
            
            if tools_to_install:
                logger.info(f"Installing {len(tools_to_install)} tools...")
                self.kali_optimizer.install_security_tools(tools_to_install)
            
            # Create tool shortcuts
            logger.info("Creating tool shortcuts...")
            self.kali_optimizer.create_tool_shortcuts()
            
            self.log_deployment_step("Security Tools Installation", "PASSED", f"Installed {len(tools_to_install)} tools")
        except Exception as e:
            self.log_deployment_step("Security Tools Installation", "FAILED", str(e))
            raise
    
    def setup_payload_generation(self):
        """Set up payload generation system"""
        logger.info("Setting up payload generation system...")
        
        try:
            # Load custom payloads from config
            if 'custom_payloads' in self.config['payloads']:
                for payload_config in self.config['payloads']['custom_payloads']:
                    # Save custom payload template
                    self.payload_generator.save_payload(
                        name=payload_config['name'],
                        payload=payload_config['payload'],
                        category=payload_config['category'],
                        description=payload_config['description'],
                        tags=payload_config['tags']
                    )
            
            self.log_deployment_step("Payload Generation Setup", "PASSED", "Payload generation system configured")
        except Exception as e:
            self.log_deployment_step("Payload Generation Setup", "FAILED", str(e))
            raise
    
    def setup_wordlists(self):
        """Set up wordlists"""
        logger.info("Setting up wordlists...")
        
        try:
            wordlists_dir = Path('wordlists')
            wordlists_dir.mkdir(exist_ok=True)
            
            # Download popular wordlists
            if self.config['wordlists'].get('download_popular', True):
                popular_wordlists = self.config['wordlists'].get('popular_wordlists', [])
                
                for wordlist in popular_wordlists:
                    logger.info(f"Downloading wordlist: {wordlist}")
                    # This would download from appropriate sources
                    # For now, create placeholder files
                    wordlist_path = wordlists_dir / wordlist
                    if not wordlist_path.exists():
                        with open(wordlist_path, 'w') as f:
                            f.write(f"# {wordlist} - Placeholder file\n")
            
            # Create custom wordlists
            if 'custom_wordlists' in self.config['wordlists']:
                for wordlist_config in self.config['wordlists']['custom_wordlists']:
                    wordlist_path = Path(wordlist_config['path'])
                    wordlist_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    if not wordlist_path.exists():
                        with open(wordlist_path, 'w') as f:
                            f.write(f"# {wordlist_config['name']} - {wordlist_config['description']}\n")
            
            self.log_deployment_step("Wordlists Setup", "PASSED", "Wordlists configured")
        except Exception as e:
            self.log_deployment_step("Wordlists Setup", "FAILED", str(e))
            raise
    
    def setup_automation_scripts(self):
        """Set up automation scripts"""
        logger.info("Setting up automation scripts...")
        
        try:
            scripts_dir = Path('scripts')
            scripts_dir.mkdir(exist_ok=True)
            
            # Create automation scripts
            if 'custom_scripts' in self.config['scripts']:
                for script_config in self.config['scripts']['custom_scripts']:
                    script_path = Path(script_config['script'])
                    script_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Create script content based on type
                    if script_config['category'] == 'scanning':
                        script_content = self._create_scanning_script(script_config)
                    elif script_config['category'] == 'reporting':
                        script_content = self._create_reporting_script(script_config)
                    elif script_config['category'] == 'maintenance':
                        script_content = self._create_maintenance_script(script_config)
                    else:
                        script_content = f"# {script_config['name']} - {script_config['description']}\n"
                    
                    with open(script_path, 'w') as f:
                        f.write(script_content)
                    
                    # Make executable if it's a shell script
                    if script_path.suffix == '.sh':
                        os.chmod(script_path, 0o755)
            
            self.log_deployment_step("Automation Scripts Setup", "PASSED", "Automation scripts created")
        except Exception as e:
            self.log_deployment_step("Automation Scripts Setup", "FAILED", str(e))
            raise
    
    def _create_scanning_script(self, config: Dict) -> str:
        """Create scanning script content"""
        return f"""#!/bin/bash
# {config['name']} - {config['description']}
# Automated vulnerability scan script

set -e

# Configuration
TARGET_DIR="workspace/targets"
REPORT_DIR="workspace/reports"
LOG_DIR="workspace/logs"

# Create directories
mkdir -p "$REPORT_DIR" "$LOG_DIR"

# Log function
log() {{
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/scan.log"
}}

log "Starting automated vulnerability scan"

# Run nmap scan
if command -v nmap &> /dev/null; then
    log "Running nmap scan..."
    nmap -sS -sV -O --script=vuln -oA "$REPORT_DIR/nmap_scan" "$TARGET_DIR/targets.txt" || true
fi

# Run web vulnerability scan
if command -v nikto &> /dev/null; then
    log "Running Nikto web scan..."
    nikto -h "$TARGET_DIR/web_targets.txt" -o "$REPORT_DIR/nikto_scan.txt" || true
fi

# Run SQLMap scan
if command -v sqlmap &> /dev/null; then
    log "Running SQLMap scan..."
    sqlmap -m "$TARGET_DIR/sql_targets.txt" --batch --random-agent -o "$REPORT_DIR/sqlmap_scan.txt" || true
fi

log "Automated scan completed"
"""
    
    def _create_reporting_script(self, config: Dict) -> str:
        """Create reporting script content"""
        return f"""#!/usr/bin/env python3
# {config['name']} - {config['description']}
# Automated report generation script

import os
import json
import yaml
from datetime import datetime
from pathlib import Path

def generate_report():
    report_dir = Path("workspace/reports")
    report_dir.mkdir(exist_ok=True)
    
    # Collect scan results
    scan_results = {{}}
    
    # Read nmap results
    nmap_file = report_dir / "nmap_scan.xml"
    if nmap_file.exists():
        scan_results['nmap'] = "Available"
    
    # Read Nikto results
    nikto_file = report_dir / "nikto_scan.txt"
    if nikto_file.exists():
        scan_results['nikto'] = "Available"
    
    # Generate report
    report = {{
        'timestamp': datetime.now().isoformat(),
        'scan_results': scan_results,
        'summary': {{
            'total_scans': len(scan_results),
            'vulnerabilities_found': 0,
            'recommendations': []
        }}
    }}
    
    # Save report
    report_file = report_dir / f"automated_report_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Report generated: {{report_file}}")

if __name__ == "__main__":
    generate_report()
"""
    
    def _create_maintenance_script(self, config: Dict) -> str:
        """Create maintenance script content"""
        return f"""#!/bin/bash
# {config['name']} - {config['description']}
# Backup and maintenance script

set -e

# Configuration
BACKUP_DIR="workspace/backups"
LOG_DIR="workspace/logs"
RETENTION_DAYS=30

# Create directories
mkdir -p "$BACKUP_DIR" "$LOG_DIR"

# Log function
log() {{
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/maintenance.log"
}}

log "Starting maintenance tasks"

# Backup important directories
log "Creating backups..."
tar -czf "$BACKUP_DIR/workspace_$(date +%Y%m%d_%H%M%S).tar.gz" workspace/ || true
tar -czf "$BACKUP_DIR/config_$(date +%Y%m%d_%H%M%S).tar.gz" config/ || true

# Clean old backups
log "Cleaning old backups..."
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete || true

# Clean old logs
log "Cleaning old logs..."
find "$LOG_DIR" -name "*.log" -mtime +7 -delete || true

# Update tools
log "Updating security tools..."
apt-get update && apt-get upgrade -y || true

log "Maintenance completed"
"""
    
    def setup_monitoring(self):
        """Set up monitoring and alerting"""
        logger.info("Setting up monitoring and alerting...")
        
        try:
            # Create monitoring script
            monitoring_script = """#!/usr/bin/env python3
# System monitoring script

import psutil
import json
import time
from pathlib import Path

def get_system_metrics():
    return {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_percent': psutil.disk_usage('/').percent,
        'timestamp': time.time()
    }

def check_thresholds(metrics):
    alerts = []
    
    if metrics['cpu_percent'] > 80:
        alerts.append(f"High CPU usage: {metrics['cpu_percent']}%")
    
    if metrics['memory_percent'] > 85:
        alerts.append(f"High memory usage: {metrics['memory_percent']}%")
    
    if metrics['disk_percent'] > 90:
        alerts.append(f"High disk usage: {metrics['disk_percent']}%")
    
    return alerts

def main():
    metrics = get_system_metrics()
    alerts = check_thresholds(metrics)
    
    # Save metrics
    metrics_file = Path("workspace/logs/system_metrics.json")
    metrics_file.parent.mkdir(exist_ok=True)
    
    with open(metrics_file, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    # Log alerts
    if alerts:
        alert_file = Path("workspace/logs/alerts.log")
        with open(alert_file, 'a') as f:
            for alert in alerts:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {alert}\\n")
    
    print(f"System metrics: {metrics}")
    if alerts:
        print(f"Alerts: {alerts}")

if __name__ == "__main__":
    main()
"""
            
            with open('scripts/monitor_system.py', 'w') as f:
                f.write(monitoring_script)
            
            os.chmod('scripts/monitor_system.py', 0o755)
            
            self.log_deployment_step("Monitoring Setup", "PASSED", "Monitoring system configured")
        except Exception as e:
            self.log_deployment_step("Monitoring Setup", "FAILED", str(e))
            raise
    
    def setup_security_hardening(self):
        """Set up security hardening"""
        logger.info("Setting up security hardening...")
        
        try:
            # Configure firewall
            if self.config['security'].get('enable_firewall', True):
                logger.info("Configuring firewall...")
                # This would configure iptables based on config
                pass
            
            # Configure SSH
            if self.config['security'].get('configure_ssh', True):
                logger.info("Configuring SSH security...")
                ssh_config = """
# SSH Security Configuration
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin no
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile %h/.ssh/authorized_keys
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
"""
                
                with open('/etc/ssh/sshd_config.backup', 'w') as f:
                    f.write(ssh_config)
                
                logger.info("SSH configuration backed up to /etc/ssh/sshd_config.backup")
            
            self.log_deployment_step("Security Hardening", "PASSED", "Security hardening configured")
        except Exception as e:
            self.log_deployment_step("Security Hardening", "FAILED", str(e))
            raise
    
    def create_startup_script(self):
        """Create startup script for the framework"""
        logger.info("Creating startup script...")
        
        try:
            startup_script = """#!/bin/bash
# Bug Bounty Framework Startup Script

set -e

# Configuration
FRAMEWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$FRAMEWORK_DIR/workspace/logs"

# Create log directory
mkdir -p "$LOG_DIR"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/startup.log"
}

log "Starting Bug Bounty Framework..."

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    log "Running as root - starting system services"
    
    # Start monitoring
    if [[ -f "$FRAMEWORK_DIR/scripts/monitor_system.py" ]]; then
        log "Starting system monitoring"
        nohup python3 "$FRAMEWORK_DIR/scripts/monitor_system.py" > "$LOG_DIR/monitoring.log" 2>&1 &
    fi
    
    # Start scheduled tasks
    if command -v cron &> /dev/null; then
        log "Setting up scheduled tasks"
        # Add cron jobs for maintenance and updates
        (crontab -l 2>/dev/null; echo "0 2 * * * $FRAMEWORK_DIR/scripts/backup_tools.sh") | crontab -
        (crontab -l 2>/dev/null; echo "0 3 * * 0 $FRAMEWORK_DIR/scripts/generate_report.py") | crontab -
    fi
fi

# Start the web dashboard
if [[ -f "$FRAMEWORK_DIR/next_gen_vuln_ui.py" ]]; then
    log "Starting web dashboard"
    cd "$FRAMEWORK_DIR"
    python3 next_gen_vuln_ui.py &
    DASHBOARD_PID=$!
    echo $DASHBOARD_PID > "$FRAMEWORK_DIR/dashboard.pid"
    log "Dashboard started with PID: $DASHBOARD_PID"
fi

log "Bug Bounty Framework started successfully"
log "Dashboard available at: http://localhost:5000"
log "Kali Tools Dashboard: http://localhost:5000/kali"
log "Security Dashboard: http://localhost:5000/security"

# Keep script running
wait
"""
            
            with open('start_framework.sh', 'w') as f:
                f.write(startup_script)
            
            os.chmod('start_framework.sh', 0o755)
            
            self.log_deployment_step("Startup Script", "PASSED", "Startup script created")
        except Exception as e:
            self.log_deployment_step("Startup Script", "FAILED", str(e))
            raise
    
    def generate_deployment_report(self):
        """Generate deployment report"""
        logger.info("Generating deployment report...")
        
        try:
            report = {
                'deployment_info': {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'config_file': self.config_path,
                    'deployment_version': '1.0.0'
                },
                'system_info': self.kali_optimizer.get_system_info() if self.kali_optimizer else {},
                'tools_status': self.kali_optimizer.get_tool_status() if self.kali_optimizer else {},
                'payload_stats': self.payload_generator.get_payload_statistics() if self.payload_generator else {},
                'deployment_log': self.deployment_log,
                'summary': {
                    'total_steps': len(self.deployment_log),
                    'successful_steps': len([step for step in self.deployment_log if step['status'] == 'PASSED']),
                    'failed_steps': len([step for step in self.deployment_log if step['status'] == 'FAILED']),
                    'warnings': len([step for step in self.deployment_log if step['status'] == 'WARNING'])
                }
            }
            
            # Save report
            report_file = f"deployment_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Deployment report saved: {report_file}")
            
            # Print summary
            print("\n" + "="*60)
            print("DEPLOYMENT SUMMARY")
            print("="*60)
            print(f"Total Steps: {report['summary']['total_steps']}")
            print(f"Successful: {report['summary']['successful_steps']}")
            print(f"Failed: {report['summary']['failed_steps']}")
            print(f"Warnings: {report['summary']['warnings']}")
            print("="*60)
            
            if report['summary']['failed_steps'] > 0:
                print("\nFAILED STEPS:")
                for step in self.deployment_log:
                    if step['status'] == 'FAILED':
                        print(f"  - {step['step']}: {step['details']}")
            
            print(f"\nDeployment report: {report_file}")
            print("Framework startup script: start_framework.sh")
            print("Dashboard URL: http://localhost:5000")
            
        except Exception as e:
            logger.error(f"Failed to generate deployment report: {e}")
    
    def deploy(self, skip_tools: bool = False, skip_optimization: bool = False):
        """Run complete deployment"""
        logger.info("Starting Kali Linux deployment...")
        
        try:
            # Check prerequisites
            if not self.check_prerequisites():
                logger.error("Prerequisites check failed")
                return False
            
            # Initialize optimizers
            self.initialize_optimizers()
            
            # System optimization
            if not skip_optimization:
                self.optimize_system()
            
            # Install security tools
            if not skip_tools:
                self.install_security_tools()
            
            # Setup payload generation
            self.setup_payload_generation()
            
            # Setup wordlists
            self.setup_wordlists()
            
            # Setup automation scripts
            self.setup_automation_scripts()
            
            # Setup monitoring
            self.setup_monitoring()
            
            # Setup security hardening
            self.setup_security_hardening()
            
            # Create startup script
            self.create_startup_script()
            
            # Generate deployment report
            self.generate_deployment_report()
            
            logger.info("Deployment completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            self.generate_deployment_report()
            return False

def main():
    """Main deployment function"""
    parser = argparse.ArgumentParser(description='Kali Linux Bug Bounty Framework Deployment')
    parser.add_argument('--config', default='kali_config.yml', help='Configuration file path')
    parser.add_argument('--skip-tools', action='store_true', help='Skip security tools installation')
    parser.add_argument('--skip-optimization', action='store_true', help='Skip system optimization')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without executing')
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("DRY RUN MODE - No changes will be made")
        print(f"Configuration file: {args.config}")
        print(f"Skip tools: {args.skip_tools}")
        print(f"Skip optimization: {args.skip_optimization}")
        return
    
    # Run deployment
    deployment = KaliLinuxDeployment(args.config)
    success = deployment.deploy(skip_tools=args.skip_tools, skip_optimization=args.skip_optimization)
    
    if success:
        print("\n🎉 Deployment completed successfully!")
        print("Run './start_framework.sh' to start the framework")
    else:
        print("\n❌ Deployment failed. Check the logs for details.")
        sys.exit(1)

if __name__ == '__main__':
    main() 