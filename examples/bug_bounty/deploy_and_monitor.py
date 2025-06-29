#!/usr/bin/env python3
"""
🚀 Comprehensive Deployment and Monitoring Script
Handles system setup, health checks, performance monitoring, and automated maintenance
for the Bug Bounty Framework.

Features:
- Automated system setup and configuration
- Real-time health monitoring
- Performance optimization
- Security monitoring
- Automated backups
- Log management
- Alert system
- Resource scaling
"""

import os
import sys
import time
import json
import logging
import subprocess
import threading
import schedule
import psutil
import requests
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import yaml
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('deployment.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SystemMonitor:
    """System health and performance monitoring"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.alert_thresholds = config.get('alert_thresholds', {})
        self.monitoring_interval = config.get('monitoring_interval', 60)
        self.health_checks = []
        self.performance_metrics = []
        
    def check_system_health(self) -> Dict:
        """Comprehensive system health check"""
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'healthy',
            'checks': {},
            'alerts': []
        }
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        health_status['checks']['cpu'] = {
            'value': cpu_percent,
            'status': 'healthy' if cpu_percent < 80 else 'warning' if cpu_percent < 90 else 'critical'
        }
        
        if cpu_percent > self.alert_thresholds.get('cpu_critical', 90):
            health_status['alerts'].append(f"Critical CPU usage: {cpu_percent}%")
            health_status['overall_status'] = 'critical'
        
        # Memory usage
        memory = psutil.virtual_memory()
        health_status['checks']['memory'] = {
            'value': memory.percent,
            'status': 'healthy' if memory.percent < 80 else 'warning' if memory.percent < 90 else 'critical'
        }
        
        if memory.percent > self.alert_thresholds.get('memory_critical', 90):
            health_status['alerts'].append(f"Critical memory usage: {memory.percent}%")
            health_status['overall_status'] = 'critical'
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total) * 100
        health_status['checks']['disk'] = {
            'value': disk_percent,
            'status': 'healthy' if disk_percent < 80 else 'warning' if disk_percent < 90 else 'critical'
        }
        
        if disk_percent > self.alert_thresholds.get('disk_critical', 90):
            health_status['alerts'].append(f"Critical disk usage: {disk_percent:.1f}%")
            health_status['overall_status'] = 'critical'
        
        # Network connectivity
        try:
            response = requests.get('http://localhost:5000/health', timeout=5)
            health_status['checks']['web_app'] = {
                'value': response.status_code,
                'status': 'healthy' if response.status_code == 200 else 'warning'
            }
        except Exception as e:
            health_status['checks']['web_app'] = {
                'value': 'error',
                'status': 'critical'
            }
            health_status['alerts'].append(f"Web application not responding: {str(e)}")
            health_status['overall_status'] = 'critical'
        
        # Database health
        try:
            with sqlite3.connect('bb_pro.db') as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
                vuln_count = cursor.fetchone()[0]
                health_status['checks']['database'] = {
                    'value': vuln_count,
                    'status': 'healthy'
                }
        except Exception as e:
            health_status['checks']['database'] = {
                'value': 'error',
                'status': 'critical'
            }
            health_status['alerts'].append(f"Database error: {str(e)}")
            health_status['overall_status'] = 'critical'
        
        # Store health check result
        self.health_checks.append(health_status)
        
        # Keep only last 100 health checks
        if len(self.health_checks) > 100:
            self.health_checks = self.health_checks[-100:]
        
        return health_status
    
    def get_performance_metrics(self) -> Dict:
        """Get detailed performance metrics"""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'system': {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100,
                'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
            },
            'network': {
                'connections': len(psutil.net_connections()),
                'interfaces': len(psutil.net_if_addrs())
            },
            'processes': {
                'total': len(psutil.pids()),
                'python': len([p for p in psutil.process_iter(['pid', 'name']) if 'python' in p.info['name'].lower()])
            }
        }
        
        self.performance_metrics.append(metrics)
        
        # Keep only last 1000 metrics
        if len(self.performance_metrics) > 1000:
            self.performance_metrics = self.performance_metrics[-1000:]
        
        return metrics

class BackupManager:
    """Automated backup management"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.backup_dir = Path(config.get('backup_dir', 'backups'))
        self.backup_dir.mkdir(exist_ok=True)
        
    def create_backup(self) -> str:
        """Create comprehensive system backup"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"bb_framework_backup_{timestamp}"
        backup_path = self.backup_dir / backup_name
        backup_path.mkdir(exist_ok=True)
        
        try:
            # Backup database
            if os.path.exists('bb_pro.db'):
                import shutil
                shutil.copy2('bb_pro.db', backup_path / 'bb_pro.db')
                logger.info(f"Database backed up to {backup_path / 'bb_pro.db'}")
            
            # Backup configuration files
            config_files = ['config.yml', 'agents.yml', 'next_gen_vuln_ui.py']
            for config_file in config_files:
                if os.path.exists(config_file):
                    shutil.copy2(config_file, backup_path / config_file)
            
            # Backup logs
            log_files = ['next_gen_vuln_ui.log', 'deployment.log', 'optimization.log']
            for log_file in log_files:
                if os.path.exists(log_file):
                    shutil.copy2(log_file, backup_path / log_file)
            
            # Create backup manifest
            manifest = {
                'timestamp': datetime.now().isoformat(),
                'backup_name': backup_name,
                'files': [f.name for f in backup_path.iterdir()],
                'system_info': {
                    'platform': sys.platform,
                    'python_version': sys.version,
                    'disk_usage': psutil.disk_usage('/')._asdict()
                }
            }
            
            with open(backup_path / 'manifest.json', 'w') as f:
                json.dump(manifest, f, indent=2)
            
            logger.info(f"Backup completed: {backup_name}")
            return str(backup_path)
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            raise
    
    def cleanup_old_backups(self, keep_days: int = 7):
        """Remove old backups"""
        cutoff_time = datetime.now() - timedelta(days=keep_days)
        
        for backup_dir in self.backup_dir.iterdir():
            if backup_dir.is_dir() and backup_dir.name.startswith('bb_framework_backup_'):
                try:
                    # Extract timestamp from directory name
                    timestamp_str = backup_dir.name.replace('bb_framework_backup_', '')
                    backup_time = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                    
                    if backup_time < cutoff_time:
                        import shutil
                        shutil.rmtree(backup_dir)
                        logger.info(f"Removed old backup: {backup_dir.name}")
                except Exception as e:
                    logger.error(f"Failed to remove old backup {backup_dir.name}: {e}")

class AlertManager:
    """Alert and notification management"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.email_config = config.get('email', {})
        self.webhook_config = config.get('webhook', {})
        self.alert_history = []
        
    def send_alert(self, alert_type: str, message: str, severity: str = 'medium'):
        """Send alert through configured channels"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message,
            'severity': severity
        }
        
        self.alert_history.append(alert)
        
        # Keep only last 100 alerts
        if len(self.alert_history) > 100:
            self.alert_history = self.alert_history[-100:]
        
        logger.warning(f"ALERT [{severity.upper()}]: {message}")
        
        # Send email alert
        if self.email_config.get('enabled', False):
            self._send_email_alert(alert)
        
        # Send webhook alert
        if self.webhook_config.get('enabled', False):
            self._send_webhook_alert(alert)
    
    def _send_email_alert(self, alert: Dict):
        """Send email alert"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['from']
            msg['To'] = self.email_config['to']
            msg['Subject'] = f"Bug Bounty Framework Alert: {alert['type']}"
            
            body = f"""
            Alert Type: {alert['type']}
            Severity: {alert['severity']}
            Message: {alert['message']}
            Timestamp: {alert['timestamp']}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['username'], self.email_config['password'])
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email alert sent: {alert['type']}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    def _send_webhook_alert(self, alert: Dict):
        """Send webhook alert"""
        try:
            response = requests.post(
                self.webhook_config['url'],
                json=alert,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Webhook alert sent: {alert['type']}")
            else:
                logger.error(f"Webhook alert failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")

class DeploymentManager:
    """Deployment and system management"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.monitor = SystemMonitor(config)
        self.backup_manager = BackupManager(config)
        self.alert_manager = AlertManager(config)
        self.app_process = None
        
    def setup_system(self):
        """Initial system setup"""
        logger.info("Starting system setup...")
        
        try:
            # Create necessary directories
            directories = [
                'backups', 'logs', 'uploads', 'exports',
                'vulnerability_analysis_reports', 'manual_test_reports'
            ]
            
            for directory in directories:
                Path(directory).mkdir(exist_ok=True)
                logger.info(f"Created directory: {directory}")
            
            # Install dependencies
            self._install_dependencies()
            
            # Initialize database
            self._initialize_database()
            
            # Setup security
            self._setup_security()
            
            logger.info("System setup completed successfully")
            
        except Exception as e:
            logger.error(f"System setup failed: {e}")
            self.alert_manager.send_alert('setup_failed', str(e), 'critical')
            raise
    
    def _install_dependencies(self):
        """Install required dependencies"""
        logger.info("Installing dependencies...")
        
        dependencies = [
            'flask', 'flask-socketio', 'flask-limiter', 'flask-caching',
            'flask-compress', 'requests', 'plotly', 'numpy', 'pandas',
            'scikit-learn', 'redis', 'celery', 'prometheus-client',
            'openai', 'anthropic', 'schedule', 'psutil'
        ]
        
        for dep in dependencies:
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', dep])
                logger.info(f"Installed: {dep}")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to install {dep}: {e}")
    
    def _initialize_database(self):
        """Initialize database"""
        logger.info("Initializing database...")
        
        try:
            # Import and run database initialization
            from next_gen_vuln_ui import DatabaseManager
            db_manager = DatabaseManager('bb_pro.db')
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def _setup_security(self):
        """Setup security features"""
        logger.info("Setting up security features...")
        
        try:
            # Generate secret key if not exists
            if not os.path.exists('.env'):
                import secrets
                secret_key = secrets.token_hex(32)
                
                with open('.env', 'w') as f:
                    f.write(f"SECRET_KEY={secret_key}\n")
                    f.write("FLASK_ENV=production\n")
                    f.write("FLASK_DEBUG=False\n")
                
                logger.info("Generated .env file with secret key")
            
            # Initialize security enhancer
            from security_enhancer import initialize_security_enhancer
            initialize_security_enhancer(os.getenv('SECRET_KEY', 'default-secret-key'))
            logger.info("Security enhancer initialized")
            
        except Exception as e:
            logger.error(f"Security setup failed: {e}")
            raise
    
    def start_application(self):
        """Start the web application"""
        logger.info("Starting web application...")
        
        try:
            # Start the Flask application
            from next_gen_vuln_ui import app, socketio
            
            # Run in production mode
            socketio.run(
                app,
                host='0.0.0.0',
                port=5000,
                debug=False,
                use_reloader=False
            )
            
        except Exception as e:
            logger.error(f"Failed to start application: {e}")
            self.alert_manager.send_alert('app_start_failed', str(e), 'critical')
            raise
    
    def start_monitoring(self):
        """Start continuous monitoring"""
        logger.info("Starting system monitoring...")
        
        def monitor_loop():
            while True:
                try:
                    # Check system health
                    health_status = self.monitor.check_system_health()
                    
                    # Send alerts for critical issues
                    if health_status['overall_status'] == 'critical':
                        for alert in health_status['alerts']:
                            self.alert_manager.send_alert('system_critical', alert, 'critical')
                    
                    # Get performance metrics
                    metrics = self.monitor.get_performance_metrics()
                    
                    # Log metrics
                    logger.debug(f"Performance metrics: {metrics}")
                    
                    time.sleep(self.config.get('monitoring_interval', 60))
                    
                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
                    time.sleep(30)
        
        # Start monitoring in background thread
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        
        logger.info("Monitoring started")
    
    def schedule_maintenance(self):
        """Schedule automated maintenance tasks"""
        logger.info("Scheduling maintenance tasks...")
        
        # Daily backup
        schedule.every().day.at("02:00").do(self.backup_manager.create_backup)
        
        # Weekly cleanup
        schedule.every().sunday.at("03:00").do(self.backup_manager.cleanup_old_backups)
        
        # Daily health report
        schedule.every().day.at("06:00").do(self._generate_health_report)
        
        # Start scheduler
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)
        
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        
        logger.info("Maintenance tasks scheduled")
    
    def _generate_health_report(self):
        """Generate daily health report"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'system_health': self.monitor.check_system_health(),
                'performance_metrics': self.monitor.get_performance_metrics(),
                'alerts': self.alert_manager.alert_history[-10:],  # Last 10 alerts
                'backups': len(list(Path('backups').glob('bb_framework_backup_*')))
            }
            
            report_path = f"reports/health_report_{datetime.now().strftime('%Y%m%d')}.json"
            Path('reports').mkdir(exist_ok=True)
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Health report generated: {report_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate health report: {e}")

def load_config(config_path: str = 'deployment_config.yml') -> Dict:
    """Load deployment configuration"""
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    else:
        # Default configuration
        return {
            'monitoring_interval': 60,
            'alert_thresholds': {
                'cpu_critical': 90,
                'memory_critical': 90,
                'disk_critical': 90
            },
            'backup_dir': 'backups',
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'from': '',
                'to': ''
            },
            'webhook': {
                'enabled': False,
                'url': ''
            }
        }

def main():
    """Main deployment function"""
    parser = argparse.ArgumentParser(description='Bug Bounty Framework Deployment')
    parser.add_argument('--config', default='deployment_config.yml', help='Configuration file path')
    parser.add_argument('--setup', action='store_true', help='Run initial system setup')
    parser.add_argument('--monitor', action='store_true', help='Start monitoring only')
    parser.add_argument('--backup', action='store_true', help='Create backup')
    parser.add_argument('--health', action='store_true', help='Check system health')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Create deployment manager
    deployment = DeploymentManager(config)
    
    try:
        if args.setup:
            # Run system setup
            deployment.setup_system()
            logger.info("System setup completed")
            
        elif args.monitor:
            # Start monitoring only
            deployment.start_monitoring()
            deployment.schedule_maintenance()
            
            # Keep running
            while True:
                time.sleep(1)
                
        elif args.backup:
            # Create backup
            backup_path = deployment.backup_manager.create_backup()
            logger.info(f"Backup created: {backup_path}")
            
        elif args.health:
            # Check system health
            health = deployment.monitor.check_system_health()
            print(json.dumps(health, indent=2))
            
        else:
            # Full deployment
            logger.info("Starting full deployment...")
            
            # Setup system if needed
            if not os.path.exists('bb_pro.db'):
                deployment.setup_system()
            
            # Start monitoring
            deployment.start_monitoring()
            deployment.schedule_maintenance()
            
            # Start application
            deployment.start_application()
            
    except KeyboardInterrupt:
        logger.info("Deployment stopped by user")
    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 