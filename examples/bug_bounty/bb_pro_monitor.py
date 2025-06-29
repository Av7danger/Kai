#!/usr/bin/env python3
"""
🎯 BUG BOUNTY PLATFORM STATUS MONITOR
Real-time system monitoring, health checks, and alerting
"""

import sqlite3
import os
import sys
import time
import json
import threading
import requests
from datetime import datetime, timedelta
from pathlib import Path
import psutil
import logging
from typing import Dict, List, Any
import subprocess
import socket

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bb_pro_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SystemMonitor:
    """Comprehensive system monitoring and health checks"""
    
    def __init__(self):
        self.db_path = 'bb_pro.db'
        self.ui_url = 'http://localhost:5000'
        self.status_file = Path('system_status.json')
        self.health_history = Path('health_history.json')
        self.alerts_log = Path('alerts.log')
        
        # Thresholds
        self.thresholds = {
            'cpu_warning': 80,
            'cpu_critical': 95,
            'memory_warning': 80,
            'memory_critical': 95,
            'disk_warning': 85,
            'disk_critical': 95,
            'response_time_warning': 2.0,
            'response_time_critical': 5.0
        }
    
    def print_banner(self):
        """Print monitoring banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                   🎯 BUG BOUNTY PLATFORM MONITOR                     ║
║                                                                      ║
║  📊 Real-time Monitoring     🚨 Alert System                        ║
║  🏥 Health Diagnostics       📈 Performance Metrics                  ║
║  🔍 Status Dashboard         📋 Detailed Reports                     ║
╚══════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def check_system_resources(self) -> Dict[str, Any]:
        """Check system resource usage"""
        try:
            # CPU Usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            
            # Memory Usage
            memory = psutil.virtual_memory()
            
            # Disk Usage
            disk = psutil.disk_usage('.')
            
            # Network Stats
            network = psutil.net_io_counters()
            
            # Process info
            current_process = psutil.Process()
            process_info = {
                'pid': current_process.pid,
                'memory_mb': current_process.memory_info().rss / 1024 / 1024,
                'cpu_percent': current_process.cpu_percent(),
                'threads': current_process.num_threads(),
                'open_files': len(current_process.open_files())
            }
            
            resources = {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'status': self._get_status_level(cpu_percent, 'cpu')
                },
                'memory': {
                    'total_gb': memory.total / (1024**3),
                    'available_gb': memory.available / (1024**3),
                    'used_gb': memory.used / (1024**3),
                    'percent': memory.percent,
                    'status': self._get_status_level(memory.percent, 'memory')
                },
                'disk': {
                    'total_gb': disk.total / (1024**3),
                    'free_gb': disk.free / (1024**3),
                    'used_gb': disk.used / (1024**3),
                    'percent': (disk.used / disk.total) * 100,
                    'status': self._get_status_level((disk.used / disk.total) * 100, 'disk')
                },
                'network': {
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv
                },
                'process': process_info
            }
            
            return resources
            
        except Exception as e:
            logger.error(f"Error checking system resources: {e}")
            return {}
    
    def _get_status_level(self, value: float, metric_type: str) -> str:
        """Determine status level based on thresholds"""
        warning_key = f"{metric_type}_warning"
        critical_key = f"{metric_type}_critical"
        
        if value >= self.thresholds.get(critical_key, 95):
            return "CRITICAL"
        elif value >= self.thresholds.get(warning_key, 80):
            return "WARNING"
        else:
            return "OK"
    
    def check_database_health(self) -> Dict[str, Any]:
        """Check database health and performance"""
        try:
            db_health = {
                'timestamp': datetime.now().isoformat(),
                'file_exists': os.path.exists(self.db_path),
                'file_size_mb': 0,
                'connection_test': False,
                'table_count': 0,
                'vulnerability_count': 0,
                'target_count': 0,
                'integrity_check': False,
                'last_backup': None,
                'status': 'UNKNOWN'
            }
            
            if not db_health['file_exists']:
                db_health['status'] = 'CRITICAL'
                db_health['error'] = 'Database file not found'
                return db_health
            
            # File size
            db_health['file_size_mb'] = os.path.getsize(self.db_path) / (1024 * 1024)
            
            # Connection test
            conn = sqlite3.connect(self.db_path, timeout=5)
            cursor = conn.cursor()
            db_health['connection_test'] = True
            
            # Table count
            cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
            db_health['table_count'] = cursor.fetchone()[0]
            
            # Data counts
            try:
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
                db_health['vulnerability_count'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM targets")
                db_health['target_count'] = cursor.fetchone()[0]
            except:
                pass
            
            # Integrity check
            cursor.execute("PRAGMA integrity_check")
            integrity_result = cursor.fetchone()
            db_health['integrity_check'] = integrity_result and integrity_result[0] == 'ok'
            
            # Check for recent backups
            backup_dir = Path('backups')
            if backup_dir.exists():
                backup_files = list(backup_dir.glob('*.db'))
                if backup_files:
                    latest_backup = max(backup_files, key=lambda f: f.stat().st_mtime)
                    db_health['last_backup'] = datetime.fromtimestamp(latest_backup.stat().st_mtime).isoformat()
            
            conn.close()
            
            # Overall status
            if not db_health['integrity_check']:
                db_health['status'] = 'CRITICAL'
            elif db_health['vulnerability_count'] == 0:
                db_health['status'] = 'WARNING'
            else:
                db_health['status'] = 'OK'
            
            return db_health
            
        except Exception as e:
            logger.error(f"Error checking database health: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'status': 'CRITICAL',
                'error': str(e)
            }
    
    def check_web_ui_health(self) -> Dict[str, Any]:
        """Check web UI health and responsiveness"""
        ui_health = {
            'timestamp': datetime.now().isoformat(),
            'url': self.ui_url,
            'accessible': False,
            'response_time': None,
            'status_code': None,
            'content_check': False,
            'status': 'UNKNOWN'
        }
        
        try:
            start_time = time.time()
            response = requests.get(self.ui_url, timeout=10)
            response_time = time.time() - start_time
            
            ui_health['accessible'] = True
            ui_health['response_time'] = response_time
            ui_health['status_code'] = response.status_code
            ui_health['content_check'] = 'Bug Bounty' in response.text or 'Dashboard' in response.text
            
            # Determine status
            if response.status_code != 200:
                ui_health['status'] = 'CRITICAL'
            elif response_time > self.thresholds['response_time_critical']:
                ui_health['status'] = 'CRITICAL'
            elif response_time > self.thresholds['response_time_warning']:
                ui_health['status'] = 'WARNING'
            elif not ui_health['content_check']:
                ui_health['status'] = 'WARNING'
            else:
                ui_health['status'] = 'OK'
                
        except requests.exceptions.ConnectionError:
            ui_health['status'] = 'CRITICAL'
            ui_health['error'] = 'Connection refused - UI not running'
        except requests.exceptions.Timeout:
            ui_health['status'] = 'CRITICAL'
            ui_health['error'] = 'Request timeout'
        except Exception as e:
            ui_health['status'] = 'CRITICAL'
            ui_health['error'] = str(e)
        
        return ui_health
    
    def check_ai_services(self) -> Dict[str, Any]:
        """Check AI service availability"""
        ai_health = {
            'timestamp': datetime.now().isoformat(),
            'gemini_available': False,
            'gemini_api_key': False,
            'api_test': False,
            'status': 'UNKNOWN'
        }
        
        try:
            # Check if Gemini is installed
            import google.generativeai as genai
            ai_health['gemini_available'] = True
            
            # Check API key
            api_key = os.getenv('GEMINI_API_KEY')
            ai_health['gemini_api_key'] = bool(api_key)
            
            if api_key:
                try:
                    genai.configure(api_key=api_key)
                    model = genai.GenerativeModel('gemini-pro')
                    response = model.generate_content("Hello")
                    ai_health['api_test'] = bool(response.text)
                    ai_health['status'] = 'OK'
                except Exception as e:
                    ai_health['status'] = 'WARNING'
                    ai_health['error'] = f'API test failed: {str(e)}'
            else:
                ai_health['status'] = 'WARNING'
                ai_health['error'] = 'API key not configured'
                
        except ImportError:
            ai_health['status'] = 'WARNING'
            ai_health['error'] = 'Gemini library not installed'
        except Exception as e:
            ai_health['status'] = 'CRITICAL'
            ai_health['error'] = str(e)
        
        return ai_health
    
    def check_file_system(self) -> Dict[str, Any]:
        """Check file system health"""
        fs_health = {
            'timestamp': datetime.now().isoformat(),
            'directories': {},
            'permissions': {},
            'status': 'OK'
        }
        
        required_dirs = [
            'vulnerability_analysis_reports',
            'manual_test_reports',
            'backups',
            'templates'
        ]
        
        for dir_name in required_dirs:
            dir_path = Path(dir_name)
            fs_health['directories'][dir_name] = {
                'exists': dir_path.exists(),
                'is_dir': dir_path.is_dir() if dir_path.exists() else False,
                'readable': os.access(dir_path, os.R_OK) if dir_path.exists() else False,
                'writable': os.access(dir_path, os.W_OK) if dir_path.exists() else False
            }
            
            if not dir_path.exists():
                fs_health['status'] = 'WARNING'
                try:
                    dir_path.mkdir(exist_ok=True)
                    logger.info(f"Created missing directory: {dir_name}")
                except Exception as e:
                    fs_health['status'] = 'CRITICAL'
                    logger.error(f"Failed to create directory {dir_name}: {e}")
        
        # Check important files
        important_files = [
            'advanced_vuln_ui.py',
            'gemini_vuln_analyzer.py',
            'manual_vuln_tester.py',
            'bb_pro.db'
        ]
        
        for file_name in important_files:
            if os.path.exists(file_name):
                fs_health['permissions'][file_name] = {
                    'readable': os.access(file_name, os.R_OK),
                    'writable': os.access(file_name, os.W_OK),
                    'size_mb': os.path.getsize(file_name) / (1024 * 1024)
                }
            else:
                fs_health['status'] = 'WARNING'
                fs_health['permissions'][file_name] = {'missing': True}
        
        return fs_health
    
    def run_comprehensive_health_check(self) -> Dict[str, Any]:
        """Run all health checks"""
        logger.info("🏥 Running comprehensive health check...")
        
        health_report = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'OK',
            'checks': {}
        }
        
        # Run all checks
        checks = [
            ('system_resources', self.check_system_resources),
            ('database', self.check_database_health),
            ('web_ui', self.check_web_ui_health),
            ('ai_services', self.check_ai_services),
            ('file_system', self.check_file_system)
        ]
        
        critical_count = 0
        warning_count = 0
        
        for check_name, check_func in checks:
            try:
                result = check_func()
                health_report['checks'][check_name] = result
                
                status = result.get('status', 'UNKNOWN')
                if status == 'CRITICAL':
                    critical_count += 1
                elif status == 'WARNING':
                    warning_count += 1
                    
                logger.info(f"✅ {check_name}: {status}")
                
            except Exception as e:
                logger.error(f"❌ {check_name} check failed: {e}")
                health_report['checks'][check_name] = {
                    'status': 'CRITICAL',
                    'error': str(e)
                }
                critical_count += 1
        
        # Determine overall status
        if critical_count > 0:
            health_report['overall_status'] = 'CRITICAL'
        elif warning_count > 0:
            health_report['overall_status'] = 'WARNING'
        else:
            health_report['overall_status'] = 'OK'
        
        health_report['summary'] = {
            'total_checks': len(checks),
            'critical_issues': critical_count,
            'warnings': warning_count,
            'healthy': len(checks) - critical_count - warning_count
        }
        
        # Save health report
        with open(self.status_file, 'w') as f:
            json.dump(health_report, f, indent=2)
        
        # Update history
        self._update_health_history(health_report)
        
        # Check for alerts
        self._check_alerts(health_report)
        
        return health_report
    
    def _update_health_history(self, health_report: Dict[str, Any]):
        """Update health history"""
        try:
            if self.health_history.exists():
                with open(self.health_history, 'r') as f:
                    history = json.load(f)
            else:
                history = {'entries': []}
            
            # Keep only last 100 entries
            history['entries'].append({
                'timestamp': health_report['timestamp'],
                'overall_status': health_report['overall_status'],
                'summary': health_report['summary']
            })
            
            if len(history['entries']) > 100:
                history['entries'] = history['entries'][-100:]
            
            with open(self.health_history, 'w') as f:
                json.dump(history, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error updating health history: {e}")
    
    def _check_alerts(self, health_report: Dict[str, Any]):
        """Check for alert conditions"""
        alerts = []
        
        for check_name, check_result in health_report['checks'].items():
            status = check_result.get('status', 'UNKNOWN')
            
            if status == 'CRITICAL':
                alerts.append({
                    'level': 'CRITICAL',
                    'check': check_name,
                    'message': check_result.get('error', 'Critical issue detected'),
                    'timestamp': datetime.now().isoformat()
                })
            elif status == 'WARNING':
                alerts.append({
                    'level': 'WARNING',
                    'check': check_name,
                    'message': check_result.get('error', 'Warning condition detected'),
                    'timestamp': datetime.now().isoformat()
                })
        
        if alerts:
            self._log_alerts(alerts)
            self._send_notifications(alerts)
    
    def _log_alerts(self, alerts: List[Dict[str, Any]]):
        """Log alerts to file"""
        try:
            with open(self.alerts_log, 'a') as f:
                for alert in alerts:
                    f.write(f"{alert['timestamp']} - {alert['level']} - {alert['check']}: {alert['message']}\n")
        except Exception as e:
            logger.error(f"Error logging alerts: {e}")
    
    def _send_notifications(self, alerts: List[Dict[str, Any]]):
        """Send notifications for alerts (placeholder)"""
        # In a real implementation, this could send emails, Slack messages, etc.
        for alert in alerts:
            logger.warning(f"🚨 ALERT: {alert['level']} in {alert['check']}: {alert['message']}")
    
    def generate_status_dashboard(self) -> str:
        """Generate a formatted status dashboard"""
        health_report = self.run_comprehensive_health_check()
        
        dashboard = f"""
╔══════════════════════════════════════════════════════════════════════╗
║                     🎯 SYSTEM STATUS DASHBOARD                       ║
║                  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                    ║
╚══════════════════════════════════════════════════════════════════════╝

🏥 OVERALL HEALTH: {health_report['overall_status']}
📊 Summary: {health_report['summary']['healthy']} OK, {health_report['summary']['warnings']} Warning, {health_report['summary']['critical_issues']} Critical

───────────────────────────────────────────────────────────────────────

📈 SYSTEM RESOURCES
"""
        
        sys_resources = health_report['checks'].get('system_resources', {})
        if sys_resources:
            dashboard += f"""  CPU Usage:     {sys_resources.get('cpu', {}).get('percent', 0):.1f}% [{sys_resources.get('cpu', {}).get('status', 'UNKNOWN')}]
  Memory Usage:  {sys_resources.get('memory', {}).get('percent', 0):.1f}% [{sys_resources.get('memory', {}).get('status', 'UNKNOWN')}]
  Disk Usage:    {sys_resources.get('disk', {}).get('percent', 0):.1f}% [{sys_resources.get('disk', {}).get('status', 'UNKNOWN')}]
"""
        
        dashboard += "\n🗄️  DATABASE HEALTH\n"
        db_health = health_report['checks'].get('database', {})
        if db_health:
            dashboard += f"""  Status:        {db_health.get('status', 'UNKNOWN')}
  File Size:     {db_health.get('file_size_mb', 0):.1f} MB
  Vulnerabilities: {db_health.get('vulnerability_count', 0)}
  Targets:       {db_health.get('target_count', 0)}
  Integrity:     {'✅' if db_health.get('integrity_check') else '❌'}
"""
        
        dashboard += "\n🌐 WEB UI STATUS\n"
        ui_health = health_report['checks'].get('web_ui', {})
        if ui_health:
            dashboard += f"""  Status:        {ui_health.get('status', 'UNKNOWN')}
  Accessible:    {'✅' if ui_health.get('accessible') else '❌'}
  Response Time: {ui_health.get('response_time', 0):.2f}s
  Status Code:   {ui_health.get('status_code', 'N/A')}
"""
        
        dashboard += "\n🤖 AI SERVICES\n"
        ai_health = health_report['checks'].get('ai_services', {})
        if ai_health:
            dashboard += f"""  Status:        {ai_health.get('status', 'UNKNOWN')}
  Gemini Available: {'✅' if ai_health.get('gemini_available') else '❌'}
  API Key Set:   {'✅' if ai_health.get('gemini_api_key') else '❌'}
  API Test:      {'✅' if ai_health.get('api_test') else '❌'}
"""
        
        dashboard += "\n📁 FILE SYSTEM\n"
        fs_health = health_report['checks'].get('file_system', {})
        if fs_health:
            dashboard += f"  Status:        {fs_health.get('status', 'UNKNOWN')}\n"
            
            for dir_name, dir_info in fs_health.get('directories', {}).items():
                status = '✅' if dir_info.get('exists') and dir_info.get('writable') else '❌'
                dashboard += f"  {dir_name}: {status}\n"
        
        dashboard += "\n" + "="*70 + "\n"
        
        return dashboard
    
    def monitor_continuously(self, interval: int = 60):
        """Run continuous monitoring"""
        logger.info(f"🔄 Starting continuous monitoring (interval: {interval}s)")
        
        try:
            while True:
                health_report = self.run_comprehensive_health_check()
                
                # Print brief status
                status = health_report['overall_status']
                timestamp = datetime.now().strftime('%H:%M:%S')
                print(f"[{timestamp}] System Status: {status}")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            logger.info("🛑 Monitoring stopped by user")
        except Exception as e:
            logger.error(f"❌ Monitoring error: {e}")

def main():
    """Main monitoring function"""
    monitor = SystemMonitor()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'dashboard':
            monitor.print_banner()
            dashboard = monitor.generate_status_dashboard()
            print(dashboard)
        elif command == 'check':
            monitor.run_comprehensive_health_check()
            print("✅ Health check completed. See system_status.json for details.")
        elif command == 'monitor':
            interval = int(sys.argv[2]) if len(sys.argv) > 2 else 60
            monitor.print_banner()
            monitor.monitor_continuously(interval)
        elif command == 'resources':
            resources = monitor.check_system_resources()
            print(json.dumps(resources, indent=2))
        elif command == 'database':
            db_health = monitor.check_database_health()
            print(json.dumps(db_health, indent=2))
        elif command == 'ui':
            ui_health = monitor.check_web_ui_health()
            print(json.dumps(ui_health, indent=2))
        else:
            print("Usage: python bb_pro_monitor.py [dashboard|check|monitor|resources|database|ui]")
    else:
        # Default: show dashboard
        monitor.print_banner()
        dashboard = monitor.generate_status_dashboard()
        print(dashboard)

if __name__ == "__main__":
    main()
