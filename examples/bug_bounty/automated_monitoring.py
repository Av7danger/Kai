#!/usr/bin/env python3
"""
🔄 Automated Scheduling & Monitoring System
Continuous vulnerability monitoring and intelligent scan scheduling

Features:
- Automated scan scheduling and execution
- Real-time vulnerability monitoring
- Intelligent alerting system
- Performance optimization
- Continuous integration with AI analysis
- Dashboard integration and notifications
"""

import os
import json
import yaml
import time
import threading
import schedule
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from pathlib import Path
import logging
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import hashlib
import queue
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import our modules
from advanced_recon_tools import AdvancedReconTools
from ai_integration import get_ai_integration

logger = logging.getLogger(__name__)

@dataclass
class ScanTask:
    """Scan task configuration"""
    id: str
    target_id: int
    target_domain: str
    scan_type: str
    schedule_type: str  # daily, weekly, monthly, custom
    schedule_config: Dict[str, Any]
    last_run: Optional[datetime]
    next_run: datetime
    status: str  # pending, running, completed, failed
    priority: int  # 1-10, higher is more important
    enabled: bool = True

@dataclass
class MonitoringAlert:
    """Monitoring alert"""
    id: str
    target_id: int
    alert_type: str  # vulnerability, performance, system
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    details: Dict[str, Any]
    timestamp: datetime
    acknowledged: bool = False
    resolved: bool = False

@dataclass
class PerformanceMetrics:
    """Performance metrics"""
    scan_id: str
    target_domain: str
    scan_duration: float
    vulnerabilities_found: int
    risk_score: float
    system_resources: Dict[str, float]
    timestamp: datetime

class AutomatedMonitoring:
    """Automated monitoring and scheduling system"""
    
    def __init__(self, config_path: str = 'monitoring_config.yml'):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize components
        self.recon_tools = AdvancedReconTools()
        self.ai_agent = get_ai_integration()
        
        # Task management
        self.scan_tasks: Dict[str, ScanTask] = {}
        self.task_queue = queue.Queue()
        self.running_tasks: Dict[str, threading.Thread] = {}
        
        # Monitoring
        self.alerts: List[MonitoringAlert] = []
        self.performance_metrics: List[PerformanceMetrics] = []
        self.monitoring_active = False
        
        # Database
        self.db_path = 'monitoring.db'
        self._init_database()
        
        # Notification system
        self.notification_handlers: Dict[str, Callable] = {}
        self._setup_notifications()
        
        # Performance tracking
        self.performance_history: List[Dict[str, Any]] = []
        
        # Create output directories
        self.output_dir = Path('monitoring_results')
        self.output_dir.mkdir(exist_ok=True)
        
        for subdir in ['scans', 'alerts', 'metrics', 'reports']:
            (self.output_dir / subdir).mkdir(exist_ok=True)
    
    def _load_config(self) -> Dict:
        """Load monitoring configuration"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default monitoring configuration"""
        return {
            'scheduling': {
                'max_concurrent_scans': 3,
                'scan_timeout': 3600,  # 1 hour
                'retry_failed_scans': True,
                'max_retries': 3,
                'retry_delay': 300  # 5 minutes
            },
            'monitoring': {
                'check_interval': 300,  # 5 minutes
                'alert_thresholds': {
                    'vulnerability_count': 10,
                    'risk_score': 7.0,
                    'scan_duration': 1800,  # 30 minutes
                    'system_cpu': 80.0,
                    'system_memory': 85.0
                },
                'continuous_monitoring': True
            },
            'notifications': {
                'email': {
                    'enabled': False,
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'recipients': []
                },
                'webhook': {
                    'enabled': False,
                    'url': '',
                    'headers': {}
                },
                'slack': {
                    'enabled': False,
                    'webhook_url': '',
                    'channel': '#security-alerts'
                }
            },
            'performance': {
                'track_metrics': True,
                'metrics_retention_days': 30,
                'optimization_enabled': True
            }
        }
    
    def _init_database(self):
        """Initialize monitoring database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scan tasks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_tasks (
                id TEXT PRIMARY KEY,
                target_id INTEGER,
                target_domain TEXT,
                scan_type TEXT,
                schedule_type TEXT,
                schedule_config TEXT,
                last_run TEXT,
                next_run TEXT,
                status TEXT,
                priority INTEGER,
                enabled INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Monitoring alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_alerts (
                id TEXT PRIMARY KEY,
                target_id INTEGER,
                alert_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                details TEXT,
                timestamp TEXT,
                acknowledged INTEGER,
                resolved INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Performance metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                target_domain TEXT,
                scan_duration REAL,
                vulnerabilities_found INTEGER,
                risk_score REAL,
                system_resources TEXT,
                timestamp TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT,
                target_domain TEXT,
                scan_type TEXT,
                status TEXT,
                results TEXT,
                duration REAL,
                started_at TEXT,
                completed_at TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _setup_notifications(self):
        """Setup notification handlers"""
        # Email notifications
        if self.config['notifications']['email']['enabled']:
            self.notification_handlers['email'] = self._send_email_alert
        
        # Webhook notifications
        if self.config['notifications']['webhook']['enabled']:
            self.notification_handlers['webhook'] = self._send_webhook_alert
        
        # Slack notifications
        if self.config['notifications']['slack']['enabled']:
            self.notification_handlers['slack'] = self._send_slack_alert
    
    def add_scan_task(self, target_id: int, target_domain: str, scan_type: str = 'full',
                     schedule_type: str = 'daily', schedule_config: Dict[str, Any] = None,
                     priority: int = 5) -> str:
        """Add a new scan task"""
        task_id = hashlib.md5(f"{target_domain}_{scan_type}_{time.time()}".encode()).hexdigest()[:12]
        
        # Calculate next run time
        next_run = self._calculate_next_run(schedule_type, schedule_config or {})
        
        task = ScanTask(
            id=task_id,
            target_id=target_id,
            target_domain=target_domain,
            scan_type=scan_type,
            schedule_type=schedule_type,
            schedule_config=schedule_config or {},
            last_run=None,
            next_run=next_run,
            status='pending',
            priority=priority,
            enabled=True
        )
        
        self.scan_tasks[task_id] = task
        self._save_task_to_db(task)
        
        logger.info(f"Added scan task {task_id} for {target_domain}")
        return task_id
    
    def _calculate_next_run(self, schedule_type: str, config: Dict[str, Any]) -> datetime:
        """Calculate next run time based on schedule type"""
        now = datetime.now()
        
        if schedule_type == 'daily':
            hour = config.get('hour', 2)  # Default to 2 AM
            return now.replace(hour=hour, minute=0, second=0, microsecond=0) + timedelta(days=1)
        
        elif schedule_type == 'weekly':
            day_of_week = config.get('day', 0)  # Monday = 0
            hour = config.get('hour', 2)
            next_run = now.replace(hour=hour, minute=0, second=0, microsecond=0)
            days_ahead = day_of_week - next_run.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            return next_run + timedelta(days=days_ahead)
        
        elif schedule_type == 'monthly':
            day_of_month = config.get('day', 1)
            hour = config.get('hour', 2)
            next_run = now.replace(day=day_of_month, hour=hour, minute=0, second=0, microsecond=0)
            if next_run <= now:
                # Move to next month
                if next_run.month == 12:
                    next_run = next_run.replace(year=next_run.year + 1, month=1)
                else:
                    next_run = next_run.replace(month=next_run.month + 1)
            return next_run
        
        elif schedule_type == 'custom':
            interval_hours = config.get('interval_hours', 24)
            return now + timedelta(hours=interval_hours)
        
        else:
            # Default to daily at 2 AM
            return now.replace(hour=2, minute=0, second=0, microsecond=0) + timedelta(days=1)
    
    def _save_task_to_db(self, task: ScanTask):
        """Save task to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO scan_tasks 
            (id, target_id, target_domain, scan_type, schedule_type, schedule_config,
             last_run, next_run, status, priority, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            task.id, task.target_id, task.target_domain, task.scan_type,
            task.schedule_type, json.dumps(task.schedule_config),
            task.last_run.isoformat() if task.last_run else None,
            task.next_run.isoformat(), task.status, task.priority, task.enabled
        ))
        
        conn.commit()
        conn.close()
    
    def start_monitoring(self):
        """Start the monitoring system"""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        logger.info("Starting automated monitoring system")
        
        # Start scheduler thread
        scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        scheduler_thread.start()
        
        # Start monitoring thread
        monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        monitoring_thread.start()
        
        # Start task executor
        executor_thread = threading.Thread(target=self._task_executor_loop, daemon=True)
        executor_thread.start()
    
    def stop_monitoring(self):
        """Stop the monitoring system"""
        self.monitoring_active = False
        logger.info("Stopping automated monitoring system")
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.monitoring_active:
            try:
                now = datetime.now()
                
                # Check for tasks that need to run
                for task_id, task in self.scan_tasks.items():
                    if (task.enabled and task.status != 'running' and 
                        task.next_run <= now):
                        
                        # Add to task queue
                        self.task_queue.put(task)
                        
                        # Update next run time
                        task.next_run = self._calculate_next_run(
                            task.schedule_type, task.schedule_config
                        )
                        self._save_task_to_db(task)
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                time.sleep(60)
    
    def _task_executor_loop(self):
        """Task execution loop"""
        max_concurrent = self.config['scheduling']['max_concurrent_scans']
        
        while self.monitoring_active:
            try:
                # Check if we can start new tasks
                running_count = len([t for t in self.running_tasks.values() if t.is_alive()])
                
                if running_count < max_concurrent and not self.task_queue.empty():
                    task = self.task_queue.get()
                    
                    # Start task execution
                    task_thread = threading.Thread(
                        target=self._execute_scan_task,
                        args=(task,),
                        daemon=True
                    )
                    task_thread.start()
                    self.running_tasks[task.id] = task_thread
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Task executor error: {e}")
                time.sleep(10)
    
    def _execute_scan_task(self, task: ScanTask):
        """Execute a scan task"""
        try:
            logger.info(f"Starting scan task {task.id} for {task.target_domain}")
            
            # Update task status
            task.status = 'running'
            task.last_run = datetime.now()
            self._save_task_to_db(task)
            
            # Record start time
            start_time = time.time()
            
            # Execute scan based on type
            if task.scan_type == 'full':
                results = self.recon_tools.run_full_reconnaissance(task.target_domain)
            elif task.scan_type == 'quick':
                results = self.recon_tools.run_quick_reconnaissance(task.target_domain)
            elif task.scan_type == 'vulnerability':
                results = self.recon_tools.run_vulnerability_scan(task.target_domain)
            else:
                results = self.recon_tools.run_custom_reconnaissance(
                    task.target_domain, [task.scan_type]
                )
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Run AI analysis
            ai_analysis = self.ai_agent.analyze_recon_data(results)
            
            # Record performance metrics
            self._record_performance_metrics(task, duration, results, ai_analysis)
            
            # Check for alerts
            self._check_alerts(task, results, ai_analysis, duration)
            
            # Save scan results
            self._save_scan_results(task, results, ai_analysis, duration)
            
            # Update task status
            task.status = 'completed'
            self._save_task_to_db(task)
            
            logger.info(f"Completed scan task {task.id} in {duration:.2f} seconds")
            
        except Exception as e:
            logger.error(f"Scan task {task.id} failed: {e}")
            task.status = 'failed'
            self._save_task_to_db(task)
            
            # Create alert for failed scan
            self._create_alert(
                task.target_id,
                'system',
                'medium',
                f'Scan Failed: {task.target_domain}',
                f'Scan task {task.id} failed: {str(e)}',
                {'task_id': task.id, 'error': str(e)}
            )
    
    def _monitoring_loop(self):
        """Continuous monitoring loop"""
        check_interval = self.config['monitoring']['check_interval']
        
        while self.monitoring_active:
            try:
                # Check system performance
                self._check_system_performance()
                
                # Check for stale tasks
                self._check_stale_tasks()
                
                # Clean up old data
                self._cleanup_old_data()
                
                time.sleep(check_interval)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(check_interval)
    
    def _check_system_performance(self):
        """Check system performance and create alerts if needed"""
        try:
            import psutil
            
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent
            
            thresholds = self.config['monitoring']['alert_thresholds']
            
            if cpu_percent > thresholds['system_cpu']:
                self._create_alert(
                    0, 'system', 'high',
                    'High CPU Usage',
                    f'CPU usage is {cpu_percent:.1f}%',
                    {'cpu_percent': cpu_percent, 'threshold': thresholds['system_cpu']}
                )
            
            if memory_percent > thresholds['system_memory']:
                self._create_alert(
                    0, 'system', 'high',
                    'High Memory Usage',
                    f'Memory usage is {memory_percent:.1f}%',
                    {'memory_percent': memory_percent, 'threshold': thresholds['system_memory']}
                )
            
        except ImportError:
            logger.warning("psutil not available, skipping system performance check")
        except Exception as e:
            logger.error(f"System performance check failed: {e}")
    
    def _check_stale_tasks(self):
        """Check for stale/running tasks that have been running too long"""
        timeout = self.config['scheduling']['scan_timeout']
        now = datetime.now()
        
        for task_id, task in self.scan_tasks.items():
            if (task.status == 'running' and task.last_run and
                (now - task.last_run).total_seconds() > timeout):
                
                logger.warning(f"Task {task_id} has been running too long, marking as failed")
                task.status = 'failed'
                self._save_task_to_db(task)
                
                self._create_alert(
                    task.target_id,
                    'system',
                    'medium',
                    'Scan Timeout',
                    f'Scan task {task_id} timed out after {timeout} seconds',
                    {'task_id': task_id, 'timeout': timeout}
                )
    
    def _create_alert(self, target_id: int, alert_type: str, severity: str,
                     title: str, description: str, details: Dict[str, Any]):
        """Create a new alert"""
        alert_id = hashlib.md5(f"{title}_{time.time()}".encode()).hexdigest()[:12]
        
        alert = MonitoringAlert(
            id=alert_id,
            target_id=target_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            details=details,
            timestamp=datetime.now()
        )
        
        self.alerts.append(alert)
        self._save_alert_to_db(alert)
        
        # Send notifications
        self._send_notifications(alert)
        
        logger.info(f"Created alert: {title} ({severity})")
    
    def _check_alerts(self, task: ScanTask, results: Dict[str, Any],
                     ai_analysis: Dict[str, Any], duration: float):
        """Check scan results for potential alerts"""
        thresholds = self.config['monitoring']['alert_thresholds']
        
        # Check vulnerability count
        vuln_count = len(results.get('vulnerabilities', []))
        if vuln_count > thresholds['vulnerability_count']:
            self._create_alert(
                task.target_id,
                'vulnerability',
                'high',
                'High Vulnerability Count',
                f'Found {vuln_count} vulnerabilities on {task.target_domain}',
                {'vulnerability_count': vuln_count, 'threshold': thresholds['vulnerability_count']}
            )
        
        # Check risk score
        risk_score = ai_analysis.get('risk_score', 0)
        if risk_score > thresholds['risk_score']:
            self._create_alert(
                task.target_id,
                'vulnerability',
                'critical',
                'High Risk Score',
                f'Risk score {risk_score:.1f} exceeds threshold for {task.target_domain}',
                {'risk_score': risk_score, 'threshold': thresholds['risk_score']}
            )
        
        # Check scan duration
        if duration > thresholds['scan_duration']:
            self._create_alert(
                task.target_id,
                'performance',
                'medium',
                'Slow Scan Performance',
                f'Scan took {duration:.1f} seconds for {task.target_domain}',
                {'duration': duration, 'threshold': thresholds['scan_duration']}
            )
    
    def _record_performance_metrics(self, task: ScanTask, duration: float,
                                  results: Dict[str, Any], ai_analysis: Dict[str, Any]):
        """Record performance metrics"""
        try:
            import psutil
            
            metrics = PerformanceMetrics(
                scan_id=task.id,
                target_domain=task.target_domain,
                scan_duration=duration,
                vulnerabilities_found=len(results.get('vulnerabilities', [])),
                risk_score=ai_analysis.get('risk_score', 0),
                system_resources={
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_percent': psutil.disk_usage('/').percent
                },
                timestamp=datetime.now()
            )
            
            self.performance_metrics.append(metrics)
            self._save_metrics_to_db(metrics)
            
        except ImportError:
            logger.warning("psutil not available, skipping system metrics")
        except Exception as e:
            logger.error(f"Failed to record performance metrics: {e}")
    
    def _save_alert_to_db(self, alert: MonitoringAlert):
        """Save alert to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO monitoring_alerts 
            (id, target_id, alert_type, severity, title, description, details, timestamp, acknowledged, resolved)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.id, alert.target_id, alert.alert_type, alert.severity,
            alert.title, alert.description, json.dumps(alert.details),
            alert.timestamp.isoformat(), alert.acknowledged, alert.resolved
        ))
        
        conn.commit()
        conn.close()
    
    def _save_metrics_to_db(self, metrics: PerformanceMetrics):
        """Save metrics to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO performance_metrics 
            (scan_id, target_domain, scan_duration, vulnerabilities_found, risk_score, system_resources, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            metrics.scan_id, metrics.target_domain, metrics.scan_duration,
            metrics.vulnerabilities_found, metrics.risk_score,
            json.dumps(metrics.system_resources), metrics.timestamp.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _save_scan_results(self, task: ScanTask, results: Dict[str, Any],
                          ai_analysis: Dict[str, Any], duration: float):
        """Save scan results to file and database"""
        # Save to file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{task.target_domain}_{task.scan_type}_{timestamp}.json"
        filepath = self.output_dir / 'scans' / filename
        
        scan_data = {
            'task_id': task.id,
            'target_domain': task.target_domain,
            'scan_type': task.scan_type,
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'results': results,
            'ai_analysis': ai_analysis
        }
        
        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_history 
            (task_id, target_domain, scan_type, status, results, duration, started_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            task.id, task.target_domain, task.scan_type, 'completed',
            json.dumps(scan_data), duration,
            task.last_run.isoformat(), datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _send_notifications(self, alert: MonitoringAlert):
        """Send notifications for alerts"""
        for handler_name, handler in self.notification_handlers.items():
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Failed to send {handler_name} notification: {e}")
    
    def _send_email_alert(self, alert: MonitoringAlert):
        """Send email alert"""
        config = self.config['notifications']['email']
        
        msg = MIMEMultipart()
        msg['From'] = config['username']
        msg['To'] = ', '.join(config['recipients'])
        msg['Subject'] = f"[{alert.severity.upper()}] {alert.title}"
        
        body = f"""
Alert Details:
- Type: {alert.alert_type}
- Severity: {alert.severity}
- Title: {alert.title}
- Description: {alert.description}
- Time: {alert.timestamp}
- Details: {json.dumps(alert.details, indent=2)}
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
            server.starttls()
            server.login(config['username'], config['password'])
            server.send_message(msg)
    
    def _send_webhook_alert(self, alert: MonitoringAlert):
        """Send webhook alert"""
        config = self.config['notifications']['webhook']
        
        payload = {
            'alert_id': alert.id,
            'type': alert.alert_type,
            'severity': alert.severity,
            'title': alert.title,
            'description': alert.description,
            'timestamp': alert.timestamp.isoformat(),
            'details': alert.details
        }
        
        requests.post(config['url'], json=payload, headers=config['headers'])
    
    def _send_slack_alert(self, alert: MonitoringAlert):
        """Send Slack alert"""
        config = self.config['notifications']['slack']
        
        color_map = {
            'critical': '#ff0000',
            'high': '#ff6600',
            'medium': '#ffcc00',
            'low': '#00cc00',
            'info': '#0066cc'
        }
        
        payload = {
            'channel': config['channel'],
            'attachments': [{
                'color': color_map.get(alert.severity, '#666666'),
                'title': alert.title,
                'text': alert.description,
                'fields': [
                    {'title': 'Type', 'value': alert.alert_type, 'short': True},
                    {'title': 'Severity', 'value': alert.severity, 'short': True},
                    {'title': 'Details', 'value': json.dumps(alert.details, indent=2), 'short': False}
                ],
                'footer': f'Bug Bounty Framework • {alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")}'
            }]
        }
        
        requests.post(config['webhook_url'], json=payload)
    
    def _cleanup_old_data(self):
        """Clean up old data based on retention settings"""
        retention_days = self.config['performance']['metrics_retention_days']
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        # Clean up old metrics
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM performance_metrics WHERE timestamp < ?', 
                      (cutoff_date.isoformat(),))
        
        cursor.execute('DELETE FROM scan_history WHERE created_at < ?',
                      (cutoff_date.isoformat(),))
        
        conn.commit()
        conn.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Task statistics
        cursor.execute('SELECT COUNT(*) FROM scan_tasks WHERE enabled = 1')
        active_tasks = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scan_tasks WHERE status = "running"')
        running_tasks = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scan_history WHERE status = "completed"')
        completed_scans = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scan_history WHERE status = "failed"')
        failed_scans = cursor.fetchone()[0]
        
        # Alert statistics
        cursor.execute('SELECT COUNT(*) FROM monitoring_alerts WHERE resolved = 0')
        active_alerts = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM monitoring_alerts WHERE severity = "critical" AND resolved = 0')
        critical_alerts = cursor.fetchone()[0]
        
        # Performance statistics
        cursor.execute('''
            SELECT AVG(scan_duration), AVG(vulnerabilities_found), AVG(risk_score)
            FROM performance_metrics
            WHERE timestamp > ?
        ''', ((datetime.now() - timedelta(days=7)).isoformat(),))
        
        perf_stats = cursor.fetchone()
        avg_duration = perf_stats[0] if perf_stats[0] else 0
        avg_vulns = perf_stats[1] if perf_stats[1] else 0
        avg_risk = perf_stats[2] if perf_stats[2] else 0
        
        conn.close()
        
        return {
            'active_tasks': active_tasks,
            'running_tasks': running_tasks,
            'completed_scans': completed_scans,
            'failed_scans': failed_scans,
            'active_alerts': active_alerts,
            'critical_alerts': critical_alerts,
            'avg_scan_duration': avg_duration,
            'avg_vulnerabilities': avg_vulns,
            'avg_risk_score': avg_risk,
            'monitoring_active': self.monitoring_active
        }
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, target_id, alert_type, severity, title, description, timestamp, acknowledged, resolved
            FROM monitoring_alerts
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'id': row[0],
                'target_id': row[1],
                'alert_type': row[2],
                'severity': row[3],
                'title': row[4],
                'description': row[5],
                'timestamp': row[6],
                'acknowledged': bool(row[7]),
                'resolved': bool(row[8])
            })
        
        conn.close()
        return alerts

# Global monitoring instance
monitoring_system = None

def initialize_monitoring(config_path: str = 'monitoring_config.yml'):
    """Initialize the global monitoring system"""
    global monitoring_system
    monitoring_system = AutomatedMonitoring(config_path)
    return monitoring_system

def get_monitoring_system() -> AutomatedMonitoring:
    """Get the global monitoring system instance"""
    if monitoring_system is None:
        raise RuntimeError("Monitoring system not initialized. Call initialize_monitoring() first.")
    return monitoring_system 