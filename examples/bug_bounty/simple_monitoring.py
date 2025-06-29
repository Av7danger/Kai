#!/usr/bin/env python3
"""
🔄 Simple Automated Monitoring & Scheduling
Basic monitoring and scheduling for bug bounty framework

Features:
- Automated scan scheduling
- Basic monitoring and alerting
- Performance tracking
- Simple notification system
"""

import os
import json
import time
import threading
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dataclasses import dataclass
from pathlib import Path
import logging
import requests

# Import our modules
from advanced_recon_tools import AdvancedReconTools
from ai_integration import get_ai_integration

logger = logging.getLogger(__name__)

@dataclass
class ScanTask:
    """Scan task configuration"""
    id: str
    target_domain: str
    scan_type: str
    schedule_hours: int  # Run every X hours
    last_run: datetime
    next_run: datetime
    status: str  # pending, running, completed, failed
    enabled: bool = True

@dataclass
class Alert:
    """Simple alert"""
    id: str
    target_domain: str
    alert_type: str
    severity: str
    message: str
    timestamp: datetime

class SimpleMonitoring:
    """Simple monitoring and scheduling system"""
    
    def __init__(self):
        self.recon_tools = AdvancedReconTools()
        self.ai_agent = get_ai_integration()
        
        # Task management
        self.scan_tasks: Dict[str, ScanTask] = {}
        self.monitoring_active = False
        
        # Alerts and metrics
        self.alerts: List[Alert] = []
        self.performance_metrics: List[Dict[str, Any]] = []
        
        # Database
        self.db_path = 'simple_monitoring.db'
        self._init_database()
        
        # Create output directory
        self.output_dir = Path('monitoring_output')
        self.output_dir.mkdir(exist_ok=True)
    
    def _init_database(self):
        """Initialize simple database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scan tasks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_tasks (
                id TEXT PRIMARY KEY,
                target_domain TEXT,
                scan_type TEXT,
                schedule_hours INTEGER,
                last_run TEXT,
                next_run TEXT,
                status TEXT,
                enabled INTEGER
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                target_domain TEXT,
                alert_type TEXT,
                severity TEXT,
                message TEXT,
                timestamp TEXT
            )
        ''')
        
        # Performance metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_domain TEXT,
                scan_type TEXT,
                duration REAL,
                vulnerabilities_found INTEGER,
                risk_score REAL,
                timestamp TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_scan_task(self, target_domain: str, scan_type: str = 'full', 
                     schedule_hours: int = 24) -> str:
        """Add a new scan task"""
        import hashlib
        
        task_id = hashlib.md5(f"{target_domain}_{scan_type}_{time.time()}".encode()).hexdigest()[:8]
        now = datetime.now()
        
        task = ScanTask(
            id=task_id,
            target_domain=target_domain,
            scan_type=scan_type,
            schedule_hours=schedule_hours,
            last_run=now,
            next_run=now + timedelta(hours=schedule_hours),
            status='pending',
            enabled=True
        )
        
        self.scan_tasks[task_id] = task
        self._save_task_to_db(task)
        
        logger.info(f"Added scan task {task_id} for {target_domain}")
        return task_id
    
    def _save_task_to_db(self, task: ScanTask):
        """Save task to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO scan_tasks 
            (id, target_domain, scan_type, schedule_hours, last_run, next_run, status, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            task.id, task.target_domain, task.scan_type, task.schedule_hours,
            task.last_run.isoformat(), task.next_run.isoformat(), task.status, task.enabled
        ))
        
        conn.commit()
        conn.close()
    
    def start_monitoring(self):
        """Start the monitoring system"""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        logger.info("Starting simple monitoring system")
        
        # Start monitoring thread
        monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop the monitoring system"""
        self.monitoring_active = False
        logger.info("Stopping simple monitoring system")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                now = datetime.now()
                
                # Check for tasks that need to run
                for task_id, task in self.scan_tasks.items():
                    if task.enabled and task.status != 'running' and task.next_run <= now:
                        # Execute task in a separate thread
                        task_thread = threading.Thread(
                            target=self._execute_scan_task,
                            args=(task,),
                            daemon=True
                        )
                        task_thread.start()
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(60)
    
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
            
            # Execute scan
            if task.scan_type == 'full':
                results = self.recon_tools.run_full_reconnaissance(task.target_domain)
            elif task.scan_type == 'quick':
                results = self.recon_tools.run_quick_reconnaissance(task.target_domain)
            else:
                results = self.recon_tools.run_custom_reconnaissance(
                    task.target_domain, [task.scan_type]
                )
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Run AI analysis
            ai_analysis = self.ai_agent.analyze_recon_data(results)
            
            # Record performance metrics
            self._record_metrics(task, duration, results, ai_analysis)
            
            # Check for alerts
            self._check_alerts(task, results, ai_analysis, duration)
            
            # Save results
            self._save_results(task, results, ai_analysis, duration)
            
            # Update task status and next run
            task.status = 'completed'
            task.next_run = datetime.now() + timedelta(hours=task.schedule_hours)
            self._save_task_to_db(task)
            
            logger.info(f"Completed scan task {task.id} in {duration:.2f} seconds")
            
        except Exception as e:
            logger.error(f"Scan task {task.id} failed: {e}")
            task.status = 'failed'
            self._save_task_to_db(task)
            
            # Create alert for failed scan
            self._create_alert(
                task.target_domain,
                'system',
                'medium',
                f'Scan failed for {task.target_domain}: {str(e)}'
            )
    
    def _record_metrics(self, task: ScanTask, duration: float, 
                       results: Dict[str, Any], ai_analysis: Dict[str, Any]):
        """Record performance metrics"""
        metrics = {
            'target_domain': task.target_domain,
            'scan_type': task.scan_type,
            'duration': duration,
            'vulnerabilities_found': len(results.get('vulnerabilities', [])),
            'risk_score': ai_analysis.get('risk_score', 0),
            'timestamp': datetime.now().isoformat()
        }
        
        self.performance_metrics.append(metrics)
        self._save_metrics_to_db(metrics)
    
    def _check_alerts(self, task: ScanTask, results: Dict[str, Any],
                     ai_analysis: Dict[str, Any], duration: float):
        """Check for potential alerts"""
        # Check vulnerability count
        vuln_count = len(results.get('vulnerabilities', []))
        if vuln_count > 10:
            self._create_alert(
                task.target_domain,
                'vulnerability',
                'high',
                f'High vulnerability count: {vuln_count} vulnerabilities found'
            )
        
        # Check risk score
        risk_score = ai_analysis.get('risk_score', 0)
        if risk_score > 7.0:
            self._create_alert(
                task.target_domain,
                'vulnerability',
                'critical',
                f'High risk score: {risk_score:.1f}/10'
            )
        
        # Check scan duration
        if duration > 1800:  # 30 minutes
            self._create_alert(
                task.target_domain,
                'performance',
                'medium',
                f'Slow scan performance: {duration:.1f} seconds'
            )
    
    def _create_alert(self, target_domain: str, alert_type: str, 
                     severity: str, message: str):
        """Create a new alert"""
        import hashlib
        
        alert_id = hashlib.md5(f"{message}_{time.time()}".encode()).hexdigest()[:8]
        
        alert = Alert(
            id=alert_id,
            target_domain=target_domain,
            alert_type=alert_type,
            severity=severity,
            message=message,
            timestamp=datetime.now()
        )
        
        self.alerts.append(alert)
        self._save_alert_to_db(alert)
        
        logger.info(f"Created alert: {message} ({severity})")
    
    def _save_alert_to_db(self, alert: Alert):
        """Save alert to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts 
            (id, target_domain, alert_type, severity, message, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert.id, alert.target_domain, alert.alert_type, 
            alert.severity, alert.message, alert.timestamp.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _save_metrics_to_db(self, metrics: Dict[str, Any]):
        """Save metrics to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO performance_metrics 
            (target_domain, scan_type, duration, vulnerabilities_found, risk_score, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            metrics['target_domain'], metrics['scan_type'], metrics['duration'],
            metrics['vulnerabilities_found'], metrics['risk_score'], metrics['timestamp']
        ))
        
        conn.commit()
        conn.close()
    
    def _save_results(self, task: ScanTask, results: Dict[str, Any],
                     ai_analysis: Dict[str, Any], duration: float):
        """Save scan results"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{task.target_domain}_{task.scan_type}_{timestamp}.json"
        filepath = self.output_dir / filename
        
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
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Task statistics
        cursor.execute('SELECT COUNT(*) FROM scan_tasks WHERE enabled = 1')
        active_tasks = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scan_tasks WHERE status = "running"')
        running_tasks = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scan_tasks WHERE status = "completed"')
        completed_tasks = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scan_tasks WHERE status = "failed"')
        failed_tasks = cursor.fetchone()[0]
        
        # Alert statistics
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE severity = "critical"')
        critical_alerts = cursor.fetchone()[0]
        
        # Performance statistics
        cursor.execute('''
            SELECT AVG(duration), AVG(vulnerabilities_found), AVG(risk_score)
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
            'completed_tasks': completed_tasks,
            'failed_tasks': failed_tasks,
            'total_alerts': total_alerts,
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
            SELECT id, target_domain, alert_type, severity, message, timestamp
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'id': row[0],
                'target_domain': row[1],
                'alert_type': row[2],
                'severity': row[3],
                'message': row[4],
                'timestamp': row[5]
            })
        
        conn.close()
        return alerts

# Global monitoring instance
simple_monitoring = None

def initialize_simple_monitoring():
    """Initialize the global simple monitoring system"""
    global simple_monitoring
    simple_monitoring = SimpleMonitoring()
    return simple_monitoring

def get_simple_monitoring() -> SimpleMonitoring:
    """Get the global simple monitoring system instance"""
    if simple_monitoring is None:
        raise RuntimeError("Simple monitoring not initialized. Call initialize_simple_monitoring() first.")
    return simple_monitoring 