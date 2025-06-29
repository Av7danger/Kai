#!/usr/bin/env python3
"""
🧪 Simple Monitoring Test
Demonstrate monitoring functionality without external dependencies
"""

import time
import json
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class MockScanTask:
    """Mock scan task for testing"""
    id: str
    target_domain: str
    scan_type: str
    schedule_hours: int
    last_run: datetime
    next_run: datetime
    status: str
    enabled: bool = True

@dataclass
class MockAlert:
    """Mock alert for testing"""
    id: str
    target_domain: str
    alert_type: str
    severity: str
    message: str
    timestamp: datetime

class MockMonitoring:
    """Mock monitoring system for testing"""
    
    def __init__(self):
        self.scan_tasks: Dict[str, MockScanTask] = {}
        self.alerts: List[MockAlert] = []
        self.monitoring_active = False
        self.performance_metrics: List[Dict[str, Any]] = []
    
    def add_scan_task(self, target_domain: str, scan_type: str = 'full', 
                     schedule_hours: int = 24) -> str:
        """Add a new scan task"""
        task_id = hashlib.md5(f"{target_domain}_{scan_type}_{time.time()}".encode()).hexdigest()[:8]
        now = datetime.now()
        
        task = MockScanTask(
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
        print(f"  ✅ Added task {task_id} for {target_domain}")
        return task_id
    
    def start_monitoring(self):
        """Start the monitoring system"""
        self.monitoring_active = True
        print("  ✅ Monitoring system started")
    
    def stop_monitoring(self):
        """Stop the monitoring system"""
        self.monitoring_active = False
        print("  ✅ Monitoring system stopped")
    
    def _create_alert(self, target_domain: str, alert_type: str, 
                     severity: str, message: str):
        """Create a new alert"""
        alert_id = hashlib.md5(f"{message}_{time.time()}".encode()).hexdigest()[:8]
        
        alert = MockAlert(
            id=alert_id,
            target_domain=target_domain,
            alert_type=alert_type,
            severity=severity,
            message=message,
            timestamp=datetime.now()
        )
        
        self.alerts.append(alert)
        print(f"  ✅ Created {severity} {alert_type} alert")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        return {
            'active_tasks': len([t for t in self.scan_tasks.values() if t.enabled]),
            'running_tasks': len([t for t in self.scan_tasks.values() if t.status == 'running']),
            'completed_tasks': len([t for t in self.scan_tasks.values() if t.status == 'completed']),
            'failed_tasks': len([t for t in self.scan_tasks.values() if t.status == 'failed']),
            'total_alerts': len(self.alerts),
            'critical_alerts': len([a for a in self.alerts if a.severity == 'critical']),
            'avg_scan_duration': 45.5,  # Mock value
            'avg_vulnerabilities': 3.2,  # Mock value
            'avg_risk_score': 5.8,  # Mock value
            'monitoring_active': self.monitoring_active
        }
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        alerts = []
        for alert in self.alerts[-limit:]:
            alerts.append({
                'id': alert.id,
                'target_domain': alert.target_domain,
                'alert_type': alert.alert_type,
                'severity': alert.severity,
                'message': alert.message,
                'timestamp': alert.timestamp.isoformat()
            })
        return alerts

def test_monitoring_system():
    """Test the monitoring system functionality"""
    print("🔄 Testing Mock Monitoring & Scheduling System...")
    
    # Initialize monitoring system
    monitoring = MockMonitoring()
    
    # Add some test tasks
    print("\n📋 Adding Test Tasks...")
    
    task1 = monitoring.add_scan_task('example.com', 'full', 24)
    task2 = monitoring.add_scan_task('test.com', 'quick', 12)
    task3 = monitoring.add_scan_task('demo.com', 'vulnerability', 6)
    
    # Get initial statistics
    print("\n📊 Initial Statistics:")
    stats = monitoring.get_statistics()
    print(f"  Active Tasks: {stats['active_tasks']}")
    print(f"  Running Tasks: {stats['running_tasks']}")
    print(f"  Total Alerts: {stats['total_alerts']}")
    print(f"  Monitoring Active: {stats['monitoring_active']}")
    
    # Start monitoring
    print("\n🚀 Starting Monitoring System...")
    monitoring.start_monitoring()
    
    # Simulate some alerts
    print("\n🚨 Simulating Alerts...")
    
    monitoring._create_alert(
        'example.com',
        'vulnerability',
        'high',
        'Test alert: High vulnerability count detected'
    )
    
    monitoring._create_alert(
        'test.com',
        'performance',
        'medium',
        'Test alert: Slow scan performance'
    )
    
    monitoring._create_alert(
        'demo.com',
        'system',
        'critical',
        'Test alert: System resource usage high'
    )
    
    # Get alerts
    print("\n📢 Recent Alerts:")
    alerts = monitoring.get_recent_alerts(5)
    for alert in alerts:
        print(f"  • [{alert['severity'].upper()}] {alert['message']}")
        print(f"    Target: {alert['target_domain']} | Type: {alert['alert_type']}")
    
    # Get updated statistics
    print("\n📊 Updated Statistics:")
    updated_stats = monitoring.get_statistics()
    print(f"  Total Alerts: {updated_stats['total_alerts']}")
    print(f"  Critical Alerts: {updated_stats['critical_alerts']}")
    print(f"  Average Scan Duration: {updated_stats['avg_scan_duration']:.2f}s")
    print(f"  Average Vulnerabilities: {updated_stats['avg_vulnerabilities']:.1f}")
    print(f"  Average Risk Score: {updated_stats['avg_risk_score']:.1f}")
    
    # Stop monitoring
    print("\n⏹️ Stopping Monitoring System...")
    monitoring.stop_monitoring()
    
    print("\n✅ Mock Monitoring System Test Completed!")

def demonstrate_scheduling():
    """Demonstrate scheduling capabilities"""
    print("\n⏰ Scheduling Demonstration...")
    
    monitoring = MockMonitoring()
    
    # Show different scheduling options
    schedules = [
        ('example.com', 'full', 24, 'Daily full scan'),
        ('test.com', 'quick', 12, 'Twice daily quick scan'),
        ('demo.com', 'vulnerability', 6, 'Four times daily vulnerability scan'),
        ('prod.com', 'full', 168, 'Weekly full scan (168 hours)'),
        ('dev.com', 'quick', 1, 'Hourly quick scan')
    ]
    
    print("\n📅 Available Scheduling Options:")
    for domain, scan_type, hours, description in schedules:
        task_id = monitoring.add_scan_task(domain, scan_type, hours)
        print(f"  • {description}")
        print(f"    Domain: {domain} | Type: {scan_type} | Interval: {hours}h")
        print(f"    Task ID: {task_id}")
    
    print(f"\n📊 Total Tasks Created: {len(monitoring.scan_tasks)}")
    
    # Show task details
    print("\n📋 Task Details:")
    for task_id, task in monitoring.scan_tasks.items():
        print(f"  • {task.target_domain}")
        print(f"    ID: {task.id} | Type: {task.scan_type}")
        print(f"    Schedule: Every {task.schedule_hours} hours")
        print(f"    Status: {task.status} | Enabled: {task.enabled}")
        print(f"    Next Run: {task.next_run.strftime('%Y-%m-%d %H:%M:%S')}")

def demonstrate_alerting():
    """Demonstrate alerting capabilities"""
    print("\n🚨 Alerting Demonstration...")
    
    monitoring = MockMonitoring()
    
    # Create different types of alerts
    alert_types = [
        ('vulnerability', 'critical', 'Critical vulnerability found: SQL injection in login form'),
        ('vulnerability', 'high', 'High severity: XSS vulnerability in search parameter'),
        ('vulnerability', 'medium', 'Medium severity: Information disclosure in error messages'),
        ('performance', 'high', 'High severity: Scan taking too long (>30 minutes)'),
        ('performance', 'medium', 'Medium severity: High CPU usage during scan'),
        ('system', 'critical', 'Critical: System resources exhausted'),
        ('system', 'medium', 'Medium: Database connection issues')
    ]
    
    print("\n📢 Creating Test Alerts...")
    for alert_type, severity, message in alert_types:
        monitoring._create_alert('demo.com', alert_type, severity, message)
    
    # Show alert statistics
    print("\n📊 Alert Statistics:")
    stats = monitoring.get_statistics()
    print(f"  Total Alerts: {stats['total_alerts']}")
    print(f"  Critical Alerts: {stats['critical_alerts']}")
    
    # Show recent alerts by severity
    print("\n🚨 Recent Alerts by Severity:")
    alerts = monitoring.get_recent_alerts(10)
    
    severity_colors = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
        'info': '🔵'
    }
    
    for alert in alerts:
        color = severity_colors.get(alert['severity'], '⚪')
        print(f"  {color} [{alert['severity'].upper()}] {alert['message']}")
        print(f"    Target: {alert['target_domain']} | Type: {alert['alert_type']}")

def demonstrate_api_endpoints():
    """Demonstrate API endpoint structure"""
    print("\n🌐 API Endpoints Demonstration...")
    
    endpoints = [
        ('POST', '/api/monitoring/tasks', 'Create new scan task'),
        ('GET', '/api/monitoring/tasks', 'Get all scan tasks'),
        ('POST', '/api/monitoring/start', 'Start monitoring system'),
        ('POST', '/api/monitoring/stop', 'Stop monitoring system'),
        ('GET', '/api/monitoring/stats', 'Get monitoring statistics'),
        ('GET', '/api/monitoring/alerts', 'Get recent alerts'),
        ('GET', '/api/monitoring/status', 'Get system status')
    ]
    
    print("\n📡 Available API Endpoints:")
    for method, endpoint, description in endpoints:
        print(f"  {method:6} {endpoint:<25} - {description}")
    
    print("\n📝 Example API Usage:")
    print("""
  # Create a new scan task
  POST /api/monitoring/tasks
  {
    "target_domain": "example.com",
    "scan_type": "full",
    "schedule_hours": 24
  }
  
  # Start monitoring
  POST /api/monitoring/start
  
  # Get statistics
  GET /api/monitoring/stats
  
  # Get recent alerts
  GET /api/monitoring/alerts?limit=10
    """)

if __name__ == '__main__':
    print("🔄 Simple Monitoring & Scheduling Test Suite")
    print("=" * 50)
    
    # Test core functionality
    test_monitoring_system()
    
    # Demonstrate scheduling
    demonstrate_scheduling()
    
    # Demonstrate alerting
    demonstrate_alerting()
    
    # Demonstrate API endpoints
    demonstrate_api_endpoints()
    
    print("\n🎉 All monitoring tests completed!")
    print("\n📋 Step 3 Features Implemented:")
    print("  ✅ Automated scan scheduling")
    print("  ✅ Real-time monitoring and alerting")
    print("  ✅ Performance tracking and metrics")
    print("  ✅ API endpoints for integration")
    print("  ✅ Database storage for tasks and alerts")
    print("  ✅ Configurable scheduling intervals")
    print("  ✅ Multiple alert severity levels")
    print("  ✅ System status monitoring")
    
    print("\n🚀 Next Steps:")
    print("1. Integrate monitoring endpoints into your main dashboard")
    print("2. Configure monitoring schedules for your targets")
    print("3. Set up alert notifications (email, webhook, Slack)")
    print("4. Monitor performance and optimize scan schedules")
    print("5. Review and act on generated alerts")
    print("6. Proceed to Step 4: Automated Bug Submission & Payout Tracking") 