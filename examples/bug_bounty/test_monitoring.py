#!/usr/bin/env python3
"""
🧪 Test Monitoring & Scheduling System
Demonstrate the automated monitoring functionality
"""

import time
import json
from simple_monitoring import initialize_simple_monitoring, get_simple_monitoring
from monitoring_api import monitoring_bp
from flask import Flask

def test_monitoring_system():
    """Test the monitoring system functionality"""
    print("🔄 Testing Monitoring & Scheduling System...")
    
    # Initialize monitoring system
    monitoring = initialize_simple_monitoring()
    
    # Add some test tasks
    print("\n📋 Adding Test Tasks...")
    
    task1 = monitoring.add_scan_task('example.com', 'full', 24)
    print(f"  ✅ Added task {task1} for example.com (daily full scan)")
    
    task2 = monitoring.add_scan_task('test.com', 'quick', 12)
    print(f"  ✅ Added task {task2} for test.com (12-hour quick scan)")
    
    task3 = monitoring.add_scan_task('demo.com', 'vulnerability', 6)
    print(f"  ✅ Added task {task3} for demo.com (6-hour vulnerability scan)")
    
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
    
    # Wait a bit for monitoring to start
    time.sleep(2)
    
    # Check status
    print("\n📈 Monitoring Status:")
    status_stats = monitoring.get_statistics()
    print(f"  Monitoring Active: {status_stats['monitoring_active']}")
    print(f"  Active Tasks: {status_stats['active_tasks']}")
    
    # Simulate some alerts
    print("\n🚨 Simulating Alerts...")
    
    # Create test alerts
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
    
    print("\n✅ Monitoring System Test Completed!")

def test_api_endpoints():
    """Test API endpoints"""
    print("\n🌐 Testing API Endpoints...")
    
    # Create Flask app for testing
    app = Flask(__name__)
    app.register_blueprint(monitoring_bp, url_prefix='/api/monitoring')
    
    with app.test_client() as client:
        # Test task creation
        print("\n📋 Testing Task Creation...")
        response = client.post('/api/monitoring/tasks',
                             json={
                                 'target_domain': 'api-test.com',
                                 'scan_type': 'full',
                                 'schedule_hours': 24
                             },
                             content_type='application/json')
        
        if response.status_code == 200:
            result = response.get_json()
            print(f"  ✅ Task created: {result['task_id']}")
        else:
            print(f"  ❌ Task creation failed: {response.get_json()}")
        
        # Test getting tasks
        print("\n📋 Testing Get Tasks...")
        response = client.get('/api/monitoring/tasks')
        
        if response.status_code == 200:
            result = response.get_json()
            print(f"  ✅ Retrieved {len(result['tasks'])} tasks")
        else:
            print(f"  ❌ Get tasks failed: {response.get_json()}")
        
        # Test monitoring start
        print("\n🚀 Testing Start Monitoring...")
        response = client.post('/api/monitoring/start')
        
        if response.status_code == 200:
            result = response.get_json()
            print(f"  ✅ {result['message']}")
        else:
            print(f"  ❌ Start monitoring failed: {response.get_json()}")
        
        # Test get status
        print("\n📊 Testing Get Status...")
        response = client.get('/api/monitoring/status')
        
        if response.status_code == 200:
            result = response.get_json()
            status = result['status']
            print(f"  ✅ Monitoring Active: {status['monitoring_active']}")
            print(f"  ✅ Active Tasks: {status['active_tasks']}")
            print(f"  ✅ Running Tasks: {status['running_tasks']}")
        else:
            print(f"  ❌ Get status failed: {response.get_json()}")
        
        # Test get stats
        print("\n📈 Testing Get Stats...")
        response = client.get('/api/monitoring/stats')
        
        if response.status_code == 200:
            result = response.get_json()
            stats = result['statistics']
            print(f"  ✅ Active Tasks: {stats['active_tasks']}")
            print(f"  ✅ Total Alerts: {stats['total_alerts']}")
        else:
            print(f"  ❌ Get stats failed: {response.get_json()}")
        
        # Test get alerts
        print("\n🚨 Testing Get Alerts...")
        response = client.get('/api/monitoring/alerts?limit=5')
        
        if response.status_code == 200:
            result = response.get_json()
            print(f"  ✅ Retrieved {len(result['alerts'])} alerts")
        else:
            print(f"  ❌ Get alerts failed: {response.get_json()}")
        
        # Test monitoring stop
        print("\n⏹️ Testing Stop Monitoring...")
        response = client.post('/api/monitoring/stop')
        
        if response.status_code == 200:
            result = response.get_json()
            print(f"  ✅ {result['message']}")
        else:
            print(f"  ❌ Stop monitoring failed: {response.get_json()}")

def demonstrate_scheduling():
    """Demonstrate scheduling capabilities"""
    print("\n⏰ Scheduling Demonstration...")
    
    monitoring = get_simple_monitoring()
    
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
    
    monitoring = get_simple_monitoring()
    
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
        print(f"  ✅ Created {severity} {alert_type} alert")
    
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

if __name__ == '__main__':
    print("🔄 Monitoring & Scheduling Test Suite")
    print("=" * 50)
    
    # Test core functionality
    test_monitoring_system()
    
    # Test API endpoints
    test_api_endpoints()
    
    # Demonstrate scheduling
    demonstrate_scheduling()
    
    # Demonstrate alerting
    demonstrate_alerting()
    
    print("\n🎉 All monitoring tests completed!")
    print("\nNext steps:")
    print("1. Integrate monitoring endpoints into your main dashboard")
    print("2. Configure monitoring schedules for your targets")
    print("3. Set up alert notifications (email, webhook, Slack)")
    print("4. Monitor performance and optimize scan schedules")
    print("5. Review and act on generated alerts") 