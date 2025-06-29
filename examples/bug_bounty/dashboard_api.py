#!/usr/bin/env python3
"""
📊 Dashboard API Endpoints
RESTful API for dashboard functionality and framework integration

Features:
- Framework component status endpoints
- Real-time data streaming
- Analytics and reporting endpoints
- User management endpoints
- Export and backup endpoints
"""

import os
import json
import time
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import asdict
from pathlib import Path
import logging
from flask import Flask, request, jsonify, Response, stream_template
from flask_cors import CORS
import yaml

# Import framework components
try:
    from recon_manager import get_recon_manager
    from ai_analysis import get_ai_manager
    from monitoring_manager import get_monitoring_manager
    from bug_submission import get_submission_manager
    from exploit_manager import get_exploit_manager
    FRAMEWORK_AVAILABLE = True
except ImportError:
    FRAMEWORK_AVAILABLE = False
    print("Warning: Some framework components not available")

logger = logging.getLogger(__name__)

class DashboardAPI:
    """Dashboard API server"""
    
    def __init__(self, config_path: str = 'dashboard_config.yml'):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize Flask app
        self.app = Flask(__name__)
        CORS(self.app)  # Enable CORS for all routes
        
        # Framework managers
        self.framework_managers = {}
        if FRAMEWORK_AVAILABLE:
            self._initialize_framework_managers()
        
        # Setup routes
        self._setup_routes()
        
        # Database
        self.db_path = 'dashboard.db'
        self._init_database()
    
    def _load_config(self) -> Dict:
        """Load dashboard configuration"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default dashboard configuration"""
        return {
            'api': {
                'host': '0.0.0.0',
                'port': 5001,
                'debug': False,
                'cors_enabled': True
            },
            'security': {
                'api_key_required': False,
                'rate_limit': 100,
                'timeout': 30
            }
        }
    
    def _init_database(self):
        """Initialize dashboard database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # API logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                endpoint TEXT,
                method TEXT,
                status_code INTEGER,
                response_time REAL,
                user_agent TEXT,
                ip_address TEXT
            )
        ''')
        
        # Analytics data table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analytics_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                metric_name TEXT,
                metric_value REAL,
                category TEXT,
                metadata TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _initialize_framework_managers(self):
        """Initialize framework component managers"""
        try:
            self.framework_managers['recon'] = get_recon_manager()
        except:
            logger.warning("Reconnaissance manager not available")
        
        try:
            self.framework_managers['ai'] = get_ai_manager()
        except:
            logger.warning("AI analysis manager not available")
        
        try:
            self.framework_managers['monitoring'] = get_monitoring_manager()
        except:
            logger.warning("Monitoring manager not available")
        
        try:
            self.framework_managers['submission'] = get_submission_manager()
        except:
            logger.warning("Submission manager not available")
        
        try:
            self.framework_managers['exploitation'] = get_exploit_manager()
        except:
            logger.warning("Exploitation manager not available")
    
    def _setup_routes(self):
        """Setup API routes"""
        
        # Health check
        @self.app.route('/api/health', methods=['GET'])
        def health_check():
            """Health check endpoint"""
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'framework_available': FRAMEWORK_AVAILABLE,
                'components': list(self.framework_managers.keys())
            })
        
        # Framework status
        @self.app.route('/api/framework/status', methods=['GET'])
        def framework_status():
            """Get framework component status"""
            status = {}
            
            for name, manager in self.framework_managers.items():
                try:
                    if hasattr(manager, 'get_all_sessions'):
                        sessions = manager.get_all_sessions()
                        status[name] = {
                            'available': True,
                            'active_sessions': len(sessions),
                            'status': 'operational'
                        }
                    elif hasattr(manager, 'targets'):
                        status[name] = {
                            'available': True,
                            'targets': len(manager.targets),
                            'status': 'operational'
                        }
                    else:
                        status[name] = {
                            'available': True,
                            'status': 'operational'
                        }
                except Exception as e:
                    status[name] = {
                        'available': False,
                        'status': 'error',
                        'error': str(e)
                    }
            
            return jsonify(status)
        
        # Reconnaissance data
        @self.app.route('/api/recon/data', methods=['GET'])
        def recon_data():
            """Get reconnaissance data"""
            if 'recon' not in self.framework_managers:
                return jsonify({'error': 'Reconnaissance manager not available'}), 503
            
            try:
                recon_manager = self.framework_managers['recon']
                
                # Get targets
                targets = []
                for target_id, target in recon_manager.targets.items():
                    targets.append({
                        'id': target_id,
                        'domain': target.domain,
                        'status': target.status,
                        'last_scan': target.last_scan.isoformat() if target.last_scan else None,
                        'vulnerabilities_found': target.vulnerabilities_found,
                        'risk_score': target.risk_score
                    })
                
                # Get active scans
                active_scans = []
                for session_id, session in recon_manager.scan_sessions.items():
                    if session.status == 'running':
                        active_scans.append({
                            'id': session_id,
                            'target': session.target_domain,
                            'start_time': session.start_time.isoformat(),
                            'progress': session.progress,
                            'current_tool': session.current_tool
                        })
                
                return jsonify({
                    'targets': targets,
                    'active_scans': active_scans,
                    'total_targets': len(targets),
                    'active_scan_count': len(active_scans)
                })
            
            except Exception as e:
                logger.error(f"Error getting recon data: {e}")
                return jsonify({'error': str(e)}), 500
        
        # AI Analysis data
        @self.app.route('/api/ai/data', methods=['GET'])
        def ai_data():
            """Get AI analysis data"""
            if 'ai' not in self.framework_managers:
                return jsonify({'error': 'AI analysis manager not available'}), 503
            
            try:
                ai_manager = self.framework_managers['ai']
                
                # Get analysis sessions
                sessions = []
                for session_id, session in ai_manager.analysis_sessions.items():
                    sessions.append({
                        'id': session_id,
                        'target': session.target_domain,
                        'status': session.status,
                        'start_time': session.start_time.isoformat(),
                        'analysis_type': session.analysis_type,
                        'findings_count': len(session.findings)
                    })
                
                # Get recent findings
                recent_findings = []
                for finding in ai_manager.recent_findings[-10:]:  # Last 10 findings
                    recent_findings.append({
                        'id': finding.id,
                        'target': finding.target_domain,
                        'type': finding.finding_type,
                        'severity': finding.severity,
                        'description': finding.description,
                        'timestamp': finding.timestamp.isoformat()
                    })
                
                return jsonify({
                    'sessions': sessions,
                    'recent_findings': recent_findings,
                    'total_sessions': len(sessions),
                    'total_findings': len(ai_manager.recent_findings)
                })
            
            except Exception as e:
                logger.error(f"Error getting AI data: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Monitoring data
        @self.app.route('/api/monitoring/data', methods=['GET'])
        def monitoring_data():
            """Get monitoring data"""
            if 'monitoring' not in self.framework_managers:
                return jsonify({'error': 'Monitoring manager not available'}), 503
            
            try:
                monitoring_manager = self.framework_managers['monitoring']
                
                # Get active tasks
                active_tasks = []
                for task_id, task in monitoring_manager.active_tasks.items():
                    active_tasks.append({
                        'id': task_id,
                        'target': task.target_domain,
                        'task_type': task.task_type,
                        'status': task.status,
                        'start_time': task.start_time.isoformat(),
                        'next_run': task.next_run.isoformat() if task.next_run else None
                    })
                
                # Get recent alerts
                recent_alerts = []
                for alert in monitoring_manager.recent_alerts[-10:]:  # Last 10 alerts
                    recent_alerts.append({
                        'id': alert.id,
                        'target': alert.target_domain,
                        'severity': alert.severity,
                        'message': alert.message,
                        'timestamp': alert.timestamp.isoformat()
                    })
                
                return jsonify({
                    'active_tasks': active_tasks,
                    'recent_alerts': recent_alerts,
                    'total_tasks': len(active_tasks),
                    'total_alerts': len(monitoring_manager.recent_alerts)
                })
            
            except Exception as e:
                logger.error(f"Error getting monitoring data: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Submissions data
        @self.app.route('/api/submissions/data', methods=['GET'])
        def submissions_data():
            """Get submissions data"""
            if 'submission' not in self.framework_managers:
                return jsonify({'error': 'Submission manager not available'}), 503
            
            try:
                submission_manager = self.framework_managers['submission']
                
                # Get submissions
                submissions = []
                for submission_id, submission in submission_manager.submissions.items():
                    submissions.append({
                        'id': submission_id,
                        'platform': submission.platform,
                        'title': submission.title,
                        'status': submission.submission_status,
                        'severity': submission.severity,
                        'submitted_at': submission.submitted_at.isoformat(),
                        'reward': submission.reward
                    })
                
                # Get payouts
                payouts = []
                for payout_id, payout in submission_manager.payouts.items():
                    payouts.append({
                        'id': payout_id,
                        'submission_id': payout.submission_id,
                        'amount': payout.amount,
                        'status': payout.status,
                        'paid_at': payout.paid_at.isoformat() if payout.paid_at else None
                    })
                
                return jsonify({
                    'submissions': submissions,
                    'payouts': payouts,
                    'total_submissions': len(submissions),
                    'total_payouts': len(payouts),
                    'total_reward': sum(p.amount for p in submission_manager.payouts.values() if p.status == 'paid')
                })
            
            except Exception as e:
                logger.error(f"Error getting submissions data: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Exploitation data
        @self.app.route('/api/exploitation/data', methods=['GET'])
        def exploitation_data():
            """Get exploitation data"""
            if 'exploitation' not in self.framework_managers:
                return jsonify({'error': 'Exploitation manager not available'}), 503
            
            try:
                exploit_manager = self.framework_managers['exploitation']
                
                # Get active sessions
                active_sessions = []
                for session_id, session in exploit_manager.active_sessions.items():
                    active_sessions.append({
                        'id': session_id,
                        'target': session.target_domain,
                        'status': session.status,
                        'start_time': session.start_time.isoformat(),
                        'exploit_type': session.exploit_type,
                        'privilege_level': session.privilege_level
                    })
                
                # Get recent payloads
                recent_payloads = []
                for payload in exploit_manager.recent_payloads[-10:]:  # Last 10 payloads
                    recent_payloads.append({
                        'id': payload.id,
                        'target': payload.target_domain,
                        'type': payload.payload_type,
                        'success': payload.success,
                        'timestamp': payload.timestamp.isoformat()
                    })
                
                return jsonify({
                    'active_sessions': active_sessions,
                    'recent_payloads': recent_payloads,
                    'total_sessions': len(active_sessions),
                    'total_payloads': len(exploit_manager.recent_payloads)
                })
            
            except Exception as e:
                logger.error(f"Error getting exploitation data: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Analytics endpoints
        @self.app.route('/api/analytics/vulnerability-trends', methods=['GET'])
        def vulnerability_trends():
            """Get vulnerability discovery trends"""
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT DATE(timestamp) as date, COUNT(*) as count
                    FROM analytics_data 
                    WHERE metric_name = 'vulnerability'
                    GROUP BY DATE(timestamp)
                    ORDER BY date DESC
                    LIMIT 30
                ''')
                
                data = cursor.fetchall()
                conn.close()
                
                if data:
                    dates = [row[0] for row in data]
                    counts = [row[1] for row in data]
                    
                    return jsonify({
                        'dates': dates,
                        'counts': counts,
                        'total_vulnerabilities': sum(counts)
                    })
                else:
                    return jsonify({
                        'dates': [],
                        'counts': [],
                        'total_vulnerabilities': 0
                    })
            
            except Exception as e:
                logger.error(f"Error getting vulnerability trends: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/analytics/success-rates', methods=['GET'])
        def success_rates():
            """Get submission success rates"""
            if 'submission' not in self.framework_managers:
                return jsonify({'error': 'Submission manager not available'}), 503
            
            try:
                submission_manager = self.framework_managers['submission']
                stats = submission_manager.get_submission_statistics()
                
                return jsonify({
                    'platform_statistics': stats['platform_statistics'],
                    'overall_success_rate': stats['overall_success_rate'],
                    'total_submissions': stats['total_submissions']
                })
            
            except Exception as e:
                logger.error(f"Error getting success rates: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Real-time streaming
        @self.app.route('/api/stream/updates', methods=['GET'])
        def stream_updates():
            """Stream real-time updates"""
            def generate():
                while True:
                    # Get current stats
                    stats = self._get_current_stats()
                    
                    # Send data
                    yield f"data: {json.dumps(stats)}\n\n"
                    
                    # Wait before next update
                    time.sleep(5)
            
            return Response(generate(), mimetype='text/event-stream')
        
        # Export endpoints
        @self.app.route('/api/export/<component>', methods=['GET'])
        def export_data(component):
            """Export component data"""
            format = request.args.get('format', 'json')
            
            try:
                if component == 'recon':
                    data = self._export_recon_data()
                elif component == 'ai':
                    data = self._export_ai_data()
                elif component == 'monitoring':
                    data = self._export_monitoring_data()
                elif component == 'submissions':
                    data = self._export_submissions_data()
                elif component == 'exploitation':
                    data = self._export_exploitation_data()
                else:
                    return jsonify({'error': 'Invalid component'}), 400
                
                if format == 'json':
                    return jsonify(data)
                else:
                    return jsonify({'error': 'Format not supported'}), 400
            
            except Exception as e:
                logger.error(f"Error exporting {component} data: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Control endpoints
        @self.app.route('/api/control/start-scan', methods=['POST'])
        def start_scan():
            """Start a new scan"""
            data = request.get_json()
            target_domain = data.get('target_domain')
            
            if not target_domain:
                return jsonify({'error': 'Target domain required'}), 400
            
            if 'recon' not in self.framework_managers:
                return jsonify({'error': 'Reconnaissance manager not available'}), 503
            
            try:
                recon_manager = self.framework_managers['recon']
                session_id = recon_manager.start_scan(target_domain)
                
                return jsonify({
                    'success': True,
                    'session_id': session_id,
                    'message': f'Scan started for {target_domain}'
                })
            
            except Exception as e:
                logger.error(f"Error starting scan: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/control/stop-scan/<session_id>', methods=['POST'])
        def stop_scan(session_id):
            """Stop a running scan"""
            if 'recon' not in self.framework_managers:
                return jsonify({'error': 'Reconnaissance manager not available'}), 503
            
            try:
                recon_manager = self.framework_managers['recon']
                success = recon_manager.stop_scan(session_id)
                
                if success:
                    return jsonify({
                        'success': True,
                        'message': f'Scan {session_id} stopped'
                    })
                else:
                    return jsonify({'error': 'Scan not found or already stopped'}), 404
            
            except Exception as e:
                logger.error(f"Error stopping scan: {e}")
                return jsonify({'error': str(e)}), 500
    
    def _get_current_stats(self) -> Dict[str, Any]:
        """Get current dashboard statistics"""
        stats = {
            'timestamp': datetime.now().isoformat(),
            'total_targets': 0,
            'active_scans': 0,
            'vulnerabilities_found': 0,
            'reports_generated': 0,
            'submissions_made': 0,
            'payouts_received': 0,
            'exploitation_sessions': 0,
            'success_rate': 0.0
        }
        
        # Get stats from framework managers
        if 'recon' in self.framework_managers:
            try:
                recon_manager = self.framework_managers['recon']
                stats['total_targets'] = len(recon_manager.targets)
                stats['active_scans'] = len([s for s in recon_manager.scan_sessions.values() if s.status == 'running'])
            except:
                pass
        
        if 'submission' in self.framework_managers:
            try:
                submission_manager = self.framework_managers['submission']
                stats['submissions_made'] = len(submission_manager.submissions)
                stats['payouts_received'] = len(submission_manager.payouts)
                
                # Calculate success rate
                if stats['submissions_made'] > 0:
                    successful = sum(1 for s in submission_manager.submissions.values() 
                                   if s.submission_status == 'accepted')
                    stats['success_rate'] = (successful / stats['submissions_made']) * 100
            except:
                pass
        
        if 'exploitation' in self.framework_managers:
            try:
                exploit_manager = self.framework_managers['exploitation']
                stats['exploitation_sessions'] = len(exploit_manager.active_sessions)
            except:
                pass
        
        return stats
    
    def _export_recon_data(self) -> Dict[str, Any]:
        """Export reconnaissance data"""
        if 'recon' not in self.framework_managers:
            raise Exception("Reconnaissance manager not available")
        
        recon_manager = self.framework_managers['recon']
        
        return {
            'export_timestamp': datetime.now().isoformat(),
            'targets': [asdict(target) for target in recon_manager.targets.values()],
            'scan_sessions': [asdict(session) for session in recon_manager.scan_sessions.values()],
            'total_targets': len(recon_manager.targets),
            'total_sessions': len(recon_manager.scan_sessions)
        }
    
    def _export_ai_data(self) -> Dict[str, Any]:
        """Export AI analysis data"""
        if 'ai' not in self.framework_managers:
            raise Exception("AI analysis manager not available")
        
        ai_manager = self.framework_managers['ai']
        
        return {
            'export_timestamp': datetime.now().isoformat(),
            'analysis_sessions': [asdict(session) for session in ai_manager.analysis_sessions.values()],
            'recent_findings': [asdict(finding) for finding in ai_manager.recent_findings],
            'total_sessions': len(ai_manager.analysis_sessions),
            'total_findings': len(ai_manager.recent_findings)
        }
    
    def _export_monitoring_data(self) -> Dict[str, Any]:
        """Export monitoring data"""
        if 'monitoring' not in self.framework_managers:
            raise Exception("Monitoring manager not available")
        
        monitoring_manager = self.framework_managers['monitoring']
        
        return {
            'export_timestamp': datetime.now().isoformat(),
            'active_tasks': [asdict(task) for task in monitoring_manager.active_tasks.values()],
            'recent_alerts': [asdict(alert) for alert in monitoring_manager.recent_alerts],
            'total_tasks': len(monitoring_manager.active_tasks),
            'total_alerts': len(monitoring_manager.recent_alerts)
        }
    
    def _export_submissions_data(self) -> Dict[str, Any]:
        """Export submissions data"""
        if 'submission' not in self.framework_managers:
            raise Exception("Submission manager not available")
        
        submission_manager = self.framework_managers['submission']
        
        return {
            'export_timestamp': datetime.now().isoformat(),
            'submissions': [asdict(submission) for submission in submission_manager.submissions.values()],
            'payouts': [asdict(payout) for payout in submission_manager.payouts.values()],
            'total_submissions': len(submission_manager.submissions),
            'total_payouts': len(submission_manager.payouts)
        }
    
    def _export_exploitation_data(self) -> Dict[str, Any]:
        """Export exploitation data"""
        if 'exploitation' not in self.framework_managers:
            raise Exception("Exploitation manager not available")
        
        exploit_manager = self.framework_managers['exploitation']
        
        return {
            'export_timestamp': datetime.now().isoformat(),
            'active_sessions': [asdict(session) for session in exploit_manager.active_sessions.values()],
            'recent_payloads': [asdict(payload) for payload in exploit_manager.recent_payloads],
            'total_sessions': len(exploit_manager.active_sessions),
            'total_payloads': len(exploit_manager.recent_payloads)
        }
    
    def run(self, host: str = None, port: int = None, debug: bool = None):
        """Run the API server"""
        host = host or self.config['api']['host']
        port = port or self.config['api']['port']
        debug = debug if debug is not None else self.config['api']['debug']
        
        logger.info(f"Starting Dashboard API server on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

# Global API instance
dashboard_api = None

def initialize_dashboard_api(config_path: str = 'dashboard_config.yml'):
    """Initialize the global dashboard API instance"""
    global dashboard_api
    dashboard_api = DashboardAPI(config_path)
    return dashboard_api

def get_dashboard_api() -> DashboardAPI:
    """Get the global dashboard API instance"""
    if dashboard_api is None:
        raise RuntimeError("Dashboard API not initialized. Call initialize_dashboard_api() first.")
    return dashboard_api

if __name__ == '__main__':
    # Initialize and run the API server
    api = initialize_dashboard_api()
    api.run() 