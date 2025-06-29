#!/usr/bin/env python3
"""
📊 Advanced Reporting & Analytics Dashboard
Unified web interface for the complete bug bounty framework

Features:
- Real-time monitoring of all framework components
- Advanced analytics and data visualization
- Interactive reports and charts
- Multi-user support with role-based access
- Export capabilities (PDF, HTML, JSON)
- Unified configuration management
"""

import os
import json
import time
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
import yaml
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import plotly.graph_objs as go
import plotly.utils
import pandas as pd
from io import BytesIO
import base64

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

@dataclass
class DashboardUser(UserMixin):
    """Dashboard user model"""
    id: str
    username: str
    email: str
    role: str  # admin, analyst, viewer
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True

@dataclass
class DashboardStats:
    """Dashboard statistics"""
    total_targets: int
    active_scans: int
    vulnerabilities_found: int
    reports_generated: int
    submissions_made: int
    payouts_received: int
    exploitation_sessions: int
    success_rate: float

class DashboardManager:
    """Main dashboard manager"""
    
    def __init__(self, config_path: str = 'dashboard_config.yml'):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Database
        self.db_path = 'dashboard.db'
        self._init_database()
        
        # User management
        self.users: Dict[str, DashboardUser] = {}
        self._load_users()
        
        # Framework managers
        self.framework_managers = {}
        if FRAMEWORK_AVAILABLE:
            self._initialize_framework_managers()
        
        # Create output directories
        self.output_dir = Path('dashboard_results')
        self.output_dir.mkdir(exist_ok=True)
        
        for subdir in ['reports', 'exports', 'charts', 'logs']:
            (self.output_dir / subdir).mkdir(exist_ok=True)
    
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
            'dashboard': {
                'title': 'Bug Bounty Framework Dashboard',
                'theme': 'dark',
                'refresh_interval': 30,
                'max_data_points': 1000
            },
            'users': {
                'default_admin': {
                    'username': 'admin',
                    'password': 'admin123',
                    'email': 'admin@example.com',
                    'role': 'admin'
                }
            },
            'analytics': {
                'enabled': True,
                'chart_types': ['line', 'bar', 'pie', 'heatmap'],
                'export_formats': ['pdf', 'html', 'json', 'csv']
            },
            'security': {
                'session_timeout': 3600,
                'max_login_attempts': 5,
                'password_min_length': 8
            }
        }
    
    def _init_database(self):
        """Initialize dashboard database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dashboard_users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT,
                last_login TEXT,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Dashboard sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dashboard_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                session_type TEXT,
                start_time TEXT,
                end_time TEXT,
                data TEXT,
                FOREIGN KEY (user_id) REFERENCES dashboard_users (id)
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
    
    def _load_users(self):
        """Load users from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM dashboard_users')
        for row in cursor.fetchall():
            user = DashboardUser(
                id=row[0],
                username=row[1],
                email=row[2],
                role=row[4],
                created_at=datetime.fromisoformat(row[5]),
                last_login=datetime.fromisoformat(row[6]) if row[6] else None,
                is_active=bool(row[7])
            )
            self.users[user.id] = user
        
        # Create default admin if no users exist
        if not self.users:
            self._create_default_admin()
        
        conn.close()
    
    def _create_default_admin(self):
        """Create default admin user"""
        admin_config = self.config['users']['default_admin']
        admin_id = hashlib.md5(admin_config['username'].encode()).hexdigest()[:12]
        
        admin_user = DashboardUser(
            id=admin_id,
            username=admin_config['username'],
            email=admin_config['email'],
            role=admin_config['role'],
            created_at=datetime.now()
        )
        
        self.users[admin_id] = admin_user
        self._save_user_to_db(admin_user, admin_config['password'])
        
        logger.info(f"Created default admin user: {admin_config['username']}")
    
    def _save_user_to_db(self, user: DashboardUser, password: str):
        """Save user to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        password_hash = generate_password_hash(password)
        
        cursor.execute('''
            INSERT INTO dashboard_users 
            (id, username, email, password_hash, role, created_at, last_login, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user.id, user.username, user.email, password_hash, user.role,
            user.created_at.isoformat(),
            user.last_login.isoformat() if user.last_login else None,
            user.is_active
        ))
        
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
    
    def authenticate_user(self, username: str, password: str) -> Optional[DashboardUser]:
        """Authenticate user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM dashboard_users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()
        
        if row and check_password_hash(row[3], password):
            user = DashboardUser(
                id=row[0],
                username=row[1],
                email=row[2],
                role=row[4],
                created_at=datetime.fromisoformat(row[5]),
                last_login=datetime.fromisoformat(row[6]) if row[6] else None,
                is_active=bool(row[7])
            )
            
            # Update last login
            self._update_last_login(user.id)
            
            return user
        
        return None
    
    def _update_last_login(self, user_id: str):
        """Update user's last login time"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE dashboard_users 
            SET last_login = ? 
            WHERE id = ?
        ''', (datetime.now().isoformat(), user_id))
        
        conn.commit()
        conn.close()
    
    def get_user_by_id(self, user_id: str) -> Optional[DashboardUser]:
        """Get user by ID"""
        return self.users.get(user_id)
    
    def get_dashboard_stats(self) -> DashboardStats:
        """Get comprehensive dashboard statistics"""
        stats = {
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
        
        # Get from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM analytics_data WHERE metric_name = "vulnerability"')
        stats['vulnerabilities_found'] = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM analytics_data WHERE metric_name = "report"')
        stats['reports_generated'] = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return DashboardStats(**stats)
    
    def generate_analytics_charts(self) -> Dict[str, str]:
        """Generate analytics charts"""
        charts = {}
        
        # Vulnerability trends chart
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
            if data:
                dates = [row[0] for row in data]
                counts = [row[1] for row in data]
                
                fig = go.Figure(data=go.Scatter(x=dates, y=counts, mode='lines+markers'))
                fig.update_layout(
                    title='Vulnerability Discovery Trends',
                    xaxis_title='Date',
                    yaxis_title='Vulnerabilities Found',
                    template='plotly_dark'
                )
                
                charts['vulnerability_trends'] = plotly.utils.PlotlyJSONEncoder().encode(fig)
            
            # Success rate chart
            if 'submission' in self.framework_managers:
                try:
                    submission_manager = self.framework_managers['submission']
                    stats = submission_manager.get_submission_statistics()
                    
                    platforms = list(stats['platform_statistics'].keys())
                    success_rates = [stats['platform_statistics'][p]['success_rate'] for p in platforms]
                    
                    fig = go.Figure(data=go.Bar(x=platforms, y=success_rates))
                    fig.update_layout(
                        title='Submission Success Rates by Platform',
                        xaxis_title='Platform',
                        yaxis_title='Success Rate (%)',
                        template='plotly_dark'
                    )
                    
                    charts['success_rates'] = plotly.utils.PlotlyJSONEncoder().encode(fig)
                except:
                    pass
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to generate charts: {e}")
        
        return charts
    
    def export_report(self, report_type: str, format: str = 'json') -> str:
        """Export dashboard report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"dashboard_report_{report_type}_{timestamp}.{format}"
        filepath = self.output_dir / 'exports' / filename
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'report_type': report_type,
            'stats': asdict(self.get_dashboard_stats()),
            'framework_status': self._get_framework_status()
        }
        
        if format == 'json':
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=2)
        elif format == 'html':
            html_content = self._generate_html_report(report_data)
            with open(filepath, 'w') as f:
                f.write(html_content)
        
        return str(filepath)
    
    def _get_framework_status(self) -> Dict[str, Any]:
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
            except:
                status[name] = {
                    'available': False,
                    'status': 'unavailable'
                }
        
        return status
    
    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Bug Bounty Framework Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .stat {{ display: inline-block; margin: 10px; padding: 10px; background: #f8f9fa; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Bug Bounty Framework Report</h1>
                <p>Generated: {data['timestamp']}</p>
            </div>
            
            <div class="section">
                <h2>Statistics</h2>
                <div class="stat">Total Targets: {data['stats']['total_targets']}</div>
                <div class="stat">Active Scans: {data['stats']['active_scans']}</div>
                <div class="stat">Vulnerabilities: {data['stats']['vulnerabilities_found']}</div>
                <div class="stat">Submissions: {data['stats']['submissions_made']}</div>
                <div class="stat">Success Rate: {data['stats']['success_rate']:.1f}%</div>
            </div>
            
            <div class="section">
                <h2>Framework Status</h2>
                {self._generate_status_html(data['framework_status'])}
            </div>
        </body>
        </html>
        """
        return html
    
    def _generate_status_html(self, status: Dict[str, Any]) -> str:
        """Generate status HTML"""
        html = ""
        for component, info in status.items():
            color = "green" if info['available'] else "red"
            html += f'<div style="color: {color};">{component}: {info["status"]}</div>'
        return html

# Global dashboard manager instance
dashboard_manager = None

def initialize_dashboard_manager(config_path: str = 'dashboard_config.yml'):
    """Initialize the global dashboard manager"""
    global dashboard_manager
    dashboard_manager = DashboardManager(config_path)
    return dashboard_manager

def get_dashboard_manager() -> DashboardManager:
    """Get the global dashboard manager instance"""
    if dashboard_manager is None:
        raise RuntimeError("Dashboard manager not initialized. Call initialize_dashboard_manager() first.")
    return dashboard_manager

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv('DASHBOARD_SECRET_KEY', 'your-secret-key-change-this')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    manager = get_dashboard_manager()
    return manager.get_user_by_id(user_id)

@app.route('/')
@login_required
def dashboard():
    """Main dashboard page"""
    manager = get_dashboard_manager()
    stats = manager.get_dashboard_stats()
    charts = manager.generate_analytics_charts()
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         charts=charts,
                         framework_available=FRAMEWORK_AVAILABLE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        manager = get_dashboard_manager()
        user = manager.authenticate_user(username, password)
        
        if user:
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for dashboard statistics"""
    manager = get_dashboard_manager()
    stats = manager.get_dashboard_stats()
    return jsonify(asdict(stats))

@app.route('/api/charts')
@login_required
def api_charts():
    """API endpoint for charts"""
    manager = get_dashboard_manager()
    charts = manager.generate_analytics_charts()
    return jsonify(charts)

@app.route('/api/export/<report_type>')
@login_required
def api_export(report_type):
    """API endpoint for report export"""
    format = request.args.get('format', 'json')
    manager = get_dashboard_manager()
    
    try:
        filepath = manager.export_report(report_type, format)
        return jsonify({'success': True, 'filepath': filepath})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    # Initialize dashboard manager
    initialize_dashboard_manager()
    
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000) 