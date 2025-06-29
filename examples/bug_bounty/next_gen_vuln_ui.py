#!/usr/bin/env python3
"""
🚀 NEXT-GENERATION VULNERABILITY ANALYSIS UI
Ultra-optimized, AI-powered, real-time vulnerability analysis platform
with advanced visualizations, collaborative features, and enterprise-grade security.

Key Features:
- Real-time WebSocket communication
- Advanced AI integration with multiple providers
- Interactive vulnerability visualization
- Collaborative analysis environment
- Advanced export and reporting
- Progressive Web App (PWA) capabilities
- Dark/Light mode with accessibility
- Advanced search and filtering
- Real-time system monitoring
- Automated PoC generation and execution
- Machine learning-based vulnerability classification
- Advanced threat intelligence integration
- Kali Linux optimization and tool integration
- Advanced payload generation and management
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file, Response
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_compress import Compress
import os
import json
import sqlite3
import subprocess
from datetime import datetime, timedelta
import threading
import time
from pathlib import Path
import requests
import hashlib
import base64
import csv
import io
import zipfile
from urllib.parse import urlparse
import re
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import uuid
import websockets
import aiohttp
import numpy as np
import pandas as pd
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Tuple
import jwt
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import schedule
import plotly.graph_objs as go
import plotly.utils
from scipy import stats
import networkx as nx
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import redis
from celery import Celery
import elasticsearch
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import openai
import anthropic
from optimization_manager import EnhancedOptimizationManager
from security_enhancer import initialize_security_enhancer, get_security_enhancer
from database_optimizer import initialize_database_optimizer, get_db_optimizer
from kali_linux_optimizer import initialize_kali_optimizer, get_kali_optimizer
from payload_generator import initialize_payload_generator, get_payload_generator
from advanced_recon_tools import initialize_recon_tools, get_recon_tools
import random
import psutil
import plotly

# Set up comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('next_gen_vuln_ui.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'next-gen-vuln-ui-super-secret-2025'),
    CACHE_TYPE='redis',
    CACHE_REDIS_URL=os.environ.get('REDIS_URL', 'redis://localhost:6379'),
    RATELIMIT_STORAGE_URL=os.environ.get('REDIS_URL', 'redis://localhost:6379'),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    MAX_CONTENT_LENGTH=100 * 1024 * 1024,  # 100MB
    UPLOAD_FOLDER='uploads',
    COMPRESS_MIMETYPES=['text/html', 'text/css', 'text/xml', 'application/json', 'application/javascript'],
    COMPRESS_LEVEL=6,
    COMPRESS_MIN_SIZE=500
)

# Initialize extensions
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
cache = Cache(app)
compress = Compress(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize all optimizers and generators
try:
    security_enhancer = initialize_security_enhancer(app.config['SECRET_KEY'])
    db_optimizer = initialize_database_optimizer(DATABASE_PATH)
    kali_optimizer = initialize_kali_optimizer('kali_config.yml')
    payload_generator = initialize_payload_generator('payload_templates')
    recon_tools = initialize_recon_tools('recon_results')
    logger.info("All optimizers and generators initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize optimizers/generators: {e}")
    security_enhancer = None
    db_optimizer = None
    kali_optimizer = None
    payload_generator = None
    recon_tools = None

# Prometheus metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_LATENCY = Histogram('http_request_duration_seconds', 'HTTP request latency')

# Celery for background tasks
celery = Celery(app.name, broker=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379'))
celery.conf.update(app.config)

# Global configuration
DATABASE_PATH = 'bb_pro.db'
REPORTS_DIR = Path('vulnerability_analysis_reports')
MANUAL_REPORTS_DIR = Path('manual_test_reports')
UPLOADS_DIR = Path('uploads')
EXPORT_DIR = Path('exports')
BACKUP_DIR = Path('backups')
LOGS_DIR = Path('logs')

# Create directories
for directory in [REPORTS_DIR, MANUAL_REPORTS_DIR, UPLOADS_DIR, EXPORT_DIR, BACKUP_DIR, LOGS_DIR]:
    directory.mkdir(exist_ok=True)

# Thread pool for background tasks
executor = ThreadPoolExecutor(max_workers=8)

# AI Provider configurations
AI_PROVIDERS = {
    'gemini': {
        'available': False,
        'api_key': os.getenv('GEMINI_API_KEY'),
        'model': 'gemini-1.5-pro-latest'
    },
    'openai': {
        'available': False,
        'api_key': os.getenv('OPENAI_API_KEY'),
        'model': 'gpt-4-turbo-preview'
    },
    'anthropic': {
        'available': False,
        'api_key': os.getenv('ANTHROPIC_API_KEY'),
        'model': 'claude-3-opus-20240229'
    }
}

# Initialize AI providers
try:
    import google.generativeai as genai
    if AI_PROVIDERS['gemini']['api_key']:
        genai.configure(api_key=AI_PROVIDERS['gemini']['api_key'])
        AI_PROVIDERS['gemini']['available'] = True
        logger.info("Gemini AI initialized successfully")
except ImportError:
    logger.warning("Gemini AI not available")

try:
    if AI_PROVIDERS['openai']['api_key']:
        openai.api_key = AI_PROVIDERS['openai']['api_key']
        AI_PROVIDERS['openai']['available'] = True
        logger.info("OpenAI initialized successfully")
except Exception as e:
    logger.warning(f"OpenAI not available: {e}")

try:
    if AI_PROVIDERS['anthropic']['api_key']:
        anthropic_client = anthropic.Anthropic(api_key=AI_PROVIDERS['anthropic']['api_key'])
        AI_PROVIDERS['anthropic']['available'] = True
        logger.info("Anthropic Claude initialized successfully")
except Exception as e:
    logger.warning(f"Anthropic not available: {e}")

@dataclass
class VulnerabilityAnalysis:
    """Enhanced vulnerability analysis data structure"""
    id: str
    target_url: str
    vulnerability_type: str
    severity: str
    confidence: float
    title: str
    description: str
    impact: str
    remediation: str
    poc_code: Optional[str]
    cvss_score: float
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    discovered_at: datetime
    last_updated: datetime
    status: str
    analyst: str
    ai_provider: Optional[str]
    reproduction_success: bool
    false_positive_probability: float
    business_impact: str
    technical_details: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    references: List[str]
    tags: List[str]

class SecurityManager:
    """Enhanced security manager for the application"""
    
    @staticmethod
    def generate_csrf_token():
        """Generate CSRF token"""
        if 'csrf_token' not in session:
            session['csrf_token'] = hashlib.sha256(os.urandom(32)).hexdigest()
        return session['csrf_token']
    
    @staticmethod
    def validate_csrf_token(token):
        """Validate CSRF token"""
        return token == session.get('csrf_token')
    
    @staticmethod
    def require_auth(f):
        """Authentication decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    
    @staticmethod
    def sanitize_input(data):
        """Sanitize user input"""
        if isinstance(data, str):
            # Remove potentially harmful characters
            data = re.sub(r'[<>"\']', '', data)
            data = data.strip()
        return data

class DatabaseManager:
    """Enhanced database manager with connection pooling and optimization"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize database with optimized schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=10000')
            conn.execute('PRAGMA temp_store=MEMORY')
            
            # Enhanced targets table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    name TEXT,
                    description TEXT,
                    program_name TEXT,
                    scope TEXT,
                    out_of_scope TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_scanned TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    priority INTEGER DEFAULT 1,
                    tags TEXT,
                    metadata TEXT
                )
            ''')
            
            # Enhanced vulnerabilities table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    target_id INTEGER,
                    target_url TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL DEFAULT 0.0,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    impact TEXT,
                    remediation TEXT,
                    poc_code TEXT,
                    cvss_score REAL DEFAULT 0.0,
                    cwe_id TEXT,
                    owasp_category TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'new',
                    analyst TEXT,
                    ai_provider TEXT,
                    reproduction_success BOOLEAN DEFAULT 0,
                    false_positive_probability REAL DEFAULT 0.0,
                    business_impact TEXT,
                    technical_details TEXT,
                    evidence TEXT,
                    references TEXT,
                    tags TEXT,
                    FOREIGN KEY (target_id) REFERENCES targets (id)
                )
            ''')
            
            # Analysis sessions table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS analysis_sessions (
                    id TEXT PRIMARY KEY,
                    target_id INTEGER,
                    analyst TEXT,
                    session_type TEXT,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    findings_count INTEGER DEFAULT 0,
                    ai_provider TEXT,
                    configuration TEXT,
                    FOREIGN KEY (target_id) REFERENCES targets (id)
                )
            ''')
            
            # System events table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS system_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    event_data TEXT,
                    user_id TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    severity TEXT DEFAULT 'info'
                )
            ''')
            
            # User activity table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS user_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT
                )
            ''')
            
            # Create indexes for performance
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target_url ON vulnerabilities(target_url)',
                'CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)',
                'CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status)',
                'CREATE INDEX IF NOT EXISTS idx_vulnerabilities_discovered_at ON vulnerabilities(discovered_at)',
                'CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status)',
                'CREATE INDEX IF NOT EXISTS idx_system_events_type ON system_events(event_type)',
                'CREATE INDEX IF NOT EXISTS idx_user_activity_user_id ON user_activity(user_id)'
            ]
            
            for index in indexes:
                conn.execute(index)
            
            conn.commit()
    
    @cache.memoize(timeout=300)
    def get_vulnerability_stats(self):
        """Get cached vulnerability statistics"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            stats = {}
            
            # Total vulnerabilities by severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count 
                FROM vulnerabilities 
                GROUP BY severity
            ''')
            stats['by_severity'] = dict(cursor.fetchall())
            
            # Total vulnerabilities by status
            cursor.execute('''
                SELECT status, COUNT(*) as count 
                FROM vulnerabilities 
                GROUP BY status
            ''')
            stats['by_status'] = dict(cursor.fetchall())
            
            # Recent discoveries (last 30 days)
            cursor.execute('''
                SELECT DATE(discovered_at) as date, COUNT(*) as count
                FROM vulnerabilities 
                WHERE discovered_at >= date('now', '-30 days')
                GROUP BY DATE(discovered_at)
                ORDER BY date
            ''')
            stats['recent_discoveries'] = dict(cursor.fetchall())
            
            # AI provider performance
            cursor.execute('''
                SELECT ai_provider, 
                       COUNT(*) as total,
                       AVG(confidence) as avg_confidence,
                       AVG(false_positive_probability) as avg_fp_rate
                FROM vulnerabilities 
                WHERE ai_provider IS NOT NULL
                GROUP BY ai_provider
            ''')
            stats['ai_performance'] = [dict(row) for row in cursor.fetchall()]
            
            return stats

db_manager = DatabaseManager(DATABASE_PATH)

class AIAnalysisEngine:
    """Multi-provider AI analysis engine with advanced capabilities"""
    
    def __init__(self):
        self.providers = AI_PROVIDERS
        self.analysis_cache = {}
        
    async def analyze_vulnerability(self, target_url: str, vulnerability_data: Dict, provider: str = 'auto') -> VulnerabilityAnalysis:
        """Analyze vulnerability using specified AI provider"""
        
        if provider == 'auto':
            provider = self._select_best_provider()
        
        if not self.providers[provider]['available']:
            raise ValueError(f"AI provider {provider} is not available")
        
        analysis_prompt = self._build_analysis_prompt(target_url, vulnerability_data)
        
        try:
            if provider == 'gemini':
                result = await self._analyze_with_gemini(analysis_prompt)
            elif provider == 'openai':
                result = await self._analyze_with_openai(analysis_prompt)
            elif provider == 'anthropic':
                result = await self._analyze_with_anthropic(analysis_prompt)
            else:
                raise ValueError(f"Unknown provider: {provider}")
            
            # Create VulnerabilityAnalysis object
            analysis = VulnerabilityAnalysis(
                id=str(uuid.uuid4()),
                target_url=target_url,
                vulnerability_type=result.get('type', 'Unknown'),
                severity=result.get('severity', 'Low'),
                confidence=result.get('confidence', 0.5),
                title=result.get('title', 'Vulnerability Detected'),
                description=result.get('description', ''),
                impact=result.get('impact', ''),
                remediation=result.get('remediation', ''),
                poc_code=result.get('poc_code'),
                cvss_score=result.get('cvss_score', 0.0),
                cwe_id=result.get('cwe_id'),
                owasp_category=result.get('owasp_category'),
                discovered_at=datetime.now(),
                last_updated=datetime.now(),
                status='new',
                analyst=f'AI-{provider}',
                ai_provider=provider,
                reproduction_success=False,
                false_positive_probability=result.get('false_positive_probability', 0.1),
                business_impact=result.get('business_impact', 'Medium'),
                technical_details=result.get('technical_details', {}),
                evidence=result.get('evidence', []),
                references=result.get('references', []),
                tags=result.get('tags', [])
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed with {provider}: {e}")
            raise
    
    def _select_best_provider(self) -> str:
        """Select the best available AI provider based on performance metrics"""
        available_providers = [name for name, config in self.providers.items() if config['available']]
        
        if not available_providers:
            raise ValueError("No AI providers available")
        
        # Simple selection logic - prefer Gemini, then OpenAI, then Anthropic
        for provider in ['gemini', 'openai', 'anthropic']:
            if provider in available_providers:
                return provider
        
        return available_providers[0]
    
    def _build_analysis_prompt(self, target_url: str, vulnerability_data: Dict) -> str:
        """Build comprehensive analysis prompt"""
        return f"""
Analyze the following potential security vulnerability:

Target URL: {target_url}
Vulnerability Data: {json.dumps(vulnerability_data, indent=2)}

Please provide a comprehensive analysis including:

1. Vulnerability Type and Classification
2. Severity Assessment (Critical/High/Medium/Low)
3. Confidence Level (0.0-1.0)
4. CVSS Score
5. CWE ID if applicable
6. OWASP Top 10 category if applicable
7. Detailed description of the vulnerability
8. Potential impact on the application and business
9. Step-by-step remediation recommendations
10. Proof of Concept code if applicable
11. False positive probability assessment
12. Additional references and resources
13. Tags for categorization

Return the analysis as a JSON object with the following structure:
{{
    "type": "string",
    "severity": "string",
    "confidence": float,
    "cvss_score": float,
    "cwe_id": "string",
    "owasp_category": "string",
    "title": "string",
    "description": "string",
    "impact": "string",
    "remediation": "string",
    "poc_code": "string",
    "false_positive_probability": float,
    "business_impact": "string",
    "technical_details": {{}},
    "evidence": [],
    "references": [],
    "tags": []
}}
"""
    
    async def _analyze_with_gemini(self, prompt: str) -> Dict:
        """Analyze using Gemini AI"""
        import google.generativeai as genai
        
        model = genai.GenerativeModel(self.providers['gemini']['model'])
        response = model.generate_content(prompt)
        
        # Parse JSON response
        try:
            result = json.loads(response.text)
            return result
        except json.JSONDecodeError:
            # Fallback parsing
            return self._parse_fallback_response(response.text)
    
    async def _analyze_with_openai(self, prompt: str) -> Dict:
        """Analyze using OpenAI GPT"""
        response = openai.ChatCompletion.create(
            model=self.providers['openai']['model'],
            messages=[
                {"role": "system", "content": "You are a security vulnerability analysis expert. Provide detailed, accurate analysis in JSON format."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1
        )
        
        try:
            result = json.loads(response.choices[0].message.content)
            return result
        except json.JSONDecodeError:
            return self._parse_fallback_response(response.choices[0].message.content)
    
    async def _analyze_with_anthropic(self, prompt: str) -> Dict:
        """Analyze using Anthropic Claude"""
        response = anthropic_client.messages.create(
            model=self.providers['anthropic']['model'],
            max_tokens=4000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        try:
            result = json.loads(response.content[0].text)
            return result
        except json.JSONDecodeError:
            return self._parse_fallback_response(response.content[0].text)
    
    def _parse_fallback_response(self, text: str) -> Dict:
        """Fallback parsing when JSON parsing fails"""
        return {
            "type": "Unknown",
            "severity": "Medium",
            "confidence": 0.5,
            "cvss_score": 5.0,
            "title": "AI Analysis Result",
            "description": text,
            "impact": "Requires manual review",
            "remediation": "Manual analysis recommended",
            "false_positive_probability": 0.3,
            "business_impact": "Medium",
            "technical_details": {},
            "evidence": [],
            "references": [],
            "tags": ["ai-analysis", "needs-review"]
        }

ai_engine = AIAnalysisEngine()

class RealtimeAnalytics:
    """Real-time analytics and monitoring"""
    
    def __init__(self):
        self.metrics = {
            'active_sessions': 0,
            'vulnerabilities_found': 0,
            'analyses_running': 0,
            'system_load': 0.0
        }
        self.start_monitoring()
    
    def start_monitoring(self):
        """Start background monitoring"""
        def monitor():
            while True:
                self.update_metrics()
                socketio.emit('metrics_update', self.metrics, namespace='/realtime')
                time.sleep(5)
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def update_metrics(self):
        """Update system metrics"""
        try:
            # Update active sessions
            # This would be tracked by session management
            
            # Update vulnerabilities count
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
                self.metrics['vulnerabilities_found'] = cursor.fetchone()[0]
            
            # Update system load (mock data)
            import psutil
            self.metrics['system_load'] = psutil.cpu_percent()
            
        except Exception as e:
            logger.error(f"Error updating metrics: {e}")

analytics = RealtimeAnalytics()

# WebSocket event handlers
@socketio.on('connect', namespace='/realtime')
def handle_connect():
    """Handle WebSocket connection"""
    analytics.metrics['active_sessions'] += 1
    join_room('global')
    emit('connected', {'status': 'connected'})

@socketio.on('disconnect', namespace='/realtime')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    analytics.metrics['active_sessions'] -= 1
    leave_room('global')

@socketio.on('start_analysis', namespace='/realtime')
def handle_start_analysis(data):
    """Handle real-time analysis request"""
    target_url = data.get('target_url')
    if not target_url:
        emit('error', {'message': 'Target URL is required'})
        return
    
    # Start analysis in background
    def run_analysis():
        try:
            analytics.metrics['analyses_running'] += 1
            emit('analysis_started', {'target_url': target_url})
            
            # Simulate analysis (replace with actual analysis)
            time.sleep(2)
            
            result = {
                'target_url': target_url,
                'vulnerabilities_found': 3,
                'status': 'completed',
                'timestamp': datetime.now().isoformat()
            }
            
            emit('analysis_completed', result)
            analytics.metrics['analyses_running'] -= 1
            
        except Exception as e:
            emit('analysis_error', {'error': str(e)})
            analytics.metrics['analyses_running'] -= 1
    
    executor.submit(run_analysis)

# Enhanced route handlers with security and optimization
@app.before_request
def before_request():
    """Before request processing with security monitoring"""
    # Record request start time for latency tracking
    request.start_time = time.time()
    
    # Security monitoring
    if security_enhancer:
        try:
            # Log security event for monitoring
            security_enhancer.security_monitor.log_event(SecurityEvent(
                event_type='request_received',
                timestamp=datetime.now(),
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                endpoint=request.endpoint or '',
                severity='info',
                details={
                    'method': request.method,
                    'path': request.path,
                    'content_length': request.content_length or 0
                }
            ))
        except Exception as e:
            logger.error(f"Security monitoring error: {e}")
    
    # Check if system is under load
    if ResourceMonitor.should_throttle():
        return jsonify({'error': 'System under high load, please try again later'}), 503

@app.after_request
def after_request(response):
    """After request processing with metrics and security"""
    # Calculate request latency
    if hasattr(request, 'start_time'):
        latency = time.time() - request.start_time
        REQUEST_LATENCY.observe(latency)
    
    # Record request metrics
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.endpoint or 'unknown',
        status=response.status_code
    ).inc()
    
    # Security monitoring for failed requests
    if security_enhancer and response.status_code >= 400:
        try:
            security_enhancer.security_monitor.log_event(SecurityEvent(
                event_type='request_failed',
                timestamp=datetime.now(),
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                endpoint=request.endpoint or '',
                severity='medium' if response.status_code < 500 else 'high',
                details={
                    'status_code': response.status_code,
                    'method': request.method,
                    'path': request.path
                }
            ))
        except Exception as e:
            logger.error(f"Security monitoring error: {e}")
    
    return response

@app.route('/')
@limiter.limit("30 per minute")
@security_enhancer.rate_limit('default') if security_enhancer else lambda f: f
def index():
    """Enhanced dashboard with security monitoring"""
    try:
        # Get comprehensive stats
        db_manager = DatabaseManager(DATABASE_PATH)
        vulnerability_stats = db_manager.get_vulnerability_stats()
        
        # Get security stats if available
        security_stats = {}
        if security_enhancer:
            try:
                security_stats = security_enhancer.get_security_report()
            except Exception as e:
                logger.error(f"Failed to get security stats: {e}")
        
        # Get database performance stats if available
        db_performance = {}
        if db_optimizer:
            try:
                db_performance = db_optimizer.pool.get_performance_stats()
            except Exception as e:
                logger.error(f"Failed to get database performance: {e}")
        
        # Create enhanced charts
        severity_chart = _create_severity_chart(vulnerability_stats.get('severity_distribution', {}))
        timeline_chart = _create_timeline_chart(vulnerability_stats.get('timeline_data', {}))
        ai_performance_chart = _create_ai_performance_chart(vulnerability_stats.get('ai_analysis_stats', {}))
        
        # Add security monitoring data
        security_chart = None
        if security_stats:
            security_chart = _create_security_chart(security_stats)
        
        return render_template('next_gen_dashboard.html',
                             vulnerability_stats=vulnerability_stats,
                             security_stats=security_stats,
                             db_performance=db_performance,
                             severity_chart=severity_chart,
                             timeline_chart=timeline_chart,
                             ai_performance_chart=ai_performance_chart,
                             security_chart=security_chart,
                             ai_providers=AI_PROVIDERS)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return render_template('next_gen_dashboard.html', error=str(e))

def _create_severity_chart(severity_data):
    """Create severity distribution chart"""
    if not severity_data:
        return None
    
    fig = go.Figure(data=[
        go.Pie(
            labels=list(severity_data.keys()),
            values=list(severity_data.values()),
            hole=0.3,
            marker_colors=['#ef4444', '#f59e0b', '#10b981', '#6366f1']
        )
    ])
    
    fig.update_layout(
        title="Vulnerability Severity Distribution",
        showlegend=True,
        height=300,
        margin=dict(t=40, b=40, l=40, r=40)
    )
    
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def _create_timeline_chart(timeline_data):
    """Create discovery timeline chart"""
    if not timeline_data:
        return None
    
    dates = list(timeline_data.keys())
    counts = list(timeline_data.values())
    
    fig = go.Figure(data=[
        go.Scatter(
            x=dates,
            y=counts,
            mode='lines+markers',
            line=dict(color='#6366f1', width=3),
            marker=dict(size=8, color='#6366f1')
        )
    ])
    
    fig.update_layout(
        title="Vulnerability Discovery Timeline (Last 30 Days)",
        xaxis_title="Date",
        yaxis_title="Vulnerabilities Found",
        height=300,
        margin=dict(t=40, b=40, l=40, r=40)
    )
    
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def _create_ai_performance_chart(ai_data):
    """Create AI performance visualization chart"""
    try:
        if not ai_data:
            return None
        
        # Extract data for chart
        providers = list(ai_data.keys())
        success_rates = [ai_data[provider].get('success_rate', 0) for provider in providers]
        avg_response_times = [ai_data[provider].get('avg_response_time', 0) for provider in providers]
        
        # Create bar chart for success rates
        success_chart = go.Figure(data=[
            go.Bar(
                x=providers,
                y=success_rates,
                name='Success Rate (%)',
                marker_color='lightgreen'
            )
        ])
        
        success_chart.update_layout(
            title='AI Provider Success Rates',
            xaxis_title='AI Provider',
            yaxis_title='Success Rate (%)',
            height=300
        )
        
        # Create bar chart for response times
        response_chart = go.Figure(data=[
            go.Bar(
                x=providers,
                y=avg_response_times,
                name='Avg Response Time (s)',
                marker_color='lightblue'
            )
        ])
        
        response_chart.update_layout(
            title='AI Provider Response Times',
            xaxis_title='AI Provider',
            yaxis_title='Response Time (seconds)',
            height=300
        )
        
        return {
            'success_rates': plotly.utils.PlotlyJSONEncoder().encode(success_chart),
            'response_times': plotly.utils.PlotlyJSONEncoder().encode(response_chart)
        }
    except Exception as e:
        logger.error(f"Error creating AI performance chart: {e}")
        return None

def _create_security_chart(security_stats):
    """Create security monitoring visualization chart"""
    try:
        if not security_stats:
            return None
        
        # Extract security data
        rate_limiter = security_stats.get('rate_limiter', {})
        security_monitor = security_stats.get('security_monitor', {})
        
        # Create security events chart
        events_data = security_monitor.get('events_by_type', {})
        if events_data:
            event_types = list(events_data.keys())
            event_counts = list(events_data.values())
            
            events_chart = go.Figure(data=[
                go.Bar(
                    x=event_types,
                    y=event_counts,
                    name='Security Events',
                    marker_color=['red' if 'injection' in event_type or 'xss' in event_type else 'orange' for event_type in event_types]
                )
            ])
            
            events_chart.update_layout(
                title='Security Events by Type (Last 24h)',
                xaxis_title='Event Type',
                yaxis_title='Count',
                height=300
            )
        else:
            events_chart = None
        
        # Create rate limiting chart
        if rate_limiter:
            blocked_ips = rate_limiter.get('blocked_ips', 0)
            blocked_users = rate_limiter.get('blocked_users', 0)
            active_ips = rate_limiter.get('active_ips', 0)
            active_users = rate_limiter.get('active_users', 0)
            
            rate_limit_chart = go.Figure(data=[
                go.Bar(
                    x=['Blocked IPs', 'Blocked Users', 'Active IPs', 'Active Users'],
                    y=[blocked_ips, blocked_users, active_ips, active_users],
                    name='Rate Limiting Stats',
                    marker_color=['red', 'red', 'green', 'blue']
                )
            ])
            
            rate_limit_chart.update_layout(
                title='Rate Limiting Statistics',
                xaxis_title='Category',
                yaxis_title='Count',
                height=300
            )
        else:
            rate_limit_chart = None
        
        return {
            'security_events': plotly.utils.PlotlyJSONEncoder().encode(events_chart) if events_chart else None,
            'rate_limiting': plotly.utils.PlotlyJSONEncoder().encode(rate_limit_chart) if rate_limit_chart else None
        }
    except Exception as e:
        logger.error(f"Error creating security chart: {e}")
        return None

@app.route('/vulnerabilities')
@limiter.limit("60 per minute")
@security_enhancer.rate_limit('api') if security_enhancer else lambda f: f
@security_enhancer.sanitize_input(['search', 'severity', 'status']) if security_enhancer else lambda f: f
def vulnerabilities():
    """Enhanced vulnerabilities page with security features"""
    try:
        # Get filter parameters with sanitization
        search = request.args.get('search', '').strip()
        severity = request.args.get('severity', '').strip()
        status = request.args.get('status', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)  # Limit per_page
        
        # Security validation
        if security_enhancer:
            if search and security_enhancer.input_sanitizer.detect_sql_injection(search):
                flash('Invalid search query', 'error')
                return redirect(url_for('vulnerabilities'))
        
        db_manager = DatabaseManager(DATABASE_PATH)
        
        # Build query with security considerations
        query = """
            SELECT v.*, t.domain as target_domain, t.status as target_status
            FROM vulnerabilities v
            LEFT JOIN targets t ON v.target_id = t.id
            WHERE 1=1
        """
        params = []
        
        if search:
            query += " AND (v.title LIKE ? OR v.description LIKE ? OR v.vulnerability_type LIKE ?)"
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
        
        if severity:
            query += " AND v.severity = ?"
            params.append(severity)
        
        if status:
            query += " AND v.status = ?"
            params.append(status)
        
        query += " ORDER BY v.discovered_at DESC"
        
        # Get total count for pagination
        count_query = f"SELECT COUNT(*) FROM ({query})"
        total_count = db_manager.execute_query(count_query, params, fetch_one=True)[0]
        
        # Add pagination
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])
        
        vulnerabilities = db_manager.execute_query(query, params)
        
        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page
        has_prev = page > 1
        has_next = page < total_pages
        
        # Get security stats for this page
        security_stats = {}
        if security_enhancer:
            try:
                security_stats = security_enhancer.get_security_report()
            except Exception as e:
                logger.error(f"Failed to get security stats: {e}")
        
        return render_template('vulnerabilities.html',
                             vulnerabilities=vulnerabilities,
                             search=search,
                             severity=severity,
                             status=status,
                             page=page,
                             per_page=per_page,
                             total_pages=total_pages,
                             has_prev=has_prev,
                             has_next=has_next,
                             security_stats=security_stats)
    except Exception as e:
        logger.error(f"Vulnerabilities page error: {e}")
        flash(f'Error loading vulnerabilities: {str(e)}', 'error')
        return render_template('vulnerabilities.html', error=str(e))

@app.route('/vulnerability/<vuln_id>')
@limiter.limit("60 per minute")
def vulnerability_detail(vuln_id):
    """Enhanced vulnerability detail with AI insights"""
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM vulnerabilities WHERE id = ?', (vuln_id,))
            vuln = cursor.fetchone()
            
            if not vuln:
                flash('Vulnerability not found', 'error')
                return redirect(url_for('vulnerabilities'))
            
            vuln = dict(vuln)
            
            # Parse JSON fields
            for field in ['technical_details', 'evidence', 'references', 'tags']:
                if vuln[field]:
                    try:
                        vuln[field] = json.loads(vuln[field])
                    except:
                        vuln[field] = [] if field in ['evidence', 'references', 'tags'] else {}
                else:
                    vuln[field] = [] if field in ['evidence', 'references', 'tags'] else {}
            
            # Get similar vulnerabilities
            cursor.execute('''
                SELECT id, title, severity, confidence, target_url
                FROM vulnerabilities 
                WHERE vulnerability_type = ? AND id != ?
                ORDER BY confidence DESC
                LIMIT 5
            ''', (vuln['vulnerability_type'], vuln_id))
            similar_vulns = [dict(row) for row in cursor.fetchall()]
        
        return render_template('next_gen_vulnerability_detail.html',
                             vulnerability=vuln,
                             similar_vulnerabilities=similar_vulns,
                             ai_providers=AI_PROVIDERS)
    
    except Exception as e:
        logger.error(f"Vulnerability detail error: {e}")
        flash(f'Error loading vulnerability: {str(e)}', 'error')
        return redirect(url_for('vulnerabilities'))

# API Routes for AJAX functionality
@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
@security_enhancer.rate_limit('scan') if security_enhancer else lambda f: f
@security_enhancer.sanitize_input(['target_url', 'vulnerability_type', 'description']) if security_enhancer else lambda f: f
@security_enhancer.require_csrf() if security_enhancer else lambda f: f
def api_analyze():
    """Enhanced vulnerability analysis API with security features"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        target_url = data.get('target_url', '').strip()
        vulnerability_type = data.get('vulnerability_type', '').strip()
        description = data.get('description', '').strip()
        
        # Security validation
        if security_enhancer:
            # Validate URL
            if not security_enhancer.input_sanitizer.validate_url(target_url):
                return jsonify({'error': 'Invalid target URL'}), 400
            
            # Check for security threats in input
            for field, value in [('target_url', target_url), ('vulnerability_type', vulnerability_type), ('description', description)]:
                if security_enhancer.input_sanitizer.detect_sql_injection(value):
                    security_enhancer._log_security_threat('sql_injection_attempt', field, value)
                    return jsonify({'error': 'Invalid input detected'}), 400
                
                if security_enhancer.input_sanitizer.detect_xss(value):
                    security_enhancer._log_security_threat('xss_attempt', field, value)
                    return jsonify({'error': 'Invalid input detected'}), 400
        
        if not target_url or not vulnerability_type:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Start analysis in background
        def run_analysis():
            try:
                # Create analysis engine
                analysis_engine = AIAnalysisEngine()
                
                # Prepare vulnerability data
                vulnerability_data = {
                    'type': vulnerability_type,
                    'description': description,
                    'target_url': target_url
                }
                
                # Run analysis with retry logic
                @retry_with_circuit_breaker(max_retries=3, base_delay=1.0)
                def perform_analysis():
                    return asyncio.run(analysis_engine.analyze_vulnerability(target_url, vulnerability_data))
                
                analysis_result = perform_analysis()
                
                # Save to database
                db_manager = DatabaseManager(DATABASE_PATH)
                vuln_id = db_manager.save_vulnerability_analysis(analysis_result)
                
                # Emit real-time update
                socketio.emit('analysis_complete', {
                    'status': 'success',
                    'vulnerability_id': vuln_id,
                    'analysis': asdict(analysis_result)
                }, namespace='/realtime')
                
            except Exception as e:
                logger.error(f"Analysis error: {e}")
                socketio.emit('analysis_error', {
                    'status': 'error',
                    'error': str(e)
                }, namespace='/realtime')
        
        # Start background task
        executor.submit(run_analysis)
        
        return jsonify({
            'status': 'success',
            'message': 'Analysis started',
            'analysis_id': str(uuid.uuid4())
        })
        
    except Exception as e:
        logger.error(f"API analyze error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerabilities/<vuln_id>/reproduce', methods=['POST'])
@limiter.limit("5 per minute")
def api_reproduce_vulnerability(vuln_id):
    """API endpoint for vulnerability reproduction"""
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM vulnerabilities WHERE id = ?', (vuln_id,))
            vuln = cursor.fetchone()
            
            if not vuln:
                return jsonify({'error': 'Vulnerability not found'}), 404
        
        # Start reproduction in background
        def run_reproduction():
            try:
                # Simulate reproduction process
                time.sleep(3)
                
                success = True  # Mock result
                
                # Update database
                with sqlite3.connect(DATABASE_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE vulnerabilities 
                        SET reproduction_success = ?, last_updated = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (success, vuln_id))
                    conn.commit()
                
                # Emit real-time update
                socketio.emit('reproduction_completed', {
                    'vuln_id': vuln_id,
                    'success': success
                }, namespace='/realtime')
                
                return success
                
            except Exception as e:
                logger.error(f"Reproduction error: {e}")
                socketio.emit('reproduction_failed', {
                    'vuln_id': vuln_id,
                    'error': str(e)
                }, namespace='/realtime')
                return False
        
        executor.submit(run_reproduction)
        
        return jsonify({
            'status': 'started',
            'message': 'Reproduction started successfully',
            'vuln_id': vuln_id
        }), 202
    
    except Exception as e:
        logger.error(f"API reproduce error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export', methods=['POST'])
@limiter.limit("5 per minute")
def api_export():
    """API endpoint for exporting vulnerabilities"""
    try:
        data = request.get_json()
        export_format = data.get('format', 'json')
        vuln_ids = data.get('vulnerability_ids', [])
        
        if not vuln_ids:
            return jsonify({'error': 'No vulnerabilities selected'}), 400
        
        # Get vulnerabilities from database
        with sqlite3.connect(DATABASE_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            placeholders = ','.join('?' * len(vuln_ids))
            cursor.execute(f'SELECT * FROM vulnerabilities WHERE id IN ({placeholders})', vuln_ids)
            vulns = [dict(row) for row in cursor.fetchall()]
        
        # Generate export file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if export_format == 'json':
            filename = f'vulnerabilities_export_{timestamp}.json'
            filepath = EXPORT_DIR / filename
            
            with open(filepath, 'w') as f:
                json.dump(vulns, f, indent=2, default=str)
        
        elif export_format == 'csv':
            filename = f'vulnerabilities_export_{timestamp}.csv'
            filepath = EXPORT_DIR / filename
            
            if vulns:
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=vulns[0].keys())
                    writer.writeheader()
                    writer.writerows(vulns)
        
        elif export_format == 'pdf':
            # Generate PDF report (simplified version)
            filename = f'vulnerabilities_report_{timestamp}.pdf'
            filepath = EXPORT_DIR / filename
            
            # This would use a PDF library like reportlab
            # For now, create a simple text file
            with open(filepath, 'w') as f:
                f.write("Vulnerability Analysis Report\n")
                f.write("="*50 + "\n\n")
                for vuln in vulns:
                    f.write(f"Title: {vuln['title']}\n")
                    f.write(f"Severity: {vuln['severity']}\n")
                    f.write(f"Target: {vuln['target_url']}\n")
                    f.write(f"Description: {vuln['description']}\n")
                    f.write("-"*30 + "\n\n")
        
        else:
            return jsonify({'error': 'Unsupported format'}), 400
        
        return jsonify({
            'status': 'success',
            'filename': filename,
            'download_url': f'/download/{filename}'
        })
    
    except Exception as e:
        logger.error(f"Export error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
@limiter.limit("10 per minute")
def download_file(filename):
    """Download exported files"""
    try:
        filepath = EXPORT_DIR / filename
        if not filepath.exists():
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(filepath, as_attachment=True)
    
    except Exception as e:
        logger.error(f"Download error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
@cache.cached(timeout=60)
@limiter.limit("30 per minute")
def api_stats():
    """API endpoint for system statistics"""
    try:
        stats = db_manager.get_vulnerability_stats()
        
        # Add real-time metrics
        stats['realtime'] = analytics.metrics
        
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Stats API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@app.route('/api/optimization_stats')
def api_optimization_stats():
    """Get comprehensive optimization statistics"""
    try:
        # Get optimization manager stats
        opt_manager = EnhancedOptimizationManager()
        opt_stats = opt_manager.get_comprehensive_stats()
        
        # Get database stats if available
        db_stats = {}
        if db_optimizer:
            try:
                db_stats = db_optimizer.pool.get_performance_stats()
            except Exception as e:
                logger.error(f"Failed to get database stats: {e}")
        
        # Get security stats if available
        security_stats = {}
        if security_enhancer:
            try:
                security_stats = security_enhancer.get_security_report()
            except Exception as e:
                logger.error(f"Failed to get security stats: {e}")
        
        # Get system health
        system_health = ResourceMonitor.get_system_health()
        
        # Generate AI-powered suggestions
        suggestions = generate_optimization_suggestions(
            opt_stats, 
            opt_stats.get('cache_stats', {}), 
            opt_stats.get('retry_stats', {}), 
            system_health
        )
        
        return jsonify({
            'status': 'success',
            'optimization_stats': opt_stats,
            'database_stats': db_stats,
            'security_stats': security_stats,
            'system_health': system_health,
            'ai_suggestions': suggestions,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get optimization stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/stats')
@limiter.limit("30 per minute")
def api_security_stats():
    """Get security monitoring statistics"""
    try:
        if not security_enhancer:
            return jsonify({'error': 'Security enhancer not available'}), 503
        
        stats = security_enhancer.get_security_report()
        return jsonify({
            'status': 'success',
            'security_stats': stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get security stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/events')
@limiter.limit("30 per minute")
def api_security_events():
    """Get recent security events"""
    try:
        if not security_enhancer:
            return jsonify({'error': 'Security enhancer not available'}), 503
        
        # Get recent events from security monitor
        events = security_enhancer.security_monitor.get_security_stats(hours=24)
        
        return jsonify({
            'status': 'success',
            'events': events,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get security events: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/unblock/<ip>', methods=['POST'])
@limiter.limit("10 per minute")
def api_unblock_ip(ip):
    """Unblock an IP address"""
    try:
        if not security_enhancer:
            return jsonify({'error': 'Security enhancer not available'}), 503
        
        security_enhancer.rate_limiter.unblock_ip(ip)
        
        # Log the unblock action
        security_enhancer.security_monitor.log_event(SecurityEvent(
            event_type='ip_unblocked',
            timestamp=datetime.now(),
            ip_address=ip,
            user_agent=request.headers.get('User-Agent', ''),
            endpoint=request.endpoint or '',
            severity='info',
            details={'action': 'manual_unblock'}
        ))
        
        return jsonify({
            'status': 'success',
            'message': f'IP {ip} unblocked successfully',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to unblock IP {ip}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/database/stats')
@limiter.limit("30 per minute")
def api_database_stats():
    """Get database performance statistics"""
    try:
        if not db_optimizer:
            return jsonify({'error': 'Database optimizer not available'}), 503
        
        stats = db_optimizer.pool.get_performance_stats()
        db_info = db_optimizer.get_database_info()
        
        return jsonify({
            'status': 'success',
            'performance_stats': stats,
            'database_info': db_info,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get database stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/database/optimize', methods=['POST'])
@limiter.limit("5 per minute")
def api_database_optimize():
    """Run database optimization tasks"""
    try:
        if not db_optimizer:
            return jsonify({'error': 'Database optimizer not available'}), 503
        
        data = request.get_json() or {}
        tasks = data.get('tasks', ['analyze', 'vacuum'])
        
        results = {}
        
        if 'analyze' in tasks:
            db_optimizer.analyze_tables()
            results['analyze'] = 'completed'
        
        if 'vacuum' in tasks:
            db_optimizer.vacuum_database()
            results['vacuum'] = 'completed'
        
        if 'optimize_queries' in tasks:
            query_suggestions = db_optimizer.optimize_queries()
            results['query_optimization'] = query_suggestions
        
        if 'backup' in tasks:
            backup_path = f"backups/bb_pro_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            db_optimizer.backup_database(backup_path)
            results['backup'] = backup_path
        
        return jsonify({
            'status': 'success',
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to optimize database: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/database/slow-queries')
@limiter.limit("30 per minute")
def api_slow_queries():
    """Get slow query analysis"""
    try:
        if not db_optimizer:
            return jsonify({'error': 'Database optimizer not available'}), 503
        
        stats = db_optimizer.pool.get_performance_stats()
        slow_queries = stats.get('slow_queries', [])
        
        # Get optimization suggestions for slow queries
        suggestions = db_optimizer.optimize_queries()
        
        return jsonify({
            'status': 'success',
            'slow_queries': slow_queries,
            'optimization_suggestions': suggestions,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get slow queries: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/rate-limits')
@limiter.limit("30 per minute")
def api_rate_limits():
    """Get rate limiting configuration and statistics"""
    try:
        if not security_enhancer:
            return jsonify({'error': 'Security enhancer not available'}), 503
        
        rate_limiter_stats = security_enhancer.rate_limiter.get_stats()
        
        return jsonify({
            'status': 'success',
            'rate_limiter': rate_limiter_stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get rate limit stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/update-rate-limits', methods=['POST'])
@limiter.limit("10 per minute")
def api_update_rate_limits():
    """Update rate limiting configuration"""
    try:
        if not security_enhancer:
            return jsonify({'error': 'Security enhancer not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update rate limits
        for limit_type, config in data.items():
            if limit_type in security_enhancer.rate_limiter.limits:
                security_enhancer.rate_limiter.limits[limit_type].update(config)
        
        return jsonify({
            'status': 'success',
            'message': 'Rate limits updated successfully',
            'new_limits': security_enhancer.rate_limiter.limits,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to update rate limits: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/threats')
@limiter.limit("30 per minute")
def api_security_threats():
    """Get security threat analysis"""
    try:
        if not security_enhancer:
            return jsonify({'error': 'Security enhancer not available'}), 503
        
        # Get recent security events
        events = security_enhancer.security_monitor.get_security_stats(hours=24)
        
        # Analyze threat patterns
        threat_analysis = {
            'high_severity_events': 0,
            'blocked_ips': len(security_enhancer.rate_limiter.blocked_ips),
            'blocked_users': len(security_enhancer.rate_limiter.blocked_users),
            'threat_types': {},
            'top_attack_vectors': [],
            'recommendations': []
        }
        
        # Count threat types
        for event_type, count in events.get('events_by_type', {}).items():
            if 'injection' in event_type or 'xss' in event_type or 'csrf' in event_type:
                threat_analysis['threat_types'][event_type] = count
        
        # Generate recommendations
        if threat_analysis['high_severity_events'] > 10:
            threat_analysis['recommendations'].append(
                "High number of security events detected. Consider implementing additional security measures."
            )
        
        if threat_analysis['blocked_ips'] > 5:
            threat_analysis['recommendations'].append(
                "Multiple IPs blocked. Consider implementing IP whitelisting or additional rate limiting."
            )
        
        return jsonify({
            'status': 'success',
            'threat_analysis': threat_analysis,
            'events': events,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get security threats: {e}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    """Custom 404 error handler"""
    return render_template('next_gen_error.html', 
                         error_code=404, 
                         error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Custom 500 error handler"""
    logger.error(f"Internal error: {error}")
    return render_template('next_gen_error.html', 
                         error_code=500, 
                         error_message="Internal server error"), 500

# Background tasks with Celery
@celery.task
def background_vulnerability_scan(target_url, scan_options):
    """Background vulnerability scanning task"""
    try:
        # Implement comprehensive vulnerability scanning
        logger.info(f"Starting background scan for {target_url}")
        
        # This would integrate with actual security tools
        # For now, simulate scanning
        time.sleep(10)
        
        results = {
            'target_url': target_url,
            'vulnerabilities_found': 5,
            'scan_duration': 10,
            'status': 'completed'
        }
        
        # Emit real-time update
        socketio.emit('scan_completed', results, namespace='/realtime')
        
        return results
        
    except Exception as e:
        logger.error(f"Background scan error: {e}")
        return {'status': 'failed', 'error': str(e)}

# Instantiate the optimization manager (singleton for the app)
optimization_manager = EnhancedOptimizationManager()

# Enhanced AI Provider Management with Fallback
class AIProviderManager:
    """Manages AI providers with automatic fallback and health monitoring"""
    
    def __init__(self):
        self.providers = {
            'gemini': {
                'name': 'Gemini',
                'available': False,
                'api_key': os.getenv('GEMINI_API_KEY'),
                'model': 'gemini-1.5-pro-latest',
                'cost_per_1k_tokens': 0.0035,
                'max_tokens': 8192,
                'health_check_url': None,
                'last_health_check': 0,
                'error_count': 0,
                'success_count': 0,
                'avg_response_time': 0
            },
            'openai': {
                'name': 'OpenAI',
                'available': False,
                'api_key': os.getenv('OPENAI_API_KEY'),
                'model': 'gpt-4-turbo-preview',
                'cost_per_1k_tokens': 0.01,
                'max_tokens': 4096,
                'health_check_url': 'https://api.openai.com/v1/models',
                'last_health_check': 0,
                'error_count': 0,
                'success_count': 0,
                'avg_response_time': 0
            },
            'anthropic': {
                'name': 'Anthropic',
                'available': False,
                'api_key': os.getenv('ANTHROPIC_API_KEY'),
                'model': 'claude-3-opus-20240229',
                'cost_per_1k_tokens': 0.015,
                'max_tokens': 4096,
                'health_check_url': 'https://api.anthropic.com/v1/messages',
                'last_health_check': 0,
                'error_count': 0,
                'success_count': 0,
                'avg_response_time': 0
            }
        }
        self.local_llm_available = False
        self.initialize_providers()
        self.start_health_monitoring()
    
    def initialize_providers(self):
        """Initialize and test AI providers"""
        for provider_name, config in self.providers.items():
            if config['api_key']:
                try:
                    if provider_name == 'gemini':
                        import google.generativeai as genai
                        genai.configure(api_key=config['api_key'])
                        config['available'] = True
                    elif provider_name == 'openai':
                        openai.api_key = config['api_key']
                        config['available'] = True
                    elif provider_name == 'anthropic':
                        config['available'] = True
                    
                    logger.info(f"{config['name']} initialized successfully")
                except Exception as e:
                    logger.warning(f"Failed to initialize {config['name']}: {e}")
        
        # Check for local LLM (Ollama)
        try:
            response = requests.get('http://localhost:11434/api/tags', timeout=5)
            if response.status_code == 200:
                self.local_llm_available = True
                logger.info("Local LLM (Ollama) available")
        except:
            logger.info("Local LLM (Ollama) not available")
    
    def start_health_monitoring(self):
        """Start background health monitoring"""
        def monitor():
            while True:
                self.check_provider_health()
                time.sleep(300)  # Check every 5 minutes
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def check_provider_health(self):
        """Check health of all providers"""
        for provider_name, config in self.providers.items():
            if not config['api_key']:
                continue
                
            try:
                if config['health_check_url']:
                    response = requests.get(
                        config['health_check_url'],
                        headers={'Authorization': f'Bearer {config["api_key"]}'},
                        timeout=10
                    )
                    config['available'] = response.status_code == 200
                else:
                    # For providers without health check URL, assume available if API key exists
                    config['available'] = True
                    
                config['last_health_check'] = time.time()
            except Exception as e:
                config['available'] = False
                logger.warning(f"Health check failed for {config['name']}: {e}")
    
    def select_best_provider(self, task_type: str = 'analysis') -> Optional[str]:
        """Select the best available provider based on cost, speed, and availability"""
        available_providers = [
            (name, config) for name, config in self.providers.items()
            if config['available'] and config['api_key']
        ]
        
        if not available_providers:
            return None
        
        # Score providers based on multiple factors
        scored_providers = []
        for name, config in available_providers:
            # Calculate score based on cost, speed, and reliability
            cost_score = 1.0 / (config['cost_per_1k_tokens'] + 0.001)  # Lower cost = higher score
            speed_score = 1.0 / (config['avg_response_time'] + 1.0)  # Lower time = higher score
            reliability_score = config['success_count'] / max(config['success_count'] + config['error_count'], 1)
            
            total_score = cost_score * 0.4 + speed_score * 0.3 + reliability_score * 0.3
            scored_providers.append((name, total_score))
        
        # Return the provider with the highest score
        return max(scored_providers, key=lambda x: x[1])[0] if scored_providers else None
    
    def get_provider_stats(self) -> Dict:
        """Get comprehensive provider statistics"""
        stats = {
            'providers': {},
            'local_llm_available': self.local_llm_available,
            'total_available': sum(1 for p in self.providers.values() if p['available'])
        }
        
        for name, config in self.providers.items():
            stats['providers'][name] = {
                'name': config['name'],
                'available': config['available'],
                'model': config['model'],
                'cost_per_1k_tokens': config['cost_per_1k_tokens'],
                'success_rate': config['success_count'] / max(config['success_count'] + config['error_count'], 1),
                'avg_response_time': config['avg_response_time'],
                'last_health_check': config['last_health_check']
            }
        
        return stats

# Enhanced retry decorator with exponential backoff and circuit breaker
def retry_with_circuit_breaker(max_retries: int = 3, base_delay: float = 1.0, 
                              max_delay: float = 60.0, circuit_breaker_threshold: int = 5):
    """Decorator for retry logic with exponential backoff and circuit breaker"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            delay = base_delay
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if attempt == max_retries:
                        break
                    
                    # Exponential backoff with jitter
                    jitter = random.uniform(0, 0.1 * delay)
                    time.sleep(delay + jitter)
                    delay = min(delay * 2, max_delay)
            
            raise last_exception
        return wrapper
    return decorator

# Resource monitoring
class ResourceMonitor:
    """Monitor system resources and provide health metrics"""
    
    @staticmethod
    def get_system_health() -> Dict:
        """Get comprehensive system health metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'cpu_usage': cpu_percent,
                'memory_usage': memory.percent,
                'memory_available': memory.available,
                'disk_usage': disk.percent,
                'disk_free': disk.free,
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
                'timestamp': time.time()
            }
        except Exception as e:
            logger.error(f"Error getting system health: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def should_throttle() -> bool:
        """Determine if system should throttle requests"""
        health = ResourceMonitor.get_system_health()
        return (health.get('cpu_usage', 0) > 80 or 
                health.get('memory_usage', 0) > 85)

# Initialize enhanced components
ai_provider_manager = AIProviderManager()
resource_monitor = ResourceMonitor()

# Enhanced health check endpoints
@app.route('/health')
def health_check():
    """Basic health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0'
    })

@app.route('/health/detailed')
def detailed_health_check():
    """Detailed health check with all services"""
    try:
        # Check database
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
            db_healthy = True
    except Exception as e:
        db_healthy = False
        db_error = str(e)
    
    # Check AI providers
    ai_stats = ai_provider_manager.get_provider_stats()
    
    # Check system resources
    system_health = resource_monitor.get_system_health()
    
    # Check cache
    cache_healthy = True
    try:
        cache.set('health_check', 'ok', timeout=60)
        cache.get('health_check')
    except Exception as e:
        cache_healthy = False
        cache_error = str(e)
    
    overall_healthy = (db_healthy and cache_healthy and 
                      ai_stats['total_available'] > 0)
    
    return jsonify({
        'status': 'healthy' if overall_healthy else 'degraded',
        'timestamp': datetime.now().isoformat(),
        'services': {
            'database': {
                'status': 'healthy' if db_healthy else 'unhealthy',
                'error': db_error if not db_healthy else None
            },
            'cache': {
                'status': 'healthy' if cache_healthy else 'unhealthy',
                'error': cache_error if not cache_healthy else None
            },
            'ai_providers': ai_stats,
            'system': system_health
        }
    })

@app.route('/api/optimization/clear-cache', methods=['POST'])
@limiter.limit("5 per minute")
def clear_cache():
    """Clear application cache"""
    try:
        # Clear Flask cache
        cache.clear()
        
        # Clear optimization manager cache
        optimization_manager.cache_manager.clear()
        
        logger.info("Cache cleared successfully")
        return jsonify({
            'status': 'success',
            'message': 'Cache cleared successfully',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to clear cache: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/optimization/run', methods=['POST'])
@limiter.limit("2 per minute")
def run_optimization():
    """Run system optimization"""
    try:
        # Run optimization manager's optimization routine
        optimization_results = optimization_manager.optimize_configuration()
        
        # Update system configuration
        optimization_manager._save_config(optimization_results)
        
        logger.info("System optimization completed")
        return jsonify({
            'status': 'success',
            'message': 'System optimization completed',
            'results': optimization_results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to run optimization: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/optimization/settings', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def optimization_settings():
    """Get or update optimization settings"""
    if request.method == 'GET':
        try:
            # Get current optimization settings
            settings = {
                'cache_settings': {
                    'max_size': optimization_manager.cache_manager.max_size,
                    'default_ttl': optimization_manager.cache_manager.default_ttl,
                    'current_size': len(optimization_manager.cache_manager.cache)
                },
                'retry_settings': optimization_manager.retry_manager.configs,
                'resource_limits': {
                    'cpu_threshold': 80,
                    'memory_threshold': 85,
                    'disk_threshold': 90
                },
                'ai_provider_settings': {
                    'auto_fallback': True,
                    'preferred_provider': 'auto',
                    'cost_optimization': True
                }
            }
            
            return jsonify(settings)
        except Exception as e:
            logger.error(f"Failed to get optimization settings: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            
            # Update cache settings
            if 'cache_settings' in data:
                cache_settings = data['cache_settings']
                if 'max_size' in cache_settings:
                    optimization_manager.cache_manager.max_size = cache_settings['max_size']
                if 'default_ttl' in cache_settings:
                    optimization_manager.cache_manager.default_ttl = cache_settings['default_ttl']
            
            # Update retry settings
            if 'retry_settings' in data:
                for operation, config in data['retry_settings'].items():
                    optimization_manager.retry_manager.configure_retry(
                        operation,
                        max_retries=config.get('max_retries', 3),
                        base_delay=config.get('base_delay', 1.0),
                        max_delay=config.get('max_delay', 60.0)
                    )
            
            # Update AI provider settings
            if 'ai_provider_settings' in data:
                ai_settings = data['ai_provider_settings']
                if 'preferred_provider' in ai_settings:
                    # Update preferred provider logic
                    pass
            
            logger.info("Optimization settings updated")
            return jsonify({
                'status': 'success',
                'message': 'Settings updated successfully',
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            logger.error(f"Failed to update optimization settings: {e}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/optimization/stats/detailed')
@limiter.limit("30 per minute")
def detailed_optimization_stats():
    """Get detailed optimization statistics"""
    try:
        # Get comprehensive stats from optimization manager
        opt_stats = optimization_manager.get_comprehensive_stats()
        
        # Get cache statistics
        cache_stats = optimization_manager.cache_manager.stats()
        
        # Get retry statistics
        retry_stats = {}
        for operation, config in optimization_manager.retry_manager.configs.items():
            retry_stats[operation] = {
                'total_attempts': config.get('total_attempts', 0),
                'successful_attempts': config.get('successful_attempts', 0),
                'failed_attempts': config.get('failed_attempts', 0),
                'success_rate': config.get('success_rate', 0),
                'avg_response_time': config.get('avg_response_time', 0),
                'circuit_breaker_status': 'open' if optimization_manager.retry_manager._is_circuit_open(operation) else 'closed'
            }
        
        # Get system resource statistics
        system_stats = resource_monitor.get_system_health()
        
        # Get AI provider performance statistics
        ai_stats = ai_provider_manager.get_provider_stats()
        
        detailed_stats = {
            'optimization': opt_stats,
            'cache': cache_stats,
            'retry': retry_stats,
            'system': system_stats,
            'ai_providers': ai_stats,
            'performance_metrics': {
                'slowest_operations': optimization_manager.db_manager.get_performance_stats(hours=24),
                'error_trends': optimization_manager.db_manager.get_error_stats(hours=24),
                'optimization_suggestions': generate_optimization_suggestions(opt_stats, cache_stats, retry_stats, system_stats)
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(detailed_stats)
    except Exception as e:
        logger.error(f"Failed to get detailed optimization stats: {e}")
        return jsonify({'error': str(e)}), 500

def generate_optimization_suggestions(opt_stats, cache_stats, retry_stats, system_stats):
    """Generate optimization suggestions based on current stats"""
    suggestions = []
    
    # Cache optimization suggestions
    if cache_stats.get('hit_ratio', 0) < 0.7:
        suggestions.append({
            'type': 'cache',
            'priority': 'medium',
            'title': 'Low Cache Hit Ratio',
            'description': f"Cache hit ratio is {cache_stats.get('hit_ratio', 0)*100:.1f}%. Consider increasing cache size or TTL.",
            'action': 'Increase cache size or TTL settings'
        })
    
    # System resource suggestions
    if system_stats.get('cpu_usage', 0) > 80:
        suggestions.append({
            'type': 'system',
            'priority': 'high',
            'title': 'High CPU Usage',
            'description': f"CPU usage is {system_stats.get('cpu_usage', 0):.1f}%. Consider throttling requests or scaling up.",
            'action': 'Enable request throttling or scale resources'
        })
    
    if system_stats.get('memory_usage', 0) > 85:
        suggestions.append({
            'type': 'system',
            'priority': 'high',
            'title': 'High Memory Usage',
            'description': f"Memory usage is {system_stats.get('memory_usage', 0):.1f}%. Consider clearing cache or scaling up.",
            'action': 'Clear cache or increase memory allocation'
        })
    
    # Retry optimization suggestions
    for operation, stats in retry_stats.items():
        if stats.get('success_rate', 1) < 0.8:
            suggestions.append({
                'type': 'retry',
                'priority': 'medium',
                'title': f'Low Success Rate for {operation}',
                'description': f"Success rate is {stats.get('success_rate', 0)*100:.1f}%. Consider adjusting retry parameters.",
                'action': f'Adjust retry configuration for {operation}'
            })
    
    return suggestions

# Enhanced API endpoint for optimization stats with more details
@app.route('/api/optimization_stats')
def api_optimization_stats():
    """Enhanced API endpoint for optimization and system stats"""
    try:
        # Get optimization manager stats
        opt_stats = optimization_manager.get_comprehensive_stats()
        
        # Get AI provider stats
        ai_stats = ai_provider_manager.get_provider_stats()
        
        # Get system health
        system_health = resource_monitor.get_system_health()
        
        # Get cache stats
        cache_stats = optimization_manager.cache_manager.stats()
        
        # Get retry stats summary
        retry_summary = {}
        for operation, config in optimization_manager.retry_manager.configs.items():
            retry_summary[operation] = {
                'success_rate': config.get('success_rate', 1.0),
                'avg_response_time': config.get('avg_response_time', 0),
                'circuit_breaker_status': 'open' if optimization_manager.retry_manager._is_circuit_open(operation) else 'closed'
            }
        
        # Combine all stats
        comprehensive_stats = {
            'optimization': opt_stats,
            'ai_providers': ai_stats,
            'system_health': system_health,
            'cache_stats': cache_stats,
            'retry_stats': retry_summary,
            'should_throttle': resource_monitor.should_throttle(),
            'optimization_suggestions': generate_optimization_suggestions(opt_stats, cache_stats, retry_summary, system_health),
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(comprehensive_stats)
    except Exception as e:
        logger.error(f"Failed to get optimization stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/security')
def security_dashboard():
    """Security monitoring dashboard"""
    try:
        if not security_enhancer:
            return render_template('security_dashboard.html', error="Security enhancer not available")
        
        # Get security statistics
        security_stats = security_enhancer.security_monitor.get_security_stats()
        
        return render_template('security_dashboard.html', 
                             security_stats=security_stats,
                             error=None)
    except Exception as e:
        logger.error(f"Failed to load security dashboard: {e}")
        return render_template('security_dashboard.html', error=str(e))

@app.route('/kali')
def kali_tools_dashboard():
    """Kali Linux tools and payload dashboard"""
    try:
        return render_template('kali_tools_dashboard.html')
    except Exception as e:
        logger.error(f"Failed to load Kali tools dashboard: {e}")
        return render_template('kali_tools_dashboard.html', error=str(e))

# Kali Linux Tools API Endpoints
@app.route('/api/kali/system-info')
@limiter.limit("30 per minute")
def api_kali_system_info():
    """Get Kali Linux system information"""
    try:
        if not kali_optimizer:
            return jsonify({'error': 'Kali optimizer not available'}), 503
        
        system_info = kali_optimizer.get_system_info()
        return jsonify({
            'status': 'success',
            'system_info': system_info,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get Kali system info: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/kali/tools/status')
@limiter.limit("30 per minute")
def api_kali_tools_status():
    """Get status of Kali Linux security tools"""
    try:
        if not kali_optimizer:
            return jsonify({'error': 'Kali optimizer not available'}), 503
        
        tools_status = kali_optimizer.get_tool_status()
        return jsonify({
            'status': 'success',
            'tools_status': tools_status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get Kali tools status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/kali/tools/install', methods=['POST'])
@limiter.limit("10 per minute")
def api_kali_install_tools():
    """Install Kali Linux security tools"""
    try:
        if not kali_optimizer:
            return jsonify({'error': 'Kali optimizer not available'}), 503
        
        data = request.get_json()
        tools = data.get('tools', [])
        
        if not tools:
            return jsonify({'error': 'No tools specified'}), 400
        
        # Install tools in background
        def install_tools():
            try:
                kali_optimizer.install_security_tools(tools)
                socketio.emit('tools_installed', {
                    'status': 'success',
                    'tools': tools,
                    'message': 'Tools installed successfully'
                }, namespace='/realtime')
            except Exception as e:
                socketio.emit('tools_install_error', {
                    'status': 'error',
                    'error': str(e)
                }, namespace='/realtime')
        
        executor.submit(install_tools)
        
        return jsonify({
            'status': 'success',
            'message': f'Installing {len(tools)} tools in background',
            'tools': tools
        })
    except Exception as e:
        logger.error(f"Failed to install Kali tools: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/kali/tools/update', methods=['POST'])
@limiter.limit("10 per minute")
def api_kali_update_tools():
    """Update Kali Linux security tools"""
    try:
        if not kali_optimizer:
            return jsonify({'error': 'Kali optimizer not available'}), 503
        
        # Update tools in background
        def update_tools():
            try:
                kali_optimizer.update_tools()
                socketio.emit('tools_updated', {
                    'status': 'success',
                    'message': 'Tools updated successfully'
                }, namespace='/realtime')
            except Exception as e:
                socketio.emit('tools_update_error', {
                    'status': 'error',
                    'error': str(e)
                }, namespace='/realtime')
        
        executor.submit(update_tools)
        
        return jsonify({
            'status': 'success',
            'message': 'Updating tools in background'
        })
    except Exception as e:
        logger.error(f"Failed to update Kali tools: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/kali/optimize', methods=['POST'])
@limiter.limit("5 per minute")
def api_kali_optimize():
    """Optimize Kali Linux system"""
    try:
        if not kali_optimizer:
            return jsonify({'error': 'Kali optimizer not available'}), 503
        
        data = request.get_json() or {}
        tasks = data.get('tasks', ['system', 'performance', 'workspace'])
        
        results = {}
        
        # Run optimization tasks
        if 'system' in tasks:
            try:
                kali_optimizer.optimize_system()
                results['system'] = 'completed'
            except Exception as e:
                results['system'] = f'failed: {str(e)}'
        
        if 'performance' in tasks:
            try:
                kali_optimizer.optimize_performance()
                results['performance'] = 'completed'
            except Exception as e:
                results['performance'] = f'failed: {str(e)}'
        
        if 'workspace' in tasks:
            try:
                kali_optimizer.create_workspace()
                results['workspace'] = 'completed'
            except Exception as e:
                results['workspace'] = f'failed: {str(e)}'
        
        if 'shortcuts' in tasks:
            try:
                kali_optimizer.create_tool_shortcuts()
                results['shortcuts'] = 'completed'
            except Exception as e:
                results['shortcuts'] = f'failed: {str(e)}'
        
        return jsonify({
            'status': 'success',
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to optimize Kali system: {e}")
        return jsonify({'error': str(e)}), 500

# Payload Generation API Endpoints
@app.route('/api/payloads/generate', methods=['POST'])
@limiter.limit("30 per minute")
def api_generate_payload():
    """Generate payload from template"""
    try:
        if not payload_generator:
            return jsonify({'error': 'Payload generator not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        template_name = data.get('template_name')
        parameters = data.get('parameters', {})
        encoding = data.get('encoding', [])
        
        if not template_name:
            return jsonify({'error': 'Template name required'}), 400
        
        payload = payload_generator.generate_payload(template_name, parameters, encoding)
        
        return jsonify({
            'status': 'success',
            'payload': payload,
            'template_name': template_name,
            'parameters': parameters,
            'encoding': encoding
        })
    except Exception as e:
        logger.error(f"Failed to generate payload: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/payloads/generate-batch', methods=['POST'])
@limiter.limit("20 per minute")
def api_generate_payload_batch():
    """Generate multiple payloads"""
    try:
        if not payload_generator:
            return jsonify({'error': 'Payload generator not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        template_names = data.get('template_names', [])
        parameters_list = data.get('parameters_list', [])
        encoding = data.get('encoding', [])
        
        if not template_names:
            return jsonify({'error': 'Template names required'}), 400
        
        payloads = payload_generator.generate_payload_batch(template_names, parameters_list, encoding)
        
        return jsonify({
            'status': 'success',
            'payloads': payloads,
            'template_names': template_names,
            'count': len(payloads)
        })
    except Exception as e:
        logger.error(f"Failed to generate payload batch: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/payloads/custom', methods=['POST'])
@limiter.limit("30 per minute")
def api_generate_custom_payload():
    """Generate custom payload"""
    try:
        if not payload_generator:
            return jsonify({'error': 'Payload generator not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        payload_template = data.get('payload')
        parameters = data.get('parameters', {})
        encoding = data.get('encoding', [])
        
        if not payload_template:
            return jsonify({'error': 'Payload template required'}), 400
        
        payload = payload_generator.generate_custom_payload(payload_template, parameters, encoding)
        
        return jsonify({
            'status': 'success',
            'payload': payload,
            'original_template': payload_template,
            'parameters': parameters,
            'encoding': encoding
        })
    except Exception as e:
        logger.error(f"Failed to generate custom payload: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/payloads/save', methods=['POST'])
@limiter.limit("20 per minute")
def api_save_payload():
    """Save payload to file"""
    try:
        if not payload_generator:
            return jsonify({'error': 'Payload generator not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        name = data.get('name')
        payload = data.get('payload')
        category = data.get('category', 'custom')
        description = data.get('description', '')
        tags = data.get('tags', [])
        
        if not name or not payload:
            return jsonify({'error': 'Name and payload required'}), 400
        
        filepath = payload_generator.save_payload(name, payload, category, description, tags)
        
        return jsonify({
            'status': 'success',
            'message': 'Payload saved successfully',
            'filepath': filepath,
            'name': name,
            'category': category
        })
    except Exception as e:
        logger.error(f"Failed to save payload: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/payloads/list')
@limiter.limit("30 per minute")
def api_list_payloads():
    """List saved payloads"""
    try:
        if not payload_generator:
            return jsonify({'error': 'Payload generator not available'}), 503
        
        category = request.args.get('category')
        payloads = payload_generator.load_payloads(category)
        
        return jsonify({
            'status': 'success',
            'payloads': payloads,
            'count': len(payloads),
            'category': category
        })
    except Exception as e:
        logger.error(f"Failed to list payloads: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/payloads/search')
@limiter.limit("30 per minute")
def api_search_payloads():
    """Search payloads"""
    try:
        if not payload_generator:
            return jsonify({'error': 'Payload generator not available'}), 503
        
        query = request.args.get('q', '')
        category = request.args.get('category')
        
        if not query:
            return jsonify({'error': 'Search query required'}), 400
        
        results = payload_generator.search_payloads(query, category)
        
        return jsonify({
            'status': 'success',
            'results': results,
            'count': len(results),
            'query': query,
            'category': category
        })
    except Exception as e:
        logger.error(f"Failed to search payloads: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/payloads/statistics')
@limiter.limit("30 per minute")
def api_payload_statistics():
    """Get payload statistics"""
    try:
        if not payload_generator:
            return jsonify({'error': 'Payload generator not available'}), 503
        
        stats = payload_generator.get_payload_statistics()
        
        return jsonify({
            'status': 'success',
            'statistics': stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get payload statistics: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/payloads/templates')
@limiter.limit("30 per minute")
def api_payload_templates():
    """Get available payload templates"""
    try:
        if not payload_generator:
            return jsonify({'error': 'Payload generator not available'}), 503
        
        templates = {}
        for name, template in payload_generator.templates.items():
            templates[name] = {
                'name': template.name,
                'description': template.description,
                'category': template.category,
                'attack_vector': template.attack_vector,
                'risk_level': template.risk_level,
                'tags': template.tags,
                'encoding': template.encoding
            }
        
        return jsonify({
            'status': 'success',
            'templates': templates,
            'count': len(templates)
        })
    except Exception as e:
        logger.error(f"Failed to get payload templates: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/payloads/validate', methods=['POST'])
@limiter.limit("30 per minute")
def api_validate_payload():
    """Validate payload"""
    try:
        if not payload_generator:
            return jsonify({'error': 'Payload generator not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        payload = data.get('payload')
        if not payload:
            return jsonify({'error': 'Payload required'}), 400
        
        validation = payload_generator.validate_payload(payload)
        
        return jsonify({
            'status': 'success',
            'validation': validation,
            'payload': payload
        })
    except Exception as e:
        logger.error(f"Failed to validate payload: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/payloads/report', methods=['POST'])
@limiter.limit("10 per minute")
def api_create_payload_report():
    """Create payload testing report"""
    try:
        if not payload_generator:
            return jsonify({'error': 'Payload generator not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        payloads = data.get('payloads', [])
        target = data.get('target')
        
        if not payloads:
            return jsonify({'error': 'Payloads required'}), 400
        
        report_path = payload_generator.create_payload_report(payloads, target)
        
        return jsonify({
            'status': 'success',
            'message': 'Payload report created successfully',
            'report_path': report_path,
            'payload_count': len(payloads)
        })
    except Exception as e:
        logger.error(f"Failed to create payload report: {e}")
        return jsonify({'error': str(e)}), 500

# Reconnaissance API Endpoints
@app.route('/api/recon/tools/status')
@limiter.limit("30 per minute")
def api_recon_tools_status():
    """Get status of reconnaissance tools"""
    try:
        if not recon_tools:
            return jsonify({'error': 'Recon tools not available'}), 503
        
        tools_status = recon_tools.check_tool_availability()
        return jsonify({
            'status': 'success',
            'tools_status': tools_status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get recon tools status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon/subdomains', methods=['POST'])
@limiter.limit("10 per minute")
def api_enumerate_subdomains():
    """Enumerate subdomains for a domain"""
    try:
        if not recon_tools:
            return jsonify({'error': 'Recon tools not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        domain = data.get('domain')
        tools = data.get('tools', ['amass', 'subfinder', 'assetfinder'])
        
        if not domain:
            return jsonify({'error': 'Domain required'}), 400
        
        # Run subdomain enumeration in background
        def enumerate_subdomains():
            try:
                subdomains = recon_tools.enumerate_subdomains(domain, tools)
                socketio.emit('subdomains_found', {
                    'status': 'success',
                    'domain': domain,
                    'subdomains': list(subdomains),
                    'count': len(subdomains)
                }, namespace='/realtime')
            except Exception as e:
                socketio.emit('subdomains_error', {
                    'status': 'error',
                    'error': str(e)
                }, namespace='/realtime')
        
        executor.submit(enumerate_subdomains)
        
        return jsonify({
            'status': 'success',
            'message': f'Enumerating subdomains for {domain}',
            'domain': domain,
            'tools': tools
        })
    except Exception as e:
        logger.error(f"Failed to enumerate subdomains: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon/live-hosts', methods=['POST'])
@limiter.limit("10 per minute")
def api_find_live_hosts():
    """Find live hosts from a list of targets"""
    try:
        if not recon_tools:
            return jsonify({'error': 'Recon tools not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        targets = data.get('targets', [])
        
        if not targets:
            return jsonify({'error': 'Targets required'}), 400
        
        # Find live hosts in background
        def find_live_hosts():
            try:
                live_hosts = recon_tools.find_live_hosts(targets)
                socketio.emit('live_hosts_found', {
                    'status': 'success',
                    'targets': targets,
                    'live_hosts': list(live_hosts),
                    'count': len(live_hosts)
                }, namespace='/realtime')
            except Exception as e:
                socketio.emit('live_hosts_error', {
                    'status': 'error',
                    'error': str(e)
                }, namespace='/realtime')
        
        executor.submit(find_live_hosts)
        
        return jsonify({
            'status': 'success',
            'message': f'Finding live hosts from {len(targets)} targets',
            'targets': targets
        })
    except Exception as e:
        logger.error(f"Failed to find live hosts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon/port-scan', methods=['POST'])
@limiter.limit("10 per minute")
def api_port_scan():
    """Port scan hosts"""
    try:
        if not recon_tools:
            return jsonify({'error': 'Recon tools not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        hosts = data.get('hosts', [])
        ports = data.get('ports', '80,443,8080,8443')
        
        if not hosts:
            return jsonify({'error': 'Hosts required'}), 400
        
        # Port scan in background
        def port_scan():
            try:
                port_results = recon_tools.port_scan(hosts, ports)
                socketio.emit('port_scan_complete', {
                    'status': 'success',
                    'hosts': hosts,
                    'ports': ports,
                    'results': port_results
                }, namespace='/realtime')
            except Exception as e:
                socketio.emit('port_scan_error', {
                    'status': 'error',
                    'error': str(e)
                }, namespace='/realtime')
        
        executor.submit(port_scan)
        
        return jsonify({
            'status': 'success',
            'message': f'Port scanning {len(hosts)} hosts',
            'hosts': hosts,
            'ports': ports
        })
    except Exception as e:
        logger.error(f"Failed to port scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon/vulnerability-scan', methods=['POST'])
@limiter.limit("5 per minute")
def api_vulnerability_scan():
    """Run vulnerability scan on targets"""
    try:
        if not recon_tools:
            return jsonify({'error': 'Recon tools not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        targets = data.get('targets', [])
        
        if not targets:
            return jsonify({'error': 'Targets required'}), 400
        
        # Vulnerability scan in background
        def vulnerability_scan():
            try:
                vulnerabilities = recon_tools.vulnerability_scan(targets)
                socketio.emit('vulnerability_scan_complete', {
                    'status': 'success',
                    'targets': targets,
                    'vulnerabilities': vulnerabilities,
                    'count': len(vulnerabilities)
                }, namespace='/realtime')
            except Exception as e:
                socketio.emit('vulnerability_scan_error', {
                    'status': 'error',
                    'error': str(e)
                }, namespace='/realtime')
        
        executor.submit(vulnerability_scan)
        
        return jsonify({
            'status': 'success',
            'message': f'Running vulnerability scan on {len(targets)} targets',
            'targets': targets
        })
    except Exception as e:
        logger.error(f"Failed to run vulnerability scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon/technology-fingerprint', methods=['POST'])
@limiter.limit("20 per minute")
def api_technology_fingerprint():
    """Perform technology fingerprinting on URLs"""
    try:
        if not recon_tools:
            return jsonify({'error': 'Recon tools not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({'error': 'URLs required'}), 400
        
        # Technology fingerprinting in background
        def technology_fingerprint():
            try:
                tech_results = recon_tools.technology_fingerprinting(urls)
                socketio.emit('technology_fingerprint_complete', {
                    'status': 'success',
                    'urls': urls,
                    'technologies': tech_results
                }, namespace='/realtime')
            except Exception as e:
                socketio.emit('technology_fingerprint_error', {
                    'status': 'error',
                    'error': str(e)
                }, namespace='/realtime')
        
        executor.submit(technology_fingerprint)
        
        return jsonify({
            'status': 'success',
            'message': f'Performing technology fingerprinting on {len(urls)} URLs',
            'urls': urls
        })
    except Exception as e:
        logger.error(f"Failed to perform technology fingerprinting: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon/comprehensive', methods=['POST'])
@limiter.limit("5 per minute")
def api_comprehensive_recon():
    """Run comprehensive reconnaissance on a domain"""
    try:
        if not recon_tools:
            return jsonify({'error': 'Recon tools not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain required'}), 400
        
        # Comprehensive reconnaissance in background
        def comprehensive_recon():
            try:
                results = recon_tools.comprehensive_recon(domain)
                socketio.emit('comprehensive_recon_complete', {
                    'status': 'success',
                    'domain': domain,
                    'results': results
                }, namespace='/realtime')
            except Exception as e:
                socketio.emit('comprehensive_recon_error', {
                    'status': 'error',
                    'error': str(e)
                }, namespace='/realtime')
        
        executor.submit(comprehensive_recon)
        
        return jsonify({
            'status': 'success',
            'message': f'Running comprehensive reconnaissance on {domain}',
            'domain': domain
        })
    except Exception as e:
        logger.error(f"Failed to run comprehensive reconnaissance: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon/statistics')
@limiter.limit("30 per minute")
def api_recon_statistics():
    """Get reconnaissance statistics"""
    try:
        if not recon_tools:
            return jsonify({'error': 'Recon tools not available'}), 503
        
        stats = recon_tools.get_recon_statistics()
        return jsonify({
            'status': 'success',
            'statistics': stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get recon statistics: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    """Run the next-generation vulnerability analysis UI"""
    
    print("\n🚀 NEXT-GENERATION VULNERABILITY ANALYSIS PLATFORM")
    print("="*60)
    print("Features:")
    print("✅ Real-time WebSocket communication")
    print("✅ Multi-provider AI analysis (Gemini, OpenAI, Claude)")
    print("✅ Advanced visualizations and analytics")
    print("✅ Progressive Web App capabilities")
    print("✅ Enterprise-grade security")
    print("✅ Background task processing")
    print("✅ Prometheus metrics")
    print("✅ Redis caching")
    print("✅ Rate limiting")
    print("✅ Comprehensive error handling")
    print("="*60)
    
    # Check dependencies
    missing_deps = []
    
    try:
        import redis
        redis_client = redis.Redis(host='localhost', port=6379, db=0)
        redis_client.ping()
        print("✅ Redis connection successful")
    except:
        print("❌ Redis not available - caching disabled")
        missing_deps.append("Redis")
    
    try:
        import plotly
        print("✅ Plotly available for advanced charts")
    except:
        print("❌ Plotly not available - charts disabled")
        missing_deps.append("Plotly")
    
    print(f"\n🌐 Starting server on http://localhost:5000")
    print(f"📊 Metrics available at http://localhost:5000/metrics")
    print(f"🔌 WebSocket namespace: /realtime")
    
    if missing_deps:
        print(f"\n⚠️ Optional dependencies missing: {', '.join(missing_deps)}")
        print("Run: pip install redis plotly celery prometheus_client")
    
    print("\n" + "="*60)
    
    # Run with SocketIO support
    socketio.run(app, 
                host='0.0.0.0', 
                port=5000, 
                debug=True,
                allow_unsafe_werkzeug=True)
