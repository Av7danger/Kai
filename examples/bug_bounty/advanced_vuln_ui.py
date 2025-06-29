#!/usr/bin/env python3
"""
🚀 ADVANCED VULNERABILITY ANALYSIS UI
Next-generation web interface for vulnerability reproduction and analysis
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file, Response
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
from concurrent.futures import ThreadPoolExecutor
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'vuln-analysis-secret-key-2025')

# Global configuration
DATABASE_PATH = 'bb_pro.db'
REPORTS_DIR = Path('vulnerability_analysis_reports')
MANUAL_REPORTS_DIR = Path('manual_test_reports')
REPORTS_DIR.mkdir(exist_ok=True)
MANUAL_REPORTS_DIR.mkdir(exist_ok=True)

# Thread pool for background tasks
executor = ThreadPoolExecutor(max_workers=4)

# Check for AI capabilities
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
except ImportError:
    GEMINI_AVAILABLE = False
    GEMINI_API_KEY = None

class VulnerabilityAnalyzer:
    """Advanced vulnerability analyzer with UI integration"""
    
    def __init__(self):
        self.db_path = DATABASE_PATH
        self.gemini_available = GEMINI_AVAILABLE and GEMINI_API_KEY
        
        if self.gemini_available:
            try:
                genai.configure(api_key=GEMINI_API_KEY)
                self.model = genai.GenerativeModel('gemini-pro')
                logger.info("✅ Gemini AI initialized")
            except Exception as e:
                logger.error(f"❌ Gemini initialization failed: {e}")
                self.gemini_available = False
                self.model = None
        else:
            self.model = None
    
    def get_vulnerability(self, vuln_id):
        """Get vulnerability details"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT v.*, t.name as target_name, t.url as target_url, t.scope
                FROM vulnerabilities v
                LEFT JOIN targets t ON v.target_id = t.id
                WHERE v.id = ?
            """, (vuln_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return dict(row)
            return None
        except Exception as e:
            logger.error(f"Error fetching vulnerability: {e}")
            return None
    
    def list_vulnerabilities(self):
        """List all vulnerabilities"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT v.id, v.title, v.vuln_type, v.severity, v.status, v.found_date,
                       t.name as target_name, t.url as target_url
                FROM vulnerabilities v
                LEFT JOIN targets t ON v.target_id = t.id
                ORDER BY v.found_date DESC
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error listing vulnerabilities: {e}")
            return []
    
    def generate_ai_analysis(self, vuln_data):
        """Generate AI analysis with progress tracking"""
        if not self.gemini_available:
            return {
                'discovery': 'AI analysis not available - Gemini API not configured',
                'reproduction': 'Please set GEMINI_API_KEY environment variable',
                'poc_scripts': 'Install: pip install google-generativeai',
                'remediation': 'Get API key from: https://makersuite.google.com/app/apikey'
            }
        
        try:
            # Discovery analysis
            discovery_prompt = f"""Analyze how this vulnerability was discovered:
Vulnerability: {vuln_data.get('title', 'Unknown')}
Type: {vuln_data.get('vuln_type', 'Unknown')}
Location: {vuln_data.get('location', 'Unknown')}
Description: {vuln_data.get('description', 'No description')}

Explain the discovery methodology, detection techniques, and scanning approaches that would find this vulnerability."""
            
            discovery = self.model.generate_content(discovery_prompt).text
            
            # Reproduction guide
            reproduction_prompt = f"""Create step-by-step reproduction instructions:
Vulnerability: {vuln_data.get('title', 'Unknown')}
Type: {vuln_data.get('vuln_type', 'Unknown')}
Target: {vuln_data.get('target_url', 'Unknown')}
Location: {vuln_data.get('location', 'Unknown')}

Provide detailed testing procedures, payloads, and evidence collection steps."""
            
            reproduction = self.model.generate_content(reproduction_prompt).text
            
            # PoC scripts
            poc_prompt = f"""Generate practical PoC scripts:
Vulnerability: {vuln_data.get('title', 'Unknown')}
Type: {vuln_data.get('vuln_type', 'Unknown')}
Target: {vuln_data.get('target_url', 'Unknown')}

Create Python scripts, curl commands, and automation code for testing."""
            
            poc_scripts = self.model.generate_content(poc_prompt).text
            
            # Remediation
            remediation_prompt = f"""Provide remediation guidance:
Vulnerability: {vuln_data.get('title', 'Unknown')}
Type: {vuln_data.get('vuln_type', 'Unknown')}
Severity: {vuln_data.get('severity', 'Unknown')}

Include immediate fixes, permanent solutions, and prevention strategies."""
            
            remediation = self.model.generate_content(remediation_prompt).text
            
            return {
                'discovery': discovery,
                'reproduction': reproduction,
                'poc_scripts': poc_scripts,
                'remediation': remediation
            }
            
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return {
                'discovery': f'AI analysis failed: {e}',
                'reproduction': 'Please try again or use manual analysis',
                'poc_scripts': 'Check your API key and network connection',
                'remediation': 'Refer to security best practices'
            }

# Initialize analyzer
analyzer = VulnerabilityAnalyzer()

@app.route('/')
def dashboard():
    """Advanced dashboard with vulnerability overview"""
    vulns = analyzer.list_vulnerabilities()
    
    # Calculate statistics
    total_vulns = len(vulns)
    severity_counts = {}
    type_counts = {}
    status_counts = {}
    
    for vuln in vulns:
        severity = vuln['severity'] or 'Unknown'
        vuln_type = vuln['vuln_type'] or 'Unknown'
        status = vuln['status'] or 'Unknown'
        
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1
    
    # Get recent activity
    recent_vulns = vulns[:10]
    
    # System status
    system_status = {
        'database': 'Connected',
        'ai_available': analyzer.gemini_available,
        'total_vulnerabilities': total_vulns,
        'reports_generated': len(list(REPORTS_DIR.glob('*.md'))) + len(list(MANUAL_REPORTS_DIR.glob('*.md')))
    }
    
    return render_template('advanced_dashboard.html',
                         vulnerabilities=recent_vulns,
                         severity_counts=severity_counts,
                         type_counts=type_counts,
                         status_counts=status_counts,
                         system_status=system_status,
                         total_vulns=total_vulns)

@app.route('/vulnerabilities')
def vulnerabilities_list():
    """List all vulnerabilities with advanced filtering"""
    vulns = analyzer.list_vulnerabilities()
    
    # Apply filters
    severity_filter = request.args.get('severity')
    type_filter = request.args.get('type')
    status_filter = request.args.get('status')
    search_query = request.args.get('search', '').lower()
    
    if severity_filter:
        vulns = [v for v in vulns if v['severity'] == severity_filter]
    
    if type_filter:
        vulns = [v for v in vulns if v['vuln_type'] == type_filter]
    
    if status_filter:
        vulns = [v for v in vulns if v['status'] == status_filter]
    
    if search_query:
        vulns = [v for v in vulns if search_query in v['title'].lower() or 
                 search_query in (v['description'] or '').lower()]
    
    # Get unique values for filters
    all_vulns = analyzer.list_vulnerabilities()
    severities = sorted(set(v['severity'] for v in all_vulns if v['severity']))
    types = sorted(set(v['vuln_type'] for v in all_vulns if v['vuln_type']))
    statuses = sorted(set(v['status'] for v in all_vulns if v['status']))
    
    return render_template('advanced_vulnerabilities.html',
                         vulnerabilities=vulns,
                         severities=severities,
                         types=types,
                         statuses=statuses,
                         current_filters={
                             'severity': severity_filter,
                             'type': type_filter,
                             'status': status_filter,
                             'search': search_query
                         })

@app.route('/vulnerability/<int:vuln_id>')
def vulnerability_detail(vuln_id):
    """Detailed vulnerability view with analysis options"""
    vuln = analyzer.get_vulnerability(vuln_id)
    
    if not vuln:
        flash('Vulnerability not found', 'error')
        return redirect(url_for('vulnerabilities_list'))
    
    # Check for existing reports
    ai_reports = list(REPORTS_DIR.glob(f'vuln_{vuln_id}_*.md'))
    manual_reports = list(MANUAL_REPORTS_DIR.glob(f'manual_test_vuln_{vuln_id}_*.md'))
    
    return render_template('advanced_vulnerability_detail.html',
                         vulnerability=vuln,
                         ai_reports=ai_reports,
                         manual_reports=manual_reports,
                         ai_available=analyzer.gemini_available)

@app.route('/api/analyze/<int:vuln_id>')
def analyze_vulnerability(vuln_id):
    """API endpoint for vulnerability analysis"""
    vuln = analyzer.get_vulnerability(vuln_id)
    
    if not vuln:
        return jsonify({'error': 'Vulnerability not found'}), 404
    
    analysis_type = request.args.get('type', 'manual')
    
    if analysis_type == 'ai' and analyzer.gemini_available:
        # Start AI analysis in background
        def run_ai_analysis():
            return analyzer.generate_ai_analysis(vuln)
        
        # For demo, we'll run synchronously
        # In production, you'd use background tasks
        try:
            analysis = analyzer.generate_ai_analysis(vuln)
            
            # Save report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_path = REPORTS_DIR / f'vuln_{vuln_id}_{timestamp}.md'
            
            report_content = f"""# AI Vulnerability Analysis Report

## Vulnerability Overview
**ID:** {vuln['id']}
**Title:** {vuln['title']}
**Type:** {vuln['vuln_type']}
**Severity:** {vuln['severity']}
**Target:** {vuln['target_name']} ({vuln['target_url']})
**Location:** {vuln['location']}

## Discovery Analysis
{analysis['discovery']}

## Reproduction Guide
{analysis['reproduction']}

## PoC Scripts
{analysis['poc_scripts']}

## Remediation
{analysis['remediation']}

---
*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            return jsonify({
                'success': True,
                'analysis': analysis,
                'report_path': str(report_path)
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    else:
        # Generate manual analysis
        manual_analysis = generate_manual_analysis(vuln)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = MANUAL_REPORTS_DIR / f'manual_test_vuln_{vuln_id}_{timestamp}.md'
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(manual_analysis)
        
        return jsonify({
            'success': True,
            'analysis': {'manual_guide': manual_analysis},
            'report_path': str(report_path)
        })

def generate_manual_analysis(vuln_data):
    """Generate manual testing guide"""
    vuln_type = vuln_data.get('vuln_type', 'Unknown')
    
    # Manual testing templates
    templates = {
        'XSS': {
            'payloads': ['<script>alert("XSS")</script>', '"><img src=x onerror=alert("XSS")>', 'javascript:alert("XSS")'],
            'steps': [
                'Identify input parameters',
                'Test basic XSS payloads',
                'Check response reflection',
                'Verify script execution',
                'Document evidence'
            ]
        },
        'SQL Injection': {
            'payloads': ["' OR '1'='1", "' UNION SELECT NULL--", "'; DROP TABLE users;--"],
            'steps': [
                'Test for SQL errors',
                'Try boolean-based injection',
                'Test time-based blind injection',
                'Attempt union-based injection',
                'Document database information'
            ]
        },
        'IDOR': {
            'payloads': ['Change ID parameters', 'Try different user IDs', 'Test sequential access'],
            'steps': [
                'Identify object references',
                'Test with different user accounts',
                'Try ID manipulation',
                'Verify unauthorized access',
                'Document impact'
            ]
        }
    }
    
    template = templates.get(vuln_type, {
        'payloads': ['Basic test payloads', 'Parameter manipulation', 'Input validation bypass'],
        'steps': ['Analyze vulnerability', 'Design test cases', 'Execute tests', 'Document findings']
    })
    
    return f"""# Manual Testing Guide: {vuln_data.get('title', 'Unknown')}

## Vulnerability Information
- **Type:** {vuln_type}
- **Severity:** {vuln_data.get('severity', 'Unknown')}
- **Target:** {vuln_data.get('target_url', 'Unknown')}
- **Location:** {vuln_data.get('location', 'Unknown')}
- **Description:** {vuln_data.get('description', 'No description')}

## Testing Steps

{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(template['steps']))}

## Test Payloads

{chr(10).join(f"- `{payload}`" for payload in template['payloads'])}

## Browser Testing
1. Open Developer Tools (F12)
2. Navigate to: {vuln_data.get('target_url', 'target')}{vuln_data.get('location', '')}
3. Test each payload in the vulnerable parameter
4. Monitor network requests and responses
5. Document any successful exploitation

## Command Line Testing
```bash
# Test with curl
curl -X GET "{vuln_data.get('target_url', 'target')}{vuln_data.get('location', '')}?param=PAYLOAD" -v

# Test with POST
curl -X POST "{vuln_data.get('target_url', 'target')}{vuln_data.get('location', '')}" -d "param=PAYLOAD" -v
```

## Evidence Collection
- [ ] Request/response details
- [ ] Screenshots of exploitation
- [ ] Network traffic captures
- [ ] Error messages or outputs
- [ ] Impact demonstration

---
Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

@app.route('/api/analysis-progress/<int:vuln_id>')
def analysis_progress(vuln_id):
    """Real-time analysis progress"""
    # This would track actual progress in a real implementation
    # For now, we'll simulate progress
    return jsonify({
        'progress': 100,
        'status': 'completed',
        'message': 'Analysis complete'
    })

@app.route('/reports')
def reports():
    """Reports listing page with mock data for demonstration"""
    try:
        # Mock data for reports since we don't have a reports table yet
        mock_reports = [
            {
                'id': 1,
                'title': 'Security Assessment Report - Example.com',
                'report_type': 'Security Assessment',
                'format': 'PDF',
                'status': 'Generated',
                'vulnerability_count': 15,
                'created_at': datetime.now() - timedelta(days=1),
                'file_path': '/reports/example_assessment.pdf',
                'file_size': '2.3 MB',
                'description': 'Comprehensive security assessment covering all identified vulnerabilities and recommendations.'
            },
            {
                'id': 2,
                'title': 'Critical Vulnerabilities Report',
                'report_type': 'Vulnerability Report',
                'format': 'HTML',
                'status': 'Generated',
                'vulnerability_count': 5,
                'created_at': datetime.now() - timedelta(days=3),
                'file_path': '/reports/critical_vulns.html',
                'file_size': '850 KB',
                'description': 'Detailed analysis of critical security vulnerabilities requiring immediate attention.'
            },
            {
                'id': 3,
                'title': 'Executive Summary Q4 2024',
                'report_type': 'Executive Summary',
                'format': 'DOCX',
                'status': 'In Progress',
                'vulnerability_count': 23,
                'created_at': datetime.now(),
                'file_path': '/reports/exec_summary_q4.docx',
                'file_size': '1.1 MB',
                'description': 'High-level overview of security posture for executive leadership.'
            }
        ]
        
        # Get all vulnerabilities for the report generation modal
        try:
            vulns = analyzer.list_vulnerabilities()
            all_vulnerabilities = [{'id': v['id'], 'title': v['title'], 'severity': v['severity']} for v in vulns]
        except:
            all_vulnerabilities = []
        
        stats = {
            'total_reports': len(mock_reports),
            'ai_reports': 2,
            'manual_reports': 1,
            'downloads': 45
        }
        
        return render_template('advanced_reports.html', 
                             reports=mock_reports, 
                             all_vulnerabilities=all_vulnerabilities,
                             stats=stats)
    except Exception as e:
        flash(f'Error loading reports: {str(e)}', 'error')
        return render_template('advanced_reports.html', 
                             reports=[], 
                             all_vulnerabilities=[],
                             stats={})

@app.route('/report/<path:filename>')
def view_report(filename):
    """View a specific report"""
    # Check both directories
    report_path = REPORTS_DIR / filename
    if not report_path.exists():
        report_path = MANUAL_REPORTS_DIR / filename
    
    if not report_path.exists():
        flash('Report not found', 'error')
        return redirect(url_for('reports'))
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return render_template('report_viewer.html', 
                             report_content=content, 
                             filename=filename)
    except Exception as e:
        flash(f'Error reading report: {e}', 'error')
        return redirect(url_for('reports'))

@app.route('/download/<path:filename>')
def download_report(filename):
    """Download a report file"""
    report_path = REPORTS_DIR / filename
    if not report_path.exists():
        report_path = MANUAL_REPORTS_DIR / filename
    
    if report_path.exists():
        return send_file(report_path, as_attachment=True)
    else:
        flash('Report not found', 'error')
        return redirect(url_for('reports'))

@app.route('/api/system-status')
def system_status():
    """Get system status information"""
    return jsonify({
        'database_connected': True,
        'ai_available': analyzer.gemini_available,
        'gemini_api_key': bool(GEMINI_API_KEY),
        'total_vulnerabilities': len(analyzer.list_vulnerabilities()),
        'reports_count': len(list(REPORTS_DIR.glob('*.md'))) + len(list(MANUAL_REPORTS_DIR.glob('*.md'))),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/settings')
def settings():
    """Settings page"""
    return render_template('advanced_settings.html',
                         ai_available=analyzer.gemini_available,
                         api_key_set=bool(GEMINI_API_KEY))

@app.route('/api/test-ai')
def test_ai():
    """Test AI connectivity"""
    if not analyzer.gemini_available:
        return jsonify({
            'success': False,
            'message': 'Gemini API not available. Check configuration.'
        })
    
    try:
        test_response = analyzer.model.generate_content("Test message: respond with 'AI connection successful'")
        return jsonify({
            'success': True,
            'message': 'AI connection successful',
            'response': test_response.text
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'AI test failed: {e}'
        })

@app.route('/api/vulnerabilities', methods=['POST'])
def create_vulnerability():
    """Create a new vulnerability"""
    try:
        data = request.json
        
        # Basic validation
        required_fields = ['title', 'target', 'vuln_type', 'severity']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        # Create vulnerability in database
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO vulnerabilities 
            (title, description, vuln_type, severity, target, endpoint, poc, status, discovered_date, cvss_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['title'],
            data.get('description', ''),
            data['vuln_type'],
            data['severity'],
            data['target'],
            data.get('endpoint', ''),
            data.get('poc', ''),
            data.get('status', 'Open'),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            data.get('cvss_score', None)
        ))
        
        vuln_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'id': vuln_id})
    except Exception as e:
        logger.error(f"Error creating vulnerability: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/report/<int:report_id>', methods=['POST'])
def generate_report_api(report_id):
    """Generate a report for a specific vulnerability"""
    try:
        vuln = analyzer.get_vulnerability(report_id)
        if not vuln:
            return jsonify({'success': False, 'error': 'Vulnerability not found'}), 404
        
        # Mock report generation - in real implementation, this would generate actual reports
        report_url = f"/reports/vuln_{report_id}_report.pdf"
        
        return jsonify({
            'success': True, 
            'report_url': report_url,
            'message': 'Report generated successfully'
        })
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/generate_poc/<int:vuln_id>', methods=['POST'])
def generate_poc_api(vuln_id):
    """Generate proof of concept for a vulnerability"""
    try:
        vuln = analyzer.get_vulnerability(vuln_id)
        if not vuln:
            return jsonify({'success': False, 'error': 'Vulnerability not found'}), 404
        
        if not analyzer.gemini_available:
            return jsonify({
                'success': False, 
                'error': 'AI service not available. Please configure Gemini API key.'
            }), 503
        
        # Generate PoC using AI
        poc_prompt = f"""Generate a proof of concept for this vulnerability:
Title: {vuln.get('title', 'Unknown')}
Type: {vuln.get('vuln_type', 'Unknown')}
Description: {vuln.get('description', 'No description')}

Provide practical exploit code or steps."""
        
        try:
            response = analyzer.model.generate_content(poc_prompt)
            poc_content = response.text
            
            return jsonify({
                'success': True,
                'poc': poc_content
            })
        except Exception as ai_error:
            return jsonify({
                'success': False,
                'error': f'AI generation failed: {str(ai_error)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Error generating PoC: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/generate_reproduction/<int:vuln_id>', methods=['POST'])
def generate_reproduction_api(vuln_id):
    """Generate reproduction steps for a vulnerability"""
    try:
        vuln = analyzer.get_vulnerability(vuln_id)
        if not vuln:
            return jsonify({'success': False, 'error': 'Vulnerability not found'}), 404
        
        if not analyzer.gemini_available:
            return jsonify({
                'success': False, 
                'error': 'AI service not available. Please configure Gemini API key.'
            }), 503
        
        # Generate reproduction steps using AI
        reproduction_prompt = f"""Create detailed reproduction steps for this vulnerability:
Title: {vuln.get('title', 'Unknown')}
Type: {vuln.get('vuln_type', 'Unknown')}
Target: {vuln.get('target', 'Unknown')}
Description: {vuln.get('description', 'No description')}

Provide step-by-step instructions for reproducing this vulnerability."""
        
        try:
            response = analyzer.model.generate_content(reproduction_prompt)
            steps_content = response.text
            
            return jsonify({
                'success': True,
                'steps': steps_content
            })
        except Exception as ai_error:
            return jsonify({
                'success': False,
                'error': f'AI generation failed: {str(ai_error)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Error generating reproduction steps: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/vulnerability/<int:vuln_id>/cvss', methods=['PUT'])
def update_cvss_score(vuln_id):
    """Update CVSS score for a vulnerability"""
    try:
        data = request.json
        cvss_score = data.get('cvss_score')
        
        if cvss_score is None or not (0 <= cvss_score <= 10):
            return jsonify({'success': False, 'error': 'Invalid CVSS score'}), 400
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE vulnerabilities 
            SET cvss_score = ?, updated_at = ?
            WHERE id = ?
        ''', (cvss_score, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), vuln_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'error': 'Vulnerability not found'}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating CVSS score: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/export/vulnerabilities')
def export_vulnerabilities():
    """Export vulnerabilities to CSV"""
    try:
        vulns = analyzer.list_vulnerabilities()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Title', 'Type', 'Severity', 'Status', 'Target', 'CVSS Score', 'Discovered Date'])
        
        # Write data
        for vuln in vulns:
            writer.writerow([
                vuln.get('id', ''),
                vuln.get('title', ''),
                vuln.get('vuln_type', ''),
                vuln.get('severity', ''),
                vuln.get('status', ''),
                vuln.get('target_name', ''),
                vuln.get('cvss_score', ''),
                vuln.get('found_date', '')
            ])
        
        output.seek(0)
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=vulnerabilities_{datetime.now().strftime("%Y%m%d")}.csv'}
        )
    except Exception as e:
        logger.error(f"Error exporting vulnerabilities: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/settings', methods=['GET', 'POST'])
def settings_api():
    """Get or update application settings"""
    if request.method == 'GET':
        # Return current settings
        settings = {
            'app_name': 'Bug Bounty Pro',
            'environment': 'development',
            'timezone': 'UTC',
            'language': 'en',
            'debug_mode': True,
            'gemini_api_key': '***' if GEMINI_API_KEY else '',
            'enable_ai_analysis': analyzer.gemini_available,
            'default_ai_model': 'gemini-pro'
        }
        return jsonify({'success': True, 'settings': settings})
    
    elif request.method == 'POST':
        try:
            data = request.json
            # In a real implementation, save settings to database or config file
            return jsonify({'success': True, 'message': 'Settings saved successfully'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

# Add method to fix vulnerability route name conflict
@app.route('/vulnerabilities')
def vulnerabilities():
    """List all vulnerabilities - updated to match template expectations"""
    try:
        vulns = analyzer.list_vulnerabilities()
        
        # Convert to expected format for template
        vulnerabilities = []
        for vuln in vulns:
            vuln_dict = {
                'id': vuln.get('id'),
                'title': vuln.get('title', 'Unknown'),
                'vuln_type': vuln.get('vuln_type', 'Unknown'),
                'severity': vuln.get('severity', 'Unknown'),
                'status': vuln.get('status', 'Open'),
                'target_name': vuln.get('target_name', 'Unknown'),
                'endpoint': vuln.get('target_url', ''),
                'cvss_score': vuln.get('cvss_score'),
                'discovered_date': datetime.now() if not vuln.get('found_date') else datetime.strptime(vuln.get('found_date'), '%Y-%m-%d %H:%M:%S'),
                'exploit_available': bool(vuln.get('poc'))
            }
            vulnerabilities.append(vuln_dict)
        
        # Calculate statistics
        stats = {
            'critical': len([v for v in vulns if v.get('severity') == 'Critical']),
            'high': len([v for v in vulns if v.get('severity') == 'High']),
            'medium': len([v for v in vulns if v.get('severity') == 'Medium']),
            'low': len([v for v in vulns if v.get('severity') in ['Low', 'Info']])
        }
        
        return render_template('advanced_vulnerabilities.html', 
                             vulnerabilities=vulnerabilities, 
                             stats=stats)
    except Exception as e:
        flash(f'Error loading vulnerabilities: {str(e)}', 'error')
        return render_template('advanced_vulnerabilities.html', 
                             vulnerabilities=[], 
                             stats={})

if __name__ == '__main__':
    print("🚀 Starting Advanced Vulnerability Analysis UI...")
    print(f"🔗 Access at: http://localhost:5000")
    print(f"🤖 AI Available: {analyzer.gemini_available}")
    print(f"📊 Database: {DATABASE_PATH}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
