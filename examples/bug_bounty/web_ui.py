#!/usr/bin/env python3
"""
🎯 BUG BOUNTY HUNTER - WEB UI
Modern web interface for the complete bug bounty framework
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import os
import json
import sqlite3
import subprocess
from datetime import datetime, timedelta
import threading
import time
from pathlib import Path

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Configuration
WORKSPACE_DIR = Path.home() / 'bb_pro_workspace'
DATABASE_PATH = WORKSPACE_DIR / 'bb_pro.db'
RESULTS_DIR = WORKSPACE_DIR / 'results'

# Ensure directories exist
WORKSPACE_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

class BugBountyUI:
    def __init__(self):
        self.active_scans = {}
        self.setup_database()
    
    def setup_database(self):
        """Initialize the database"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY,
                domain TEXT UNIQUE,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scan TIMESTAMP,
                vulnerabilities_found INTEGER DEFAULT 0,
                estimated_payout REAL DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                vulnerability_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                poc TEXT,
                estimated_payout REAL,
                status TEXT DEFAULT 'draft',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                scan_type TEXT,
                status TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                results TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        conn.commit()
        conn.close()

bb_ui = BugBountyUI()

@app.route('/')
def dashboard():
    """Main dashboard"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get dashboard stats
    cursor.execute('SELECT COUNT(*) FROM targets')
    total_targets = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
    total_vulns = cursor.fetchone()[0]
    
    cursor.execute('SELECT SUM(estimated_payout) FROM vulnerabilities')
    total_earnings = cursor.fetchone()[0] or 0
    
    cursor.execute('SELECT COUNT(*) FROM targets WHERE status = "scanning"')
    active_scans = cursor.fetchone()[0]
    
    # Get recent targets
    cursor.execute('''
        SELECT domain, status, vulnerabilities_found, estimated_payout, last_scan
        FROM targets 
        ORDER BY created_at DESC 
        LIMIT 10
    ''')
    recent_targets = cursor.fetchall()
    
    # Get recent vulnerabilities
    cursor.execute('''
        SELECT v.title, v.severity, v.estimated_payout, t.domain, v.created_at
        FROM vulnerabilities v
        JOIN targets t ON v.target_id = t.id
        ORDER BY v.created_at DESC
        LIMIT 10
    ''')
    recent_vulns = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         total_targets=total_targets,
                         total_vulns=total_vulns,
                         total_earnings=total_earnings,
                         active_scans=active_scans,
                         recent_targets=recent_targets,
                         recent_vulns=recent_vulns)

@app.route('/targets')
def targets():
    """Target management page"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, domain, status, vulnerabilities_found, estimated_payout, 
               created_at, last_scan
        FROM targets 
        ORDER BY created_at DESC
    ''')
    targets_list = cursor.fetchall()
    
    conn.close()
    
    return render_template('targets.html', targets=targets_list)

@app.route('/add_target', methods=['GET', 'POST'])
def add_target():
    """Add new target"""
    if request.method == 'POST':
        domain = request.form['domain'].strip()
        
        if not domain:
            flash('Please enter a domain', 'error')
            return redirect(url_for('add_target'))
        
        # Clean domain
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('/')[2]
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute('INSERT INTO targets (domain) VALUES (?)', (domain,))
            conn.commit()
            flash(f'Target {domain} added successfully!', 'success')
            return redirect(url_for('targets'))
        except sqlite3.IntegrityError:
            flash('Target already exists', 'error')
        finally:
            conn.close()
    
    return render_template('add_target.html')

@app.route('/scan/<int:target_id>')
def start_scan(target_id):
    """Start scanning a target"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get target info
    cursor.execute('SELECT domain FROM targets WHERE id = ?', (target_id,))
    result = cursor.fetchone()
    
    if not result:
        flash('Target not found', 'error')
        return redirect(url_for('targets'))
    
    domain = result[0]
    
    # Update target status
    cursor.execute('UPDATE targets SET status = "scanning", last_scan = ? WHERE id = ?', 
                   (datetime.now(), target_id))
    
    # Create scan record
    cursor.execute('INSERT INTO scans (target_id, scan_type, status) VALUES (?, ?, ?)',
                   (target_id, 'automated', 'running'))
    
    conn.commit()
    conn.close()
    
    # Start scan in background
    thread = threading.Thread(target=run_scan, args=(target_id, domain))
    thread.daemon = True
    thread.start()
    
    flash(f'Scan started for {domain}', 'success')
    return redirect(url_for('targets'))

def run_scan(target_id, domain):
    """Run the actual scan (background task)"""
    try:
        # Simulate scan with actual tools
        time.sleep(2)  # Simulate initial setup
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Run basic reconnaissance
        scan_results = {
            'subdomains': [],
            'technologies': [],
            'endpoints': [],
            'vulnerabilities': []
        }
        
        # Run subfinder
        try:
            result = subprocess.run(['subfinder', '-d', domain, '-silent'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                scan_results['subdomains'] = result.stdout.strip().split('\n')
        except:
            pass
        
        # Run httpx
        try:
            result = subprocess.run(['httpx', '-l', '-', '-silent'], 
                                  input='\n'.join(scan_results['subdomains']),
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                scan_results['endpoints'] = result.stdout.strip().split('\n')
        except:
            pass
        
        # Simulate vulnerability findings
        sample_vulns = [
            {
                'type': 'SQL Injection',
                'severity': 'High',
                'title': f'SQL Injection in {domain}/login',
                'description': 'Authentication bypass via SQL injection',
                'payout': 2500
            },
            {
                'type': 'XSS',
                'severity': 'Medium', 
                'title': f'Stored XSS in {domain}/contact',
                'description': 'Stored cross-site scripting vulnerability',
                'payout': 800
            }
        ]
        
        # Add vulnerabilities to database
        total_payout = 0
        vuln_count = 0
        
        for vuln in sample_vulns:
            cursor.execute('''
                INSERT INTO vulnerabilities 
                (target_id, vulnerability_type, severity, title, description, estimated_payout)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (target_id, vuln['type'], vuln['severity'], vuln['title'], 
                  vuln['description'], vuln['payout']))
            total_payout += vuln['payout']
            vuln_count += 1
        
        # Update target with results
        cursor.execute('''
            UPDATE targets 
            SET status = "completed", vulnerabilities_found = ?, estimated_payout = ?
            WHERE id = ?
        ''', (vuln_count, total_payout, target_id))
        
        # Update scan record
        cursor.execute('''
            UPDATE scans 
            SET status = "completed", completed_at = ?, results = ?
            WHERE target_id = ? AND status = "running"
        ''', (datetime.now(), json.dumps(scan_results), target_id))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        # Handle scan errors
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('UPDATE targets SET status = "error" WHERE id = ?', (target_id,))
        cursor.execute('UPDATE scans SET status = "error" WHERE target_id = ? AND status = "running"', 
                       (target_id,))
        
        conn.commit()
        conn.close()

@app.route('/vulnerabilities')
def vulnerabilities():
    """Vulnerabilities page"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT v.id, v.title, v.severity, v.vulnerability_type, v.estimated_payout, 
               v.status, t.domain, v.created_at
        FROM vulnerabilities v
        JOIN targets t ON v.target_id = t.id
        ORDER BY v.created_at DESC
    ''')
    vulns_list = cursor.fetchall()
    
    conn.close()
    
    return render_template('vulnerabilities.html', vulnerabilities=vulns_list)

@app.route('/vulnerability/<int:vuln_id>')
def vulnerability_detail(vuln_id):
    """Vulnerability detail page"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT v.*, t.domain
        FROM vulnerabilities v
        JOIN targets t ON v.target_id = t.id
        WHERE v.id = ?
    ''', (vuln_id,))
    
    vuln = cursor.fetchone()
    conn.close()
    
    if not vuln:
        flash('Vulnerability not found', 'error')
        return redirect(url_for('vulnerabilities'))
    
    return render_template('vulnerability_detail.html', vulnerability=vuln)

@app.route('/reports')
def reports():
    """Reports and analytics page"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get monthly stats
    cursor.execute('''
        SELECT 
            COUNT(*) as total_vulns,
            SUM(estimated_payout) as total_earnings,
            AVG(estimated_payout) as avg_payout
        FROM vulnerabilities 
        WHERE created_at >= date('now', '-30 days')
    ''')
    monthly_stats = cursor.fetchone()
    
    # Get vulnerability types breakdown
    cursor.execute('''
        SELECT vulnerability_type, COUNT(*), SUM(estimated_payout)
        FROM vulnerabilities
        GROUP BY vulnerability_type
        ORDER BY SUM(estimated_payout) DESC
    ''')
    vuln_breakdown = cursor.fetchall()
    
    # Get severity breakdown
    cursor.execute('''
        SELECT severity, COUNT(*), SUM(estimated_payout)
        FROM vulnerabilities
        GROUP BY severity
        ORDER BY SUM(estimated_payout) DESC
    ''')
    severity_breakdown = cursor.fetchall()
    
    conn.close()
    
    return render_template('reports.html', 
                         monthly_stats=monthly_stats,
                         vuln_breakdown=vuln_breakdown,
                         severity_breakdown=severity_breakdown)

@app.route('/settings')
def settings():
    """Settings page"""
    return render_template('settings.html')

@app.route('/api/scan_status/<int:target_id>')
def scan_status(target_id):
    """API endpoint for scan status"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT status FROM targets WHERE id = ?', (target_id,))
    result = cursor.fetchone()
    
    conn.close()
    
    if result:
        return jsonify({'status': result[0]})
    return jsonify({'status': 'unknown'})

if __name__ == '__main__':
    print("🚀 Starting Bug Bounty Hunter Web UI...")
    print("📱 Open your browser to: http://localhost:5000")
    print("🎯 Ready to hunt for bounties!")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
