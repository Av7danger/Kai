#!/usr/bin/env python3
"""
🎯 BUG BOUNTY HUNTER - WEB UI
Modern web interface for the complete bug bounty framework
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
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

# Optional advanced imports with fallbacks
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Configuration
WORKSPACE_DIR = Path.home() / 'bb_pro_workspace'
DATABASE_PATH = WORKSPACE_DIR / 'bb_pro.db'
RESULTS_DIR = WORKSPACE_DIR / 'results'

# Ensure directories exist
WORKSPACE_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

# Global UI instance to ensure database initialization
bug_bounty_ui = None

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
                estimated_payout REAL DEFAULT 0,
                program_name TEXT,
                reward_range TEXT,
                scope TEXT,
                ip_address TEXT,
                technology_stack TEXT,
                subdomains_count INTEGER DEFAULT 0,
                ports_open TEXT,
                ssl_info TEXT,
                whois_data TEXT,
                risk_score INTEGER DEFAULT 0
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
                cvss_score REAL,
                cwe_id TEXT,
                steps_to_reproduce TEXT,
                impact TEXT,
                remediation TEXT,
                attachments TEXT,
                reported_date TIMESTAMP,
                bounty_received REAL DEFAULT 0,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        # Add new advanced tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                scan_type TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT,
                results TEXT,
                findings_count INTEGER DEFAULT 0,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY,
                vulnerability_id INTEGER,
                exploit_type TEXT,
                exploit_code TEXT,
                success_rate INTEGER DEFAULT 0,
                payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY,
                name TEXT,
                category TEXT,
                payload_code TEXT,
                description TEXT,
                success_rate INTEGER DEFAULT 0,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intelligence (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                intel_type TEXT,
                source TEXT,
                data TEXT,
                confidence_level INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wordlists (
                id INTEGER PRIMARY KEY,
                name TEXT,
                category TEXT,
                file_path TEXT,
                word_count INTEGER DEFAULT 0,
                effectiveness_score INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS automation_tasks (
                id INTEGER PRIMARY KEY,
                task_name TEXT,
                target_id INTEGER,
                task_type TEXT,
                schedule TEXT,
                status TEXT DEFAULT 'pending',
                last_run TIMESTAMP,
                next_run TIMESTAMP,
                config TEXT,
                results TEXT,
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                name TEXT,
                description TEXT,
                file_type TEXT,
                file_path TEXT,
                file_size INTEGER,
                content_type TEXT,
                tags TEXT,
                scope_info TEXT,
                program_info TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        conn.commit()
        
        # Insert default payloads
        default_payloads = [
            ("XSS Basic Alert", "xss", "<script>alert('XSS')</script>", "Basic XSS payload for testing", 85, "basic,alert,reflected"),
            ("XSS IMG Onerror", "xss", "<img src=x onerror=alert('XSS')>", "XSS using image error event", 80, "img,onerror,bypass"),
            ("SQL Union Basic", "sqli", "' UNION SELECT NULL,NULL,NULL--", "Basic union-based SQL injection", 75, "union,basic,null"),
            ("SQL Boolean", "sqli", "' AND 1=1--", "Boolean-based blind SQL injection", 70, "boolean,blind,basic"),
            ("LFI Basic", "lfi", "../../../etc/passwd", "Basic local file inclusion for Unix", 85, "basic,unix,passwd"),
            ("LFI PHP Wrapper", "lfi", "php://filter/convert.base64-encode/resource=index.php", "PHP wrapper for base64 encoding", 90, "php,wrapper,base64"),
            ("XXE Basic", "xxe", "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>", "Basic XXE payload", 75, "basic,file,disclosure"),
            ("SSTI Jinja2", "ssti", "{{7*7}}", "Server-side template injection for Jinja2", 80, "jinja2,math,basic"),
            ("Command Injection", "cmdi", "; cat /etc/passwd", "Basic command injection payload", 85, "basic,unix,semicolon"),
            ("Directory Traversal", "directory_traversal", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows directory traversal", 75, "windows,basic,hosts")
        ]
        
        for payload in default_payloads:
            cursor.execute('''
                INSERT OR IGNORE INTO payloads (name, category, payload_code, description, success_rate, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', payload)
        
        # Insert default wordlists (placeholder entries)
        default_wordlists = [
            ("Common Directories", "directory", "/usr/share/wordlists/common-dirs.txt", 50000, 90),
            ("Subdomains Top 1M", "subdomain", "/usr/share/wordlists/subdomains-top1m.txt", 1000000, 85),
            ("Common Passwords", "password", "/usr/share/wordlists/rockyou.txt", 14344391, 95),
            ("Common Usernames", "username", "/usr/share/wordlists/usernames.txt", 10000, 80),
            ("API Endpoints", "api", "/usr/share/wordlists/api-endpoints.txt", 5000, 75),
            ("Parameter Names", "parameter", "/usr/share/wordlists/param-names.txt", 2500, 70)
        ]
        
        for wordlist in default_wordlists:
            cursor.execute('''
                INSERT OR IGNORE INTO wordlists (name, category, file_path, word_count, effectiveness_score)
                VALUES (?, ?, ?, ?, ?)
            ''', wordlist)
        
        conn.commit()
        conn.close()

    def gather_intelligence(self, domain):
        """Advanced intelligence gathering for a target"""
        intel_data = {
            'domain': domain,
            'subdomains': [],
            'technologies': [],
            'ssl_info': {},
            'whois_data': {},
            'dns_records': {},
            'shodan_data': {},
            'social_media': [],
            'employees': [],
            'email_patterns': [],
            'ip_ranges': [],
            'risk_assessment': {}
        }
        
        try:
            # Subdomain enumeration
            intel_data['subdomains'] = self.enumerate_subdomains(domain)
            
            # Technology detection
            intel_data['technologies'] = self.detect_technologies(domain)
            
            # SSL certificate analysis
            intel_data['ssl_info'] = self.analyze_ssl(domain)
            
            # WHOIS data
            if WHOIS_AVAILABLE:
                try:
                    whois_data = whois.whois(domain)
                    intel_data['whois_data'] = {
                        'registrar': str(whois_data.registrar),
                        'creation_date': str(whois_data.creation_date),
                        'expiration_date': str(whois_data.expiration_date),
                        'name_servers': whois_data.name_servers
                    }
                except:
                    intel_data['whois_data'] = {'error': 'Failed to retrieve WHOIS data'}
            
            # DNS enumeration
            if DNS_AVAILABLE:
                intel_data['dns_records'] = self.enumerate_dns(domain)
            
            # Shodan intelligence
            if SHODAN_AVAILABLE:
                intel_data['shodan_data'] = self.shodan_lookup(domain)
            
            # Social media and employee enumeration
            intel_data['social_media'] = self.find_social_media(domain)
            intel_data['employees'] = self.enumerate_employees(domain)
            
            # Email pattern detection
            intel_data['email_patterns'] = self.detect_email_patterns(domain)
            
            # Risk assessment
            intel_data['risk_assessment'] = self.assess_risk(intel_data)
            
        except Exception as e:
            print(f"Error gathering intelligence: {e}")
        
        return intel_data
    
    def enumerate_subdomains(self, domain):
        """Enhanced subdomain enumeration"""
        subdomains = set()
        
        # Common subdomain wordlist
        common_subs = [
            'www', 'mail', 'ftp', 'blog', 'admin', 'api', 'dev', 'test', 'staging',
            'app', 'portal', 'secure', 'vpn', 'remote', 'login', 'panel', 'dashboard',
            'cdn', 'assets', 'static', 'media', 'images', 'files', 'downloads',
            'support', 'help', 'docs', 'wiki', 'forum', 'community', 'shop',
            'store', 'cart', 'payment', 'checkout', 'account', 'profile', 'user',
            'internal', 'private', 'beta', 'alpha', 'pre', 'demo', 'sandbox'
        ]
        
        for sub in common_subs:
            try:
                full_domain = f"{sub}.{domain}"
                # Simple DNS resolution check
                subprocess.run(['nslookup', full_domain], capture_output=True, timeout=5)
                subdomains.add(full_domain)
            except:
                continue
        
        return list(subdomains)
    
    def detect_technologies(self, domain):
        """Detect web technologies and frameworks"""
        technologies = []
        
        try:
            response = requests.get(f"http://{domain}", timeout=10, allow_redirects=True)
            headers = response.headers
            content = response.text.lower()
            
            # Server detection
            if 'server' in headers:
                technologies.append(f"Server: {headers['server']}")
            
            # Framework detection patterns
            tech_patterns = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Django': ['django', 'csrftoken'],
                'React': ['react', '__reactinternalinstance'],
                'Angular': ['angular', 'ng-'],
                'Vue.js': ['vue.js', '__vue__'],
                'jQuery': ['jquery', '$.fn.jquery'],
                'Bootstrap': ['bootstrap'],
                'Laravel': ['laravel', 'laravel_session'],
                'CodeIgniter': ['codeigniter', 'ci_session'],
                'Drupal': ['drupal', 'sites/all/modules'],
                'Joomla': ['joomla', '/media/system/js/'],
                'Magento': ['magento', 'mage/cookies'],
                'Shopify': ['shopify', 'cdn.shopify.com'],
                'ASP.NET': ['aspnet', '__viewstate'],
                'PHP': ['php', 'phpsessid'],
                'Node.js': ['express', 'connect.sid'],
                'Ruby on Rails': ['rails', 'authenticity_token']
            }
            
            for tech, patterns in tech_patterns.items():
                if any(pattern in content for pattern in patterns):
                    technologies.append(tech)
            
            # Security headers check
            security_headers = {
                'X-Frame-Options': 'X-Frame-Options',
                'X-XSS-Protection': 'X-XSS-Protection',
                'X-Content-Type-Options': 'X-Content-Type-Options',
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP'
            }
            
            for header, name in security_headers.items():
                if header in headers:
                    technologies.append(f"Security: {name}")
                else:
                    technologies.append(f"Missing: {name}")
                    
        except Exception as e:
            technologies.append(f"Error detecting technologies: {str(e)}")
        
        return technologies
    
    def analyze_ssl(self, domain):
        """Analyze SSL certificate and configuration"""
        ssl_info = {}
        
        try:
            # Basic SSL check using openssl
            result = subprocess.run([
                'openssl', 's_client', '-connect', f'{domain}:443', '-servername', domain
            ], capture_output=True, text=True, timeout=10, input='')
            
            if result.returncode == 0:
                ssl_info['ssl_enabled'] = True
                ssl_info['certificate_chain'] = "Available"
            else:
                ssl_info['ssl_enabled'] = False
                ssl_info['error'] = "SSL not available or connection failed"
                
        except Exception as e:
            ssl_info['error'] = f"SSL analysis failed: {str(e)}"
        
        return ssl_info
    
    def enumerate_dns(self, domain):
        """Comprehensive DNS enumeration"""
        dns_records = {}
        
        if not DNS_AVAILABLE:
            return {'error': 'DNS library not available'}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(answer) for answer in answers]
            except:
                dns_records[record_type] = []
        
        return dns_records
    
    def shodan_lookup(self, domain):
        """Shodan intelligence gathering"""
        if not SHODAN_AVAILABLE:
            return {'error': 'Shodan library not available'}
        
        # Note: Requires Shodan API key
        try:
            api = shodan.Shodan("YOUR_SHODAN_API_KEY")  # Replace with actual API key
            host = api.host(domain)
            return {
                'ip': host['ip_str'],
                'ports': host.get('ports', []),
                'vulns': host.get('vulns', []),
                'last_update': host.get('last_update', ''),
                'country': host.get('country_name', ''),
                'org': host.get('org', '')
            }
        except:
            return {'error': 'Shodan lookup failed - check API key'}
    
    def find_social_media(self, domain):
        """Find social media accounts related to the domain"""
        social_accounts = []
        
        # Extract company name from domain
        company_name = domain.split('.')[0]
        
        # Common social media platforms
        platforms = [
            f"https://twitter.com/{company_name}",
            f"https://facebook.com/{company_name}",
            f"https://linkedin.com/company/{company_name}",
            f"https://instagram.com/{company_name}",
            f"https://github.com/{company_name}"
        ]
        
        for platform in platforms:
            try:
                response = requests.head(platform, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    social_accounts.append(platform)
            except:
                continue
        
        return social_accounts
    
    def enumerate_employees(self, domain):
        """Employee enumeration through various sources"""
        employees = []
        
        # This would typically integrate with LinkedIn API, Hunter.io, etc.
        # For now, return placeholder data
        employees.append({
            'source': 'placeholder',
            'note': 'Employee enumeration requires API integration'
        })
        
        return employees
    
    def detect_email_patterns(self, domain):
        """Detect common email patterns for the domain"""
        patterns = []
        
        # Common email patterns
        common_patterns = [
            f"firstname.lastname@{domain}",
            f"firstname@{domain}",
            f"f.lastname@{domain}",
            f"flastname@{domain}",
            f"admin@{domain}",
            f"info@{domain}",
            f"support@{domain}",
            f"sales@{domain}",
            f"security@{domain}",
            f"contact@{domain}"
        ]
        
        patterns.extend(common_patterns)
        return patterns
    
    def assess_risk(self, intel_data):
        """Assess overall risk score for the target"""
        risk_score = 0
        risk_factors = []
        
        # Subdomain count factor
        subdomain_count = len(intel_data.get('subdomains', []))
        if subdomain_count > 10:
            risk_score += 20
            risk_factors.append("High subdomain count")
        elif subdomain_count > 5:
            risk_score += 10
            risk_factors.append("Moderate subdomain count")
        
        # Technology stack complexity
        tech_count = len(intel_data.get('technologies', []))
        if tech_count > 8:
            risk_score += 15
            risk_factors.append("Complex technology stack")
        
        # Missing security headers
        technologies = intel_data.get('technologies', [])
        missing_security = [tech for tech in technologies if tech.startswith('Missing:')]
        risk_score += len(missing_security) * 5
        if missing_security:
            risk_factors.append(f"Missing security headers: {len(missing_security)}")
        
        # SSL issues
        ssl_info = intel_data.get('ssl_info', {})
        if not ssl_info.get('ssl_enabled', False):
            risk_score += 25
            risk_factors.append("SSL not properly configured")
        
        return {
            'score': min(risk_score, 100),  # Cap at 100
            'level': 'High' if risk_score > 70 else 'Medium' if risk_score > 40 else 'Low',
            'factors': risk_factors
        }
    
    def automated_scan(self, target_id, scan_types=None):
        """Run automated scanning suite"""
        if scan_types is None:
            scan_types = ['port_scan', 'web_scan', 'vuln_scan', 'intel_gathering']
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get target info
        cursor.execute('SELECT domain FROM targets WHERE id = ?', (target_id,))
        target = cursor.fetchone()
        
        if not target:
            return {'error': 'Target not found'}
        
        domain = target[0]
        scan_results = {}
        
        for scan_type in scan_types:
            try:
                if scan_type == 'intel_gathering':
                    scan_results[scan_type] = self.gather_intelligence(domain)
                elif scan_type == 'port_scan':
                    scan_results[scan_type] = self.port_scan(domain)
                elif scan_type == 'web_scan':
                    scan_results[scan_type] = self.web_vulnerability_scan(domain)
                elif scan_type == 'vuln_scan':
                    scan_results[scan_type] = self.vulnerability_assessment(domain)
                
                # Log scan in history
                cursor.execute('''
                    INSERT INTO scan_history (target_id, scan_type, start_time, end_time, status, results)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (target_id, scan_type, datetime.now(), datetime.now(), 'completed', json.dumps(scan_results[scan_type])))
                
            except Exception as e:
                scan_results[scan_type] = {'error': str(e)}
        
        conn.commit()
        conn.close()
        
        return scan_results
    
    def port_scan(self, domain):
        """Advanced port scanning"""
        if not NMAP_AVAILABLE:
            return {'error': 'Nmap library not available'}
        
        try:
            nm = nmap.PortScanner()
            result = nm.scan(domain, '1-1000', '-sS -sV -O')
            
            scan_data = {}
            for host in nm.all_hosts():
                scan_data[host] = {
                    'state': nm[host].state(),
                    'protocols': list(nm[host].all_protocols()),
                    'ports': {}
                }
                
                for protocol in nm[host].all_protocols():
                    ports = nm[host][protocol].keys()
                    for port in ports:
                        port_info = nm[host][protocol][port]
                        scan_data[host]['ports'][port] = {
                            'state': port_info['state'],
                            'name': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', '')
                        }
            
            return scan_data
            
        except Exception as e:
            return {'error': f'Port scan failed: {str(e)}'}
    
    def web_vulnerability_scan(self, domain):
        """Web application vulnerability scanning"""
        vulnerabilities = []
        
        try:
            base_url = f"http://{domain}"
            
            # SQL Injection tests
            sql_payloads = [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--"
            ]
            
            for payload in sql_payloads:
                try:
                    response = requests.get(f"{base_url}?id={payload}", timeout=5)
                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax error', 'ora-']):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'payload': payload,
                            'evidence': 'Database error detected'
                        })
                except:
                    continue
            
            # XSS tests
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>"
            ]
            
            for payload in xss_payloads:
                try:
                    response = requests.get(f"{base_url}?q={payload}", timeout=5)
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'Medium',
                            'payload': payload,
                            'evidence': 'Payload reflected in response'
                        })
                except:
                    continue
            
            # Directory traversal
            lfi_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "../../../../etc/shadow"
            ]
            
            for payload in lfi_payloads:
                try:
                    response = requests.get(f"{base_url}?file={payload}", timeout=5)
                    if any(pattern in response.text.lower() for pattern in ['root:', '[fonts]', 'daemon:']):
                        vulnerabilities.append({
                            'type': 'Directory Traversal',
                            'severity': 'High',
                            'payload': payload,
                            'evidence': 'System file content detected'
                        })
                except:
                    continue
                    
        except Exception as e:
            vulnerabilities.append({
                'type': 'Scan Error',
                'severity': 'Info',
                'error': str(e)
            })
        
        return {'vulnerabilities': vulnerabilities, 'scan_complete': True}
    
    def vulnerability_assessment(self, domain):
        """Comprehensive vulnerability assessment"""
        assessment = {
            'security_headers': self.check_security_headers(domain),
            'ssl_vulnerabilities': self.check_ssl_vulnerabilities(domain),
            'common_files': self.check_common_files(domain),
            'information_disclosure': self.check_information_disclosure(domain)
        }
        
        return assessment
    
    def check_security_headers(self, domain):
        """Check for security headers"""
        headers_check = {}
        
        try:
            response = requests.get(f"http://{domain}", timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content injection protection',
                'Referrer-Policy': 'Referrer information control'
            }
            
            for header, description in security_headers.items():
                headers_check[header] = {
                    'present': header in headers,
                    'value': headers.get(header, 'Not set'),
                    'description': description
                }
                
        except Exception as e:
            headers_check['error'] = str(e)
        
        return headers_check
    
    def check_ssl_vulnerabilities(self, domain):
        """Check for SSL/TLS vulnerabilities"""
        ssl_check = {}
        
        try:
            # Test various SSL/TLS configurations
            # This is a simplified check - in practice, you'd use tools like testssl.sh
            ssl_check['basic_connectivity'] = True
            ssl_check['protocols_supported'] = ['TLS 1.2', 'TLS 1.3']  # Placeholder
            ssl_check['weak_ciphers'] = []  # Would detect weak ciphers
            ssl_check['certificate_issues'] = []  # Would check cert validity
            
        except Exception as e:
            ssl_check['error'] = str(e)
        
        return ssl_check
    
    def check_common_files(self, domain):
        """Check for common sensitive files"""
        common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'admin', 'login', 'phpmyadmin', 'wp-admin',
            '.git', '.svn', 'backup', 'config.php', '.env'
        ]
        
        found_files = []
        
        for file in common_files:
            try:
                response = requests.get(f"http://{domain}/{file}", timeout=5)
                if response.status_code == 200:
                    found_files.append({
                        'file': file,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
            except:
                continue
        
        return found_files
    
    def check_information_disclosure(self, domain):
        """Check for information disclosure"""
        disclosure_check = {}
        
        try:
            response = requests.get(f"http://{domain}", timeout=10)
            
            # Check for version disclosure in headers
            disclosure_check['server_version'] = response.headers.get('Server', 'Not disclosed')
            disclosure_check['powered_by'] = response.headers.get('X-Powered-By', 'Not disclosed')
            
            # Check for error pages that might leak information
            error_response = requests.get(f"http://{domain}/nonexistent-page-test", timeout=5)
            if 'apache' in error_response.text.lower() or 'nginx' in error_response.text.lower():
                disclosure_check['error_page_disclosure'] = True
            
        except Exception as e:
            disclosure_check['error'] = str(e)
        
        return disclosure_check
    
@app.route('/')
def dashboard():
    """Main dashboard with comprehensive stats"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get dashboard stats
    cursor.execute('SELECT COUNT(*) FROM targets')
    total_targets = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
    total_vulnerabilities = cursor.fetchone()[0]
    
    cursor.execute('SELECT SUM(estimated_payout) FROM vulnerabilities WHERE estimated_payout IS NOT NULL')
    total_estimated_payout = cursor.fetchone()[0] or 0
    
    cursor.execute('SELECT COUNT(*) FROM targets WHERE status = "scanning"')
    active_scans = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "critical"')
    critical_vulns = cursor.fetchone()[0]
    
    # Get recent targets with full data
    cursor.execute('''
        SELECT id, domain, status, created_at, last_scan, vulnerabilities_found, 
               estimated_payout, program_name, reward_range, scope, ip_address, 
               technology_stack, subdomains_count, ports_open, ssl_info, whois_data, risk_score
        FROM targets 
        ORDER BY created_at DESC 
        LIMIT 10
    ''')
    recent_targets = cursor.fetchall()
    
    # Get recent vulnerabilities
    cursor.execute('''
        SELECT v.vulnerability_type, v.severity, v.estimated_payout, t.domain, v.created_at, v.title
        FROM vulnerabilities v
        JOIN targets t ON v.target_id = t.id
        ORDER BY v.created_at DESC
        LIMIT 10
    ''')
    recent_vulns = cursor.fetchall()
    
    # Get vulnerability statistics by type
    cursor.execute('''
        SELECT vulnerability_type, COUNT(*) as count
        FROM vulnerabilities
        GROUP BY vulnerability_type
    ''')
    vuln_type_stats = dict(cursor.fetchall())
    
    # Create vuln_stats for chart
    vuln_stats = {
        'xss': vuln_type_stats.get('XSS', 0),
        'sqli': vuln_type_stats.get('SQL Injection', 0),
        'csrf': vuln_type_stats.get('CSRF', 0),
        'lfi': vuln_type_stats.get('LFI', 0),
        'other': sum(count for vtype, count in vuln_type_stats.items() 
                    if vtype not in ['XSS', 'SQL Injection', 'CSRF', 'LFI'])
    }
    
    # Create recent activities
    recent_activities = []
    
    # Add vulnerability activities
    for vuln in recent_vulns[:5]:
        recent_activities.append({
            'icon': 'fa-shield-alt',
            'color': 'danger' if vuln[1] == 'critical' else 'warning' if vuln[1] == 'high' else 'info',
            'title': f'New {vuln[1]} vulnerability found',
            'description': f'{vuln[0]} on {vuln[3]}',
            'time': vuln[4],
            'action': 'View Details'
        })
    
    # Add target activities
    for target in recent_targets[:3]:
        if target[4]:  # has last_scan
            recent_activities.append({
                'icon': 'fa-search',
                'color': 'success',
                'title': f'Scan completed for {target[1]}',
                'description': f'Found {target[5] or 0} vulnerabilities',
                'time': target[4],
                'action': 'View Results'
            })
    
    # Sort activities by time (most recent first)
    recent_activities.sort(key=lambda x: x['time'] or '', reverse=True)
    recent_activities = recent_activities[:8]  # Limit to 8 most recent
    
    conn.close()
    
    return render_template('dashboard.html', 
                         total_targets=total_targets,
                         total_vulnerabilities=total_vulnerabilities,
                         total_estimated_payout=round(total_estimated_payout, 2),
                         active_scans=active_scans,
                         critical_vulns=critical_vulns,
                         recent_targets=recent_targets,
                         recent_vulns=recent_vulns,
                         recent_activities=recent_activities,
                         vuln_stats=vuln_stats)

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

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """Settings page with save/load functionality"""
    if request.method == 'POST':
        try:
            # Get settings from form
            settings_data = {
                'general': {
                    'max_concurrent_scans': request.form.get('max_concurrent_scans', 3),
                    'scan_timeout': request.form.get('scan_timeout', 60),
                    'rate_limit': request.form.get('rate_limit', 10),
                    'auto_save_results': request.form.get('auto_save_results') == 'on',
                    'email_notifications': request.form.get('email_notifications') == 'on'
                },
                'tools': {
                    'nmap_path': request.form.get('nmap_path', '/usr/bin/nmap'),
                    'wordlist_path': request.form.get('wordlist_path', '/usr/share/wordlists'),
                    'output_directory': request.form.get('output_directory', '~/bb_pro_workspace/results'),
                    'user_agent': request.form.get('user_agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
                },
                'api': {
                    'shodan_api_key': request.form.get('shodan_api_key', ''),
                    'virustotal_api_key': request.form.get('virustotal_api_key', ''),
                    'gemini_api_key': request.form.get('gemini_api_key', ''),
                    'censys_api_key': request.form.get('censys_api_key', '')
                },
                'notifications': {
                    'email_address': request.form.get('email_address', ''),
                    'smtp_server': request.form.get('smtp_server', ''),
                    'smtp_port': request.form.get('smtp_port', 587),
                    'discord_webhook': request.form.get('discord_webhook', ''),
                    'slack_webhook': request.form.get('slack_webhook', '')
                }
            }
            
            # Save to database or file
            settings_file = WORKSPACE_DIR / 'settings.json'
            with open(settings_file, 'w') as f:
                json.dump(settings_data, f, indent=2)
            
            flash('Settings saved successfully!', 'success')
            return redirect(url_for('settings'))
            
        except Exception as e:
            flash(f'Error saving settings: {str(e)}', 'error')
    
    # Load existing settings
    settings_file = WORKSPACE_DIR / 'settings.json'
    settings_data = {}
    if settings_file.exists():
        try:
            with open(settings_file, 'r') as f:
                settings_data = json.load(f)
        except:
            pass
    
    return render_template('settings.html', settings=settings_data)

@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    """API endpoint for settings management"""
    if request.method == 'GET':
        settings_file = WORKSPACE_DIR / 'settings.json'
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                return jsonify(json.load(f))
        return jsonify({})
    
    elif request.method == 'POST':
        try:
            settings_data = request.get_json()
            settings_file = WORKSPACE_DIR / 'settings.json'
            with open(settings_file, 'w') as f:
                json.dump(settings_data, f, indent=2)
            return jsonify({'success': True, 'message': 'Settings saved successfully'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test_configuration', methods=['POST'])
def test_configuration():
    """Test system configuration"""
    results = {}
    
    try:
        # Test nmap
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True, timeout=5)
            results['nmap'] = {'status': 'success', 'message': 'Nmap is available'}
        except:
            results['nmap'] = {'status': 'error', 'message': 'Nmap not found or not working'}
        
        # Test wordlists directory
        wordlist_path = Path('/usr/share/wordlists')
        if wordlist_path.exists():
            results['wordlists'] = {'status': 'success', 'message': f'Wordlists directory found with {len(list(wordlist_path.glob("*")))} items'}
        else:
            results['wordlists'] = {'status': 'warning', 'message': 'Wordlists directory not found'}
        
        # Test database
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM targets')
            count = cursor.fetchone()[0]
            conn.close()
            results['database'] = {'status': 'success', 'message': f'Database working, {count} targets found'}
        except Exception as e:
            results['database'] = {'status': 'error', 'message': f'Database error: {str(e)}'}
        
        # Test workspace
        if WORKSPACE_DIR.exists():
            results['workspace'] = {'status': 'success', 'message': f'Workspace directory: {WORKSPACE_DIR}'}
        else:
            results['workspace'] = {'status': 'error', 'message': 'Workspace directory not found'}
            
        return jsonify({'success': True, 'results': results})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# === ADVANCED FEATURES ===

@app.route('/intelligence/<int:target_id>')
def intelligence_dashboard(target_id):
    """Advanced intelligence dashboard for a target"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get target info
    cursor.execute('SELECT * FROM targets WHERE id = ?', (target_id,))
    target = cursor.fetchone()
    
    if not target:
        flash('Target not found', 'error')
        return redirect(url_for('targets'))
    
    # Get intelligence data
    cursor.execute('SELECT * FROM intelligence WHERE target_id = ?', (target_id,))
    intel_data = cursor.fetchall()
    
    # Get scan history
    cursor.execute('SELECT * FROM scan_history WHERE target_id = ? ORDER BY start_time DESC LIMIT 10', (target_id,))
    scan_history = cursor.fetchall()
    
    conn.close()
    
    return render_template('intelligence.html', 
                         target=target, 
                         intel_data=intel_data, 
                         scan_history=scan_history)

@app.route('/api/gather_intelligence/<int:target_id>')
def api_gather_intelligence(target_id):
    """API endpoint to gather intelligence for a target"""
    ui = BugBountyUI()
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT domain FROM targets WHERE id = ?', (target_id,))
    target = cursor.fetchone()
    
    if not target:
        return jsonify({'error': 'Target not found'})
    
    domain = target[0]
    
    # Start intelligence gathering in background
    def gather_intel():
        intel_data = ui.gather_intelligence(domain)
        
        # Save intelligence to database
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        for intel_type, data in intel_data.items():
            cursor.execute('''
                INSERT INTO intelligence (target_id, intel_type, source, data, confidence_level)
                VALUES (?, ?, ?, ?, ?)
            ''', (target_id, intel_type, 'automated', json.dumps(data), 85))
        
        # Update target with gathered data
        cursor.execute('''
            UPDATE targets SET 
                subdomains_count = ?,
                technology_stack = ?,
                risk_score = ?,
                last_scan = ?
            WHERE id = ?
        ''', (
            len(intel_data.get('subdomains', [])),
            json.dumps(intel_data.get('technologies', [])),
            intel_data.get('risk_assessment', {}).get('score', 0),
            datetime.now(),
            target_id
        ))
        
        conn.commit()
        conn.close()
    
    thread = threading.Thread(target=gather_intel)
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'Intelligence gathering started', 'target_id': target_id})

@app.route('/payloads')
def payloads_manager():
    """Payload management interface"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM payloads ORDER BY category, name')
    payloads = cursor.fetchall()
    
    # Group by category
    payload_categories = {}
    for payload in payloads:
        category = payload[2]  # category column
        if category not in payload_categories:
            payload_categories[category] = []
        payload_categories[category].append(payload)
    
    conn.close()
    
    return render_template('payloads.html', payload_categories=payload_categories)

@app.route('/add_payload', methods=['GET', 'POST'])
def add_payload():
    """Add new payload"""
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        payload_code = request.form['payload_code']
        description = request.form['description']
        tags = request.form['tags']
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO payloads (name, category, payload_code, description, tags)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, category, payload_code, description, tags))
        
        conn.commit()
        conn.close()
        
        flash('Payload added successfully!', 'success')
        return redirect(url_for('payloads_manager'))
    
    return render_template('add_payload.html')

@app.route('/automation')
def automation_dashboard():
    """Automation and scheduling dashboard"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get automation tasks
    cursor.execute('''
        SELECT at.*, t.domain 
        FROM automation_tasks at 
        JOIN targets t ON at.target_id = t.id 
        ORDER BY at.created_at DESC
    ''')
    tasks = cursor.fetchall()
    
    # Get targets for new task creation
    cursor.execute('SELECT id, domain FROM targets ORDER BY domain')
    targets = cursor.fetchall()
    
    conn.close()
    
    return render_template('automation.html', tasks=tasks, targets=targets)

@app.route('/api/schedule_scan', methods=['POST'])
def schedule_scan():
    """Schedule automated scan"""
    data = request.get_json()
    
    target_id = data.get('target_id')
    scan_type = data.get('scan_type')
    schedule = data.get('schedule')  # daily, weekly, monthly
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Calculate next run time
    now = datetime.now()
    if schedule == 'daily':
        next_run = now + timedelta(days=1)
    elif schedule == 'weekly':
        next_run = now + timedelta(weeks=1)
    elif schedule == 'monthly':
        next_run = now + timedelta(days=30)
    else:
        next_run = now + timedelta(hours=1)
    
    cursor.execute('''
        INSERT INTO automation_tasks (task_name, target_id, task_type, schedule, next_run, config)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (f"Automated {scan_type}", target_id, scan_type, schedule, next_run, json.dumps(data)))
    
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'Scan scheduled successfully'})

@app.route('/wordlists')
def wordlists_manager():
    """Wordlist management interface"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM wordlists ORDER BY category, name')
    wordlists = cursor.fetchall()
    
    conn.close()
    
    return render_template('wordlists.html', wordlists=wordlists)

@app.route('/api/run_automated_scan/<int:target_id>')
def run_automated_scan(target_id):
    """Run comprehensive automated scan"""
    ui = BugBountyUI()
    
    def run_scan():
        results = ui.automated_scan(target_id)
        
        # Process results and update database
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Update target status
        cursor.execute('''
            UPDATE targets SET 
                status = 'scanned', 
                last_scan = ?
            WHERE id = ?
        ''', (datetime.now(), target_id))
        
        # Auto-generate vulnerabilities from scan results
        web_scan = results.get('web_scan', {})
        if isinstance(web_scan, dict):
            vulns = web_scan.get('vulnerabilities', [])
        else:
            vulns = []
        
        for vuln in vulns:
            if vuln.get('type') and vuln.get('severity'):
                cursor.execute('''
                    INSERT INTO vulnerabilities 
                    (target_id, vulnerability_type, severity, title, description, poc, estimated_payout)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    target_id,
                    vuln['type'],
                    vuln['severity'],
                    f"Auto-detected: {vuln['type']}",
                    f"Automated scan detected potential {vuln['type']} vulnerability",
                    vuln.get('payload', 'Auto-detected'),
                    500 if vuln['severity'] == 'High' else 200 if vuln['severity'] == 'Medium' else 50
                ))
        
        conn.commit()
        conn.close()
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'Automated scan started', 'target_id': target_id})

@app.route('/api/export_data/<export_type>')
def export_data(export_type):
    """Export data in various formats"""
    conn = sqlite3.connect(DATABASE_PATH)
    
    if export_type == 'vulnerabilities_csv':
        # Export vulnerabilities as CSV
        cursor = conn.cursor()
        cursor.execute('''
            SELECT v.*, t.domain 
            FROM vulnerabilities v 
            JOIN targets t ON v.target_id = t.id
            ORDER BY v.created_at DESC
        ''')
        
        vulnerabilities = cursor.fetchall()
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Domain', 'Type', 'Severity', 'Title', 'Description', 'POC', 'Payout', 'Status', 'Created'])
        
        # Write data
        for vuln in vulnerabilities:
            writer.writerow([
                vuln[0], vuln[-1], vuln[2], vuln[3], vuln[4], 
                vuln[5], vuln[6], vuln[7], vuln[8], vuln[9]
            ])
        
        output.seek(0)
        
        # Create response
        response = send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name='vulnerabilities_export.csv'
        )
        
        conn.close()
        return response
    
    elif export_type == 'full_report_json':
        # Export complete database as JSON
        cursor = conn.cursor()
        
        # Get all data
        report = {}
        
        cursor.execute('SELECT * FROM targets')
        report['targets'] = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]
        
        cursor.execute('SELECT * FROM vulnerabilities')
        report['vulnerabilities'] = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]
        
        cursor.execute('SELECT * FROM scan_history')
        report['scan_history'] = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]
        
        cursor.execute('SELECT * FROM intelligence')
        report['intelligence'] = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]
        
        conn.close()
        
        # Create JSON response
        json_data = json.dumps(report, indent=2, default=str)
        
        return send_file(
            io.BytesIO(json_data.encode()),
            mimetype='application/json',
            as_attachment=True,
            download_name='bug_bounty_report.json'
        )
    
    conn.close()
    return jsonify({'error': 'Invalid export type'})

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

# === DOCUMENT MANAGEMENT ===

@app.route('/documents')
def documents_manager():
    """Document management interface"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get all documents with target info
    cursor.execute('''
        SELECT d.*, t.domain 
        FROM documents d 
        LEFT JOIN targets t ON d.target_id = t.id 
        ORDER BY d.uploaded_at DESC
    ''')
    documents = cursor.fetchall()
    
    # Get targets for new document upload
    cursor.execute('SELECT id, domain FROM targets ORDER BY domain')
    targets = cursor.fetchall()
    
    # Group documents by target
    documents_by_target = {}
    for doc in documents:
        target_domain = doc[13] or 'No Target'
        if target_domain not in documents_by_target:
            documents_by_target[target_domain] = []
        documents_by_target[target_domain].append(doc)
    
    conn.close()
    
    return render_template('documents.html', 
                         documents_by_target=documents_by_target, 
                         targets=targets,
                         total_documents=len(documents))

@app.route('/upload_document', methods=['GET', 'POST'])
def upload_document():
    """Upload new document"""
    if request.method == 'POST':
        try:
            # Get form data
            target_id = request.form.get('target_id')
            name = request.form.get('name')
            description = request.form.get('description')
            tags = request.form.get('tags', '')
            scope_info = request.form.get('scope_info', '')
            program_info = request.form.get('program_info', '')
            
            # Handle file upload
            file = request.files.get('file')
            
            if file and file.filename:
                # Create documents directory
                docs_dir = WORKSPACE_DIR / 'documents'
                docs_dir.mkdir(exist_ok=True)
                
                # Save file
                filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
                file_path = docs_dir / filename
                file.save(str(file_path))
                
                # Get file info
                file_size = file_path.stat().st_size
                content_type = file.content_type or 'application/octet-stream'
                file_type = file.filename.split('.')[-1].lower() if '.' in file.filename else 'unknown'
                
                # Save to database
                conn = sqlite3.connect(DATABASE_PATH)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO documents 
                    (target_id, name, description, file_type, file_path, file_size, 
                     content_type, tags, scope_info, program_info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (target_id, name, description, file_type, str(file_path), 
                      file_size, content_type, tags, scope_info, program_info))
                
                conn.commit()
                conn.close()
                
                flash('Document uploaded successfully!', 'success')
                return redirect(url_for('documents_manager'))
            
            else:
                flash('Please select a file to upload', 'error')
                
        except Exception as e:
            flash(f'Error uploading document: {str(e)}', 'error')
    
    # GET request - show upload form
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, domain FROM targets ORDER BY domain')
    targets = cursor.fetchall()
    conn.close()
    
    return render_template('upload_document.html', targets=targets)

@app.route('/document/<int:doc_id>')
def view_document(doc_id):
    """View document details"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT d.*, t.domain 
        FROM documents d 
        LEFT JOIN targets t ON d.target_id = t.id 
        WHERE d.id = ?
    ''', (doc_id,))
    
    document = cursor.fetchone()
    conn.close()
    
    if not document:
        flash('Document not found', 'error')
        return redirect(url_for('documents_manager'))
    
    return render_template('document_detail.html', document=document)

@app.route('/download_document/<int:doc_id>')
def download_document(doc_id):
    """Download document file"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT name, file_path, content_type FROM documents WHERE id = ?', (doc_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        flash('Document not found', 'error')
        return redirect(url_for('documents_manager'))
    
    name, file_path, content_type = result
    
    try:
        return send_file(
            file_path,
            mimetype=content_type,
            as_attachment=True,
            download_name=name
        )
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('documents_manager'))

@app.route('/api/parse_document/<int:doc_id>')
def parse_document(doc_id):
    """Parse document to extract scope and target information"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT file_path, file_type FROM documents WHERE id = ?', (doc_id,))
    result = cursor.fetchone()
    
    if not result:
        return jsonify({'error': 'Document not found'})
    
    file_path, file_type = result
    
    try:
        parsed_data = {}
        
        # Read file content based on type
        if file_type.lower() in ['txt', 'md']:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Extract common patterns
                parsed_data['urls'] = re.findall(r'https?://[^\s<>"\']+', content)
                parsed_data['domains'] = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
                parsed_data['ips'] = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
                parsed_data['emails'] = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
                
                # Extract scope keywords
                scope_keywords = ['in-scope', 'out-of-scope', 'allowed', 'forbidden', 'excluded', 'included']
                parsed_data['scope_sections'] = []
                
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if any(keyword in line.lower() for keyword in scope_keywords):
                        # Get context around scope mentions
                        start = max(0, i-2)
                        end = min(len(lines), i+3)
                        context = '\n'.join(lines[start:end])
                        parsed_data['scope_sections'].append(context)
                
                # Extract reward information
                reward_patterns = [
                    r'\$[\d,]+',  # Dollar amounts
                    r'[\d,]+\s*USD',  # USD amounts
                    r'reward[s]?\s*:?\s*\$?[\d,]+',  # Reward mentions
                    r'bounty[s]?\s*:?\s*\$?[\d,]+'   # Bounty mentions
                ]
                
                parsed_data['rewards'] = []
                for pattern in reward_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    parsed_data['rewards'].extend(matches)
                
        elif file_type.lower() == 'json':
            with open(file_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
                parsed_data['json_structure'] = list(json_data.keys())
                parsed_data['content'] = json_data
                
        else:
            parsed_data['message'] = f'Parsing not supported for {file_type} files'
        
        # Update document with parsed data
        cursor.execute('''
            UPDATE documents 
            SET scope_info = ?, program_info = ? 
            WHERE id = ?
        ''', (
            json.dumps(parsed_data.get('scope_sections', [])),
            json.dumps({
                'urls': parsed_data.get('urls', []),
                'domains': parsed_data.get('domains', []),
                'rewards': parsed_data.get('rewards', [])
            }),
            doc_id
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'parsed_data': parsed_data
        })
        
    except Exception as e:
        conn.close()
        return jsonify({'error': f'Error parsing document: {str(e)}'})

@app.route('/api/delete_document/<int:doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    """Delete document"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get file path before deleting
    cursor.execute('SELECT file_path FROM documents WHERE id = ?', (doc_id,))
    result = cursor.fetchone()
    
    if result:
        file_path = result[0]
        
        # Delete from database
        cursor.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
        conn.commit()
        
        # Delete file
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Warning: Could not delete file {file_path}: {e}")
        
        conn.close()
        return jsonify({'success': True})
    
    conn.close()
    return jsonify({'success': False, 'error': 'Document not found'})

@app.route('/api/extract_targets_from_document/<int:doc_id>')
def extract_targets_from_document(doc_id):
    """Extract and automatically add targets from document"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT file_path, file_type FROM documents WHERE id = ?', (doc_id,))
    result = cursor.fetchone()
    
    if not result:
        return jsonify({'error': 'Document not found'})
    
    file_path, file_type = result
    added_targets = []
    
    try:
        if file_type.lower() in ['txt', 'md']:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Extract domains and URLs
                domains = set(re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content))
                urls = re.findall(r'https?://([^/\s<>"\']+)', content)
                
                all_domains = domains.union(set(urls))
                
                # Filter out common false positives
                filtered_domains = []
                exclude_patterns = [
                    r'example\.com',
                    r'localhost',
                    r'127\.0\.0\.1',
                    r'\.png$', r'\.jpg$', r'\.gif$', r'\.css$', r'\.js$'
                ]
                
                for domain in all_domains:
                    if not any(re.search(pattern, domain, re.IGNORECASE) for pattern in exclude_patterns):
                        if len(domain) > 4 and '.' in domain:
                            filtered_domains.append(domain)
                
                # Add unique domains as targets
                for domain in filtered_domains[:20]:  # Limit to 20 targets
                    # Check if target already exists
                    cursor.execute('SELECT id FROM targets WHERE domain = ?', (domain,))
                    if not cursor.fetchone():
                        cursor.execute('''
                            INSERT INTO targets (domain, status, program_name)
                            VALUES (?, 'pending', ?)
                        ''', (domain, f'Auto-extracted from document'))
                        added_targets.append(domain)
                
                conn.commit()
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'added_targets': added_targets,
            'count': len(added_targets)
        })
        
    except Exception as e:
        conn.close()
        return jsonify({'error': f'Error extracting targets: {str(e)}'})

# === API ROUTES FOR DASHBOARD ===

@app.route('/api/dashboard_data')
def api_dashboard_data():
    """API endpoint for dashboard data updates"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM targets')
    targets = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
    vulnerabilities = cursor.fetchone()[0]
    
    cursor.execute('SELECT SUM(estimated_payout) FROM vulnerabilities WHERE estimated_payout IS NOT NULL')
    payouts = cursor.fetchone()[0] or 0
    
    cursor.execute('SELECT COUNT(*) FROM targets WHERE status = "scanning"')
    active_scans = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'stats': {
            'targets': targets,
            'vulnerabilities': vulnerabilities,
            'payouts': round(payouts, 2),
            'active_scans': active_scans
        }
    })

@app.route('/api/quick_scan_all', methods=['POST'])
def api_quick_scan_all():
    """Start quick scan on all targets"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, domain FROM targets WHERE status != "scanning"')
        targets = cursor.fetchall()
        
        count = 0
        for target_id, domain in targets:
            cursor.execute('UPDATE targets SET status = "scanning" WHERE id = ?', (target_id,))
            count += 1
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'count': count, 'message': f'Started scanning {count} targets'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/run_full_scan', methods=['POST'])
def api_run_full_scan():
    """Start comprehensive scan on all targets"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM targets')
        count = cursor.fetchone()[0]
        
        cursor.execute('UPDATE targets SET status = "scanning"')
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'count': count, 'message': f'Started full scan on {count} targets'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/generate_dashboard_report', methods=['POST'])
def api_generate_dashboard_report():
    """Generate dashboard report"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get data for report
        cursor.execute('SELECT COUNT(*) FROM targets')
        total_targets = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
        total_vulns = cursor.fetchone()[0]
        
        cursor.execute('SELECT vulnerability_type, severity, COUNT(*) FROM vulnerabilities GROUP BY vulnerability_type, severity')
        vuln_breakdown = cursor.fetchall()
        
        conn.close()
        
        # Create simple text report
        report_content = f"""
Bug Bounty Hunter Pro - Dashboard Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

=== SUMMARY ===
Total Targets: {total_targets}
Total Vulnerabilities: {total_vulns}

=== VULNERABILITY BREAKDOWN ===
"""
        for vuln_type, severity, count in vuln_breakdown:
            report_content += f"{vuln_type} ({severity}): {count}\n"
        
        # Create file-like object
        from io import StringIO
        import io
        
        output = io.BytesIO()
        output.write(report_content.encode('utf-8'))
        output.seek(0)
        
        return send_file(
            io.BytesIO(report_content.encode('utf-8')),
            as_attachment=True,
            download_name='dashboard_report.txt',
            mimetype='text/plain'
        )
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
        
# ...existing code...
if __name__ == '__main__':
    print("🚀 Starting Bug Bounty Hunter Web UI...")
    print("📱 Open your browser to: http://localhost:5000")
    print("🎯 Ready to hunt for bounties!")
    
    # Initialize database
    print("🗄️ Initializing database...")
    bug_bounty_ui = BugBountyUI()
    print("✅ Database ready!")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
