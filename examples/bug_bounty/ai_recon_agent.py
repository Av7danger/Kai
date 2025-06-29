#!/usr/bin/env python3
"""
🤖 AI-Powered Reconnaissance & Reporting Agent
Intelligent analysis and automation for bug bounty hunting

Features:
- AI-powered analysis of reconnaissance results
- Intelligent attack vector suggestions
- Custom payload generation based on context
- Automated bug report generation
- Pattern recognition and anomaly detection
- Vulnerability prioritization
- Professional report formatting
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import logging
import re
import requests

logger = logging.getLogger(__name__)

@dataclass
class AIAnalysisResult:
    """AI analysis result"""
    target: str
    analysis_type: str
    findings: List[Dict[str, Any]]
    suggestions: List[str]
    risk_score: float
    confidence: float
    timestamp: str

@dataclass
class BugReport:
    """Bug report structure"""
    title: str
    description: str
    severity: str
    impact: str
    steps_to_reproduce: List[str]
    proof_of_concept: str
    affected_components: List[str]
    recommendations: List[str]
    references: List[str]
    tags: List[str]
    timestamp: str

class AIReconAgent:
    """AI-powered reconnaissance and reporting agent"""
    
    def __init__(self, config_path: str = 'ai_agent_config.yml'):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize AI providers
        self.ai_providers = self._initialize_ai_providers()
        
        # Results storage
        self.analysis_results = []
        self.bug_reports = []
        
        # Create output directories
        self.output_dir = Path('ai_analysis_results')
        self.output_dir.mkdir(exist_ok=True)
        
        for subdir in ['analysis', 'reports', 'suggestions', 'payloads']:
            (self.output_dir / subdir).mkdir(exist_ok=True)
    
    def _load_config(self) -> Dict:
        """Load AI agent configuration"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default AI agent configuration"""
        return {
            'ai_providers': {
                'openai': {
                    'enabled': True,
                    'api_key': os.getenv('OPENAI_API_KEY'),
                    'model': 'gpt-4-turbo-preview',
                    'max_tokens': 4000
                },
                'anthropic': {
                    'enabled': True,
                    'api_key': os.getenv('ANTHROPIC_API_KEY'),
                    'model': 'claude-3-opus-20240229',
                    'max_tokens': 4000
                },
                'gemini': {
                    'enabled': True,
                    'api_key': os.getenv('GEMINI_API_KEY'),
                    'model': 'gemini-1.5-pro-latest'
                }
            },
            'analysis_settings': {
                'enable_pattern_recognition': True,
                'enable_anomaly_detection': True,
                'enable_vulnerability_prioritization': True,
                'confidence_threshold': 0.7
            },
            'report_settings': {
                'template_path': 'templates/bug_report_template.md',
                'auto_generate_poc': True,
                'include_impact_analysis': True,
                'include_recommendations': True
            }
        }
    
    def _initialize_ai_providers(self) -> Dict[str, Any]:
        """Initialize AI providers"""
        providers = {}
        
        # Initialize OpenAI
        if (self.config['ai_providers']['openai']['enabled'] and 
            self.config['ai_providers']['openai']['api_key']):
            try:
                import openai
                openai.api_key = self.config['ai_providers']['openai']['api_key']
                providers['openai'] = {
                    'client': openai,
                    'model': self.config['ai_providers']['openai']['model'],
                    'max_tokens': self.config['ai_providers']['openai']['max_tokens']
                }
                logger.info("OpenAI initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI: {e}")
        
        # Initialize Anthropic
        if (self.config['ai_providers']['anthropic']['enabled'] and 
            self.config['ai_providers']['anthropic']['api_key']):
            try:
                import anthropic
                providers['anthropic'] = {
                    'client': anthropic.Anthropic(api_key=self.config['ai_providers']['anthropic']['api_key']),
                    'model': self.config['ai_providers']['anthropic']['model'],
                    'max_tokens': self.config['ai_providers']['anthropic']['max_tokens']
                }
                logger.info("Anthropic initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Anthropic: {e}")
        
        # Initialize Gemini
        if (self.config['ai_providers']['gemini']['enabled'] and 
            self.config['ai_providers']['gemini']['api_key']):
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.config['ai_providers']['gemini']['api_key'])
                providers['gemini'] = {
                    'client': genai,
                    'model': self.config['ai_providers']['gemini']['model']
                }
                logger.info("Gemini initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini: {e}")
        
        return providers
    
    def analyze_recon_results(self, recon_data: Dict[str, Any]) -> AIAnalysisResult:
        """Analyze reconnaissance results using AI"""
        logger.info("Starting AI analysis of reconnaissance results")
        
        try:
            # Prepare analysis prompt
            prompt = self._create_analysis_prompt(recon_data)
            
            # Get AI analysis
            analysis = self._get_ai_analysis(prompt)
            
            # Parse analysis results
            parsed_analysis = self._parse_analysis_results(analysis)
            
            # Create analysis result
            result = AIAnalysisResult(
                target=recon_data.get('domain', 'unknown'),
                analysis_type='reconnaissance',
                findings=parsed_analysis.get('findings', []),
                suggestions=parsed_analysis.get('suggestions', []),
                risk_score=parsed_analysis.get('risk_score', 0.0),
                confidence=parsed_analysis.get('confidence', 0.0),
                timestamp=datetime.now().isoformat()
            )
            
            # Save analysis result
            self._save_analysis_result(result)
            self.analysis_results.append(result)
            
            logger.info(f"AI analysis completed for {result.target}")
            return result
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            raise
    
    def _create_analysis_prompt(self, recon_data: Dict[str, Any]) -> str:
        """Create analysis prompt for AI"""
        prompt = f"""
You are an expert cybersecurity analyst and bug bounty hunter. Analyze the following reconnaissance data and provide insights for finding vulnerabilities.

RECONNAISSANCE DATA:
Domain: {recon_data.get('domain', 'N/A')}
Subdomains Found: {len(recon_data.get('subdomains', []))}
Live Hosts: {len(recon_data.get('live_hosts', []))}
Vulnerabilities Found: {len(recon_data.get('vulnerabilities', []))}

SUBDOMAINS:
{json.dumps(recon_data.get('subdomains', []), indent=2)}

LIVE HOSTS:
{json.dumps(recon_data.get('live_hosts', []), indent=2)}

TECHNOLOGIES:
{json.dumps(recon_data.get('technologies', {}), indent=2)}

VULNERABILITIES:
{json.dumps(recon_data.get('vulnerabilities', []), indent=2)}

PORT SCAN RESULTS:
{json.dumps(recon_data.get('port_scan', {}), indent=2)}

Please analyze this data and provide:

1. KEY FINDINGS:
   - List the most interesting and potentially vulnerable targets
   - Identify unusual or suspicious configurations
   - Highlight technologies that are known to have vulnerabilities

2. ATTACK VECTOR SUGGESTIONS:
   - Suggest specific attack vectors to test
   - Recommend payloads for different vulnerability types
   - Identify potential entry points

3. RISK ASSESSMENT:
   - Rate the overall risk level (0-10)
   - Identify high-priority targets
   - Suggest focus areas for manual testing

4. NEXT STEPS:
   - Recommend specific tools and techniques
   - Suggest custom payloads to generate
   - Identify areas for deeper investigation

Format your response as JSON with the following structure:
{{
    "findings": [
        {{"type": "finding_type", "description": "description", "target": "target", "confidence": 0.8}}
    ],
    "suggestions": [
        {{"type": "attack_vector", "description": "description", "targets": ["target1", "target2"], "payload_suggestions": ["payload1", "payload2"]}}
    ],
    "risk_score": 7.5,
    "confidence": 0.85,
    "priority_targets": ["target1", "target2"],
    "recommended_tools": ["tool1", "tool2"],
    "custom_payloads": ["payload1", "payload2"]
}}
"""
        return prompt
    
    def _get_ai_analysis(self, prompt: str) -> str:
        """Get AI analysis from available providers"""
        for provider_name, provider in self.ai_providers.items():
            try:
                if provider_name == 'openai':
                    response = provider['client'].ChatCompletion.create(
                        model=provider['model'],
                        messages=[
                            {"role": "system", "content": "You are an expert cybersecurity analyst."},
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=provider['max_tokens'],
                        temperature=0.3
                    )
                    return response.choices[0].message.content
                
                elif provider_name == 'anthropic':
                    response = provider['client'].messages.create(
                        model=provider['model'],
                        max_tokens=provider['max_tokens'],
                        messages=[
                            {"role": "user", "content": prompt}
                        ]
                    )
                    return response.content[0].text
                
                elif provider_name == 'gemini':
                    model = provider['client'].GenerativeModel(provider['model'])
                    response = model.generate_content(prompt)
                    return response.text
                
            except Exception as e:
                logger.error(f"AI analysis failed with {provider_name}: {e}")
                continue
        
        # Fallback: return basic analysis
        return self._get_fallback_analysis()
    
    def _get_fallback_analysis(self) -> str:
        """Get fallback analysis when AI providers are unavailable"""
        return json.dumps({
            "findings": [
                {"type": "general", "description": "Basic reconnaissance completed", "target": "general", "confidence": 0.5}
            ],
            "suggestions": [
                {"type": "manual_testing", "description": "Perform manual testing on discovered endpoints", "targets": ["all"], "payload_suggestions": ["standard_payloads"]}
            ],
            "risk_score": 5.0,
            "confidence": 0.5,
            "priority_targets": ["main_domain"],
            "recommended_tools": ["manual_testing", "burp_suite"],
            "custom_payloads": ["basic_xss", "basic_sqli"]
        })
    
    def _parse_analysis_results(self, analysis: str) -> Dict[str, Any]:
        """Parse AI analysis results"""
        try:
            # Try to extract JSON from the response
            json_match = re.search(r'\{.*\}', analysis, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # Fallback parsing
                return {
                    'findings': [],
                    'suggestions': [],
                    'risk_score': 5.0,
                    'confidence': 0.5
                }
        except Exception as e:
            logger.error(f"Failed to parse analysis results: {e}")
            return {
                'findings': [],
                'suggestions': [],
                'risk_score': 5.0,
                'confidence': 0.5
            }
    
    def generate_custom_payloads(self, analysis_result: AIAnalysisResult) -> List[str]:
        """Generate custom payloads based on AI analysis"""
        logger.info("Generating custom payloads based on AI analysis")
        
        payloads = []
        
        try:
            # Create payload generation prompt
            prompt = self._create_payload_prompt(analysis_result)
            
            # Get AI-generated payloads
            ai_payloads = self._get_ai_analysis(prompt)
            
            # Parse payloads
            parsed_payloads = self._parse_payload_results(ai_payloads)
            
            # Validate and filter payloads
            for payload in parsed_payloads:
                if self._validate_payload(payload):
                    payloads.append(payload)
            
            # Save payloads
            self._save_custom_payloads(analysis_result.target, payloads)
            
            logger.info(f"Generated {len(payloads)} custom payloads")
            return payloads
            
        except Exception as e:
            logger.error(f"Payload generation failed: {e}")
            return []
    
    def _create_payload_prompt(self, analysis_result: AIAnalysisResult) -> str:
        """Create payload generation prompt"""
        prompt = f"""
You are an expert payload generator for security testing. Based on the following analysis, generate specific, effective payloads for testing.

ANALYSIS TARGET: {analysis_result.target}
RISK SCORE: {analysis_result.risk_score}
CONFIDENCE: {analysis_result.confidence}

FINDINGS:
{json.dumps(analysis_result.findings, indent=2)}

SUGGESTIONS:
{json.dumps(analysis_result.suggestions, indent=2)}

Generate specific payloads for the following categories:

1. XSS (Cross-Site Scripting) Payloads:
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS
   - Event handler XSS

2. SQL Injection Payloads:
   - Boolean-based
   - Time-based
   - Union-based
   - Error-based

3. Command Injection Payloads:
   - OS command injection
   - Blind command injection
   - Reverse shell payloads

4. SSRF (Server-Side Request Forgery) Payloads:
   - Internal network access
   - Cloud metadata access
   - Local file access

5. XXE (XML External Entity) Payloads:
   - File read
   - Out-of-band requests
   - Parameter entities

For each payload, provide:
- The actual payload
- Target parameter/endpoint
- Expected behavior
- Risk level

Format your response as JSON:
{{
    "payloads": [
        {{
            "category": "xss",
            "name": "payload_name",
            "payload": "actual_payload",
            "target": "parameter_or_endpoint",
            "expected_behavior": "what_should_happen",
            "risk_level": "high/medium/low"
        }}
    ]
}}
"""
        return prompt
    
    def _parse_payload_results(self, ai_payloads: str) -> List[str]:
        """Parse AI-generated payloads"""
        try:
            json_match = re.search(r'\{.*\}', ai_payloads, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return [payload['payload'] for payload in data.get('payloads', [])]
            else:
                # Extract payloads from text
                payloads = []
                lines = ai_payloads.split('\n')
                for line in lines:
                    if any(keyword in line.lower() for keyword in ['<script>', 'alert(', 'union', 'sleep(', 'http://']):
                        payloads.append(line.strip())
                return payloads
        except Exception as e:
            logger.error(f"Failed to parse payload results: {e}")
            return []
    
    def _validate_payload(self, payload: str) -> bool:
        """Validate generated payload"""
        # Basic validation
        if not payload or len(payload) < 3:
            return False
        
        # Check for common payload patterns
        payload_patterns = [
            r'<script>', r'alert\(', r'union\s+select', r'sleep\(', 
            r'http://', r'file://', r'javascript:', r'data:'
        ]
        
        for pattern in payload_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        
        return False
    
    def generate_bug_report(self, vulnerability_data: Dict[str, Any], 
                          analysis_result: AIAnalysisResult) -> BugReport:
        """Generate a professional bug report"""
        logger.info("Generating bug report")
        
        try:
            # Create bug report prompt
            prompt = self._create_bug_report_prompt(vulnerability_data, analysis_result)
            
            # Get AI-generated report
            ai_report = self._get_ai_analysis(prompt)
            
            # Parse report
            parsed_report = self._parse_bug_report(ai_report)
            
            # Create bug report object
            bug_report = BugReport(
                title=parsed_report.get('title', 'Vulnerability Report'),
                description=parsed_report.get('description', ''),
                severity=parsed_report.get('severity', 'medium'),
                impact=parsed_report.get('impact', ''),
                steps_to_reproduce=parsed_report.get('steps_to_reproduce', []),
                proof_of_concept=parsed_report.get('proof_of_concept', ''),
                affected_components=parsed_report.get('affected_components', []),
                recommendations=parsed_report.get('recommendations', []),
                references=parsed_report.get('references', []),
                tags=parsed_report.get('tags', []),
                timestamp=datetime.now().isoformat()
            )
            
            # Save bug report
            self._save_bug_report(bug_report)
            self.bug_reports.append(bug_report)
            
            logger.info(f"Bug report generated: {bug_report.title}")
            return bug_report
            
        except Exception as e:
            logger.error(f"Bug report generation failed: {e}")
            raise
    
    def _create_bug_report_prompt(self, vulnerability_data: Dict[str, Any], 
                                 analysis_result: AIAnalysisResult) -> str:
        """Create bug report generation prompt"""
        prompt = f"""
You are an expert bug bounty hunter. Create a professional, detailed bug report for the following vulnerability.

VULNERABILITY DATA:
{json.dumps(vulnerability_data, indent=2)}

ANALYSIS CONTEXT:
Target: {analysis_result.target}
Risk Score: {analysis_result.risk_score}
Findings: {json.dumps(analysis_result.findings, indent=2)}

Create a comprehensive bug report with the following sections:

1. TITLE: Clear, concise title describing the vulnerability
2. DESCRIPTION: Detailed explanation of the vulnerability
3. SEVERITY: Critical/High/Medium/Low with justification
4. IMPACT: What can be achieved with this vulnerability
5. STEPS TO REPRODUCE: Detailed, numbered steps
6. PROOF OF CONCEPT: Working exploit code or demonstration
7. AFFECTED COMPONENTS: Which parts of the application are affected
8. RECOMMENDATIONS: How to fix the vulnerability
9. REFERENCES: Related CVEs, documentation, or similar vulnerabilities
10. TAGS: Relevant tags for categorization

Format your response as JSON:
{{
    "title": "Vulnerability Title",
    "description": "Detailed description...",
    "severity": "high",
    "impact": "Impact description...",
    "steps_to_reproduce": ["Step 1", "Step 2", "Step 3"],
    "proof_of_concept": "PoC code or demonstration...",
    "affected_components": ["component1", "component2"],
    "recommendations": ["recommendation1", "recommendation2"],
    "references": ["reference1", "reference2"],
    "tags": ["tag1", "tag2"]
}}
"""
        return prompt
    
    def _parse_bug_report(self, ai_report: str) -> Dict[str, Any]:
        """Parse AI-generated bug report"""
        try:
            json_match = re.search(r'\{.*\}', ai_report, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # Fallback parsing
                return {
                    'title': 'Vulnerability Report',
                    'description': ai_report,
                    'severity': 'medium',
                    'impact': 'Unknown',
                    'steps_to_reproduce': [],
                    'proof_of_concept': '',
                    'affected_components': [],
                    'recommendations': [],
                    'references': [],
                    'tags': []
                }
        except Exception as e:
            logger.error(f"Failed to parse bug report: {e}")
            return {
                'title': 'Vulnerability Report',
                'description': ai_report,
                'severity': 'medium',
                'impact': 'Unknown',
                'steps_to_reproduce': [],
                'proof_of_concept': '',
                'affected_components': [],
                'recommendations': [],
                'references': [],
                'tags': []
            }
    
    def detect_patterns(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect patterns and anomalies in data"""
        patterns = []
        
        try:
            # Group by similar characteristics
            grouped_data = {}
            for item in data:
                key = self._get_pattern_key(item)
                if key not in grouped_data:
                    grouped_data[key] = []
                grouped_data[key].append(item)
            
            # Identify patterns
            for key, items in grouped_data.items():
                if len(items) > 1:
                    patterns.append({
                        'type': 'pattern',
                        'key': key,
                        'items': items,
                        'count': len(items),
                        'description': f"Found {len(items)} similar items"
                    })
            
            # Detect anomalies
            anomalies = self._detect_anomalies(data)
            patterns.extend(anomalies)
            
        except Exception as e:
            logger.error(f"Pattern detection failed: {e}")
        
        return patterns
    
    def _get_pattern_key(self, item: Dict[str, Any]) -> str:
        """Get pattern key for grouping"""
        if 'technology' in item:
            return f"tech_{item['technology']}"
        elif 'service' in item:
            return f"service_{item['service']}"
        elif 'status_code' in item:
            return f"status_{item['status_code']}"
        else:
            return "unknown"
    
    def _detect_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in data"""
        anomalies = []
        
        try:
            # Detect unusual status codes
            status_codes = [item.get('status_code', 0) for item in data if 'status_code' in item]
            if status_codes:
                avg_status = sum(status_codes) / len(status_codes)
                for item in data:
                    if 'status_code' in item and abs(item['status_code'] - avg_status) > 100:
                        anomalies.append({
                            'type': 'anomaly',
                            'item': item,
                            'description': f"Unusual status code: {item['status_code']}"
                        })
            
            # Detect unusual technologies
            tech_counts = {}
            for item in data:
                if 'technology' in item:
                    tech = item['technology']
                    tech_counts[tech] = tech_counts.get(tech, 0) + 1
            
            for item in data:
                if 'technology' in item:
                    tech = item['technology']
                    if tech_counts[tech] == 1:  # Unique technology
                        anomalies.append({
                            'type': 'anomaly',
                            'item': item,
                            'description': f"Unique technology: {tech}"
                        })
        
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
        
        return anomalies
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize vulnerabilities based on AI analysis"""
        prioritized = []
        
        try:
            for vuln in vulnerabilities:
                # Calculate priority score
                priority_score = self._calculate_priority_score(vuln)
                vuln['priority_score'] = priority_score
                prioritized.append(vuln)
            
            # Sort by priority score
            prioritized.sort(key=lambda x: x['priority_score'], reverse=True)
            
        except Exception as e:
            logger.error(f"Vulnerability prioritization failed: {e}")
        
        return prioritized
    
    def _calculate_priority_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate priority score for a vulnerability"""
        score = 0.0
        
        try:
            # Severity scoring
            severity_scores = {
                'critical': 10.0,
                'high': 8.0,
                'medium': 5.0,
                'low': 2.0,
                'info': 1.0
            }
            
            severity = vuln.get('severity', 'medium').lower()
            score += severity_scores.get(severity, 5.0)
            
            # CVSS scoring
            if 'cvss_score' in vuln:
                score += vuln['cvss_score'] * 0.5
            
            # Exploitability scoring
            if vuln.get('exploitable', False):
                score += 3.0
            
            # Impact scoring
            if 'impact' in vuln:
                impact = vuln['impact'].lower()
                if 'rce' in impact or 'remote code execution' in impact:
                    score += 5.0
                elif 'sqli' in impact or 'sql injection' in impact:
                    score += 4.0
                elif 'xss' in impact or 'cross-site scripting' in impact:
                    score += 3.0
            
            # Asset value scoring
            if 'target' in vuln:
                target = vuln['target']
                if 'admin' in target or 'api' in target or 'auth' in target:
                    score += 2.0
            
        except Exception as e:
            logger.error(f"Priority score calculation failed: {e}")
        
        return min(score, 10.0)  # Cap at 10.0
    
    def _save_analysis_result(self, result: AIAnalysisResult):
        """Save analysis result to file"""
        output_file = self.output_dir / 'analysis' / f"{result.target}_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump({
                'target': result.target,
                'analysis_type': result.analysis_type,
                'findings': result.findings,
                'suggestions': result.suggestions,
                'risk_score': result.risk_score,
                'confidence': result.confidence,
                'timestamp': result.timestamp
            }, f, indent=2)
    
    def _save_custom_payloads(self, target: str, payloads: List[str]):
        """Save custom payloads to file"""
        output_file = self.output_dir / 'payloads' / f"{target}_custom_payloads_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump({
                'target': target,
                'payloads': payloads,
                'count': len(payloads),
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)
    
    def _save_bug_report(self, report: BugReport):
        """Save bug report to file"""
        output_file = self.output_dir / 'reports' / f"{report.title.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump({
                'title': report.title,
                'description': report.description,
                'severity': report.severity,
                'impact': report.impact,
                'steps_to_reproduce': report.steps_to_reproduce,
                'proof_of_concept': report.proof_of_concept,
                'affected_components': report.affected_components,
                'recommendations': report.recommendations,
                'references': report.references,
                'tags': report.tags,
                'timestamp': report.timestamp
            }, f, indent=2)
    
    def get_ai_agent_statistics(self) -> Dict[str, Any]:
        """Get AI agent statistics"""
        return {
            'total_analyses': len(self.analysis_results),
            'total_bug_reports': len(self.bug_reports),
            'ai_providers_available': len(self.ai_providers),
            'last_analysis': self.analysis_results[-1].timestamp if self.analysis_results else None,
            'average_risk_score': sum(r.risk_score for r in self.analysis_results) / len(self.analysis_results) if self.analysis_results else 0.0
        }

# Global AI agent instance
ai_agent = None

def initialize_ai_agent(config_path: str = 'ai_agent_config.yml'):
    """Initialize the global AI agent instance"""
    global ai_agent
    ai_agent = AIReconAgent(config_path)
    return ai_agent

def get_ai_agent() -> AIReconAgent:
    """Get the global AI agent instance"""
    if ai_agent is None:
        raise RuntimeError("AI agent not initialized. Call initialize_ai_agent() first.")
    return ai_agent 