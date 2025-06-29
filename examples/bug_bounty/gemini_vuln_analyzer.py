#!/usr/bin/env python3
"""
Gemini Vulnerability Analyzer & PoC Generator
==============================================

This script analyzes vulnerabilities found by the AI and generates:
1. Step-by-step discovery process explanation
2. Detailed reproduction instructions
3. PoC scripts and payloads
4. Remediation recommendations

Author: Bug Bounty Pro Team
"""

import os
import sys
import json
import sqlite3
import argparse
import requests
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

# Try to import Gemini API
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("Warning: google-generativeai not installed. Please install it with: pip install google-generativeai")

class GeminiVulnAnalyzer:
    def __init__(self, api_key: Optional[str] = None, db_path: str = "bb_pro.db"):
        """Initialize the Gemini Vulnerability Analyzer"""
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        self.db_path = db_path
        
        if not GEMINI_AVAILABLE:
            raise ImportError("google-generativeai package not installed. Install with: pip install google-generativeai")
        
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY environment variable not set")
        
        # Configure Gemini
        try:
            if hasattr(genai, 'configure'):
                genai.configure(api_key=self.api_key)
            if hasattr(genai, 'GenerativeModel'):
                self.model = genai.GenerativeModel('gemini-pro')
            else:
                self.model = None
        except Exception as e:
            print(f"Warning: Could not initialize Gemini API: {e}")
            self.model = None
        
        # Create reports directory
        self.reports_dir = Path("vulnerability_analysis_reports")
        self.reports_dir.mkdir(exist_ok=True)
        
        print("[+] Gemini Vulnerability Analyzer initialized")
    
    def get_vulnerability_from_db(self, vuln_id: int) -> Optional[Dict]:
        """Fetch vulnerability details from database"""
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
            print(f"[-] Error fetching vulnerability: {e}")
            return None
    
    def list_vulnerabilities(self) -> List[Dict]:
        """List all vulnerabilities from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT v.id, v.title, v.severity, v.status, v.found_date,
                       t.name as target_name, t.url as target_url
                FROM vulnerabilities v
                LEFT JOIN targets t ON v.target_id = t.id
                ORDER BY v.found_date DESC
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
            
        except Exception as e:
            print(f"[-] Error listing vulnerabilities: {e}")
            return []
    
    def generate_ai_content(self, prompt: str) -> str:
        """Generate content using AI with fallback handling"""
        if not self.model:
            return self._generate_fallback_content(prompt)
        
        try:
            if hasattr(self.model, 'generate_content'):
                response = self.model.generate_content(prompt)
                return response.text if hasattr(response, 'text') else str(response)
            else:
                return self._generate_fallback_content(prompt)
        except Exception as e:
            print(f"Warning: AI generation failed: {e}")
            return self._generate_fallback_content(prompt)
    
    def _generate_fallback_content(self, prompt: str) -> str:
        """Generate fallback content when AI is not available"""
        if "DISCOVERY METHODOLOGY" in prompt:
            return """# AI Analysis Not Available

**Note**: This analysis requires AI capabilities. Please ensure:
1. google-generativeai package is installed: `pip install google-generativeai`
2. GEMINI_API_KEY environment variable is set
3. Valid Gemini API key is configured

## Manual Analysis Template

Please perform manual analysis based on:
- Vulnerability type and severity
- Target application technology stack
- Common attack vectors for this vulnerability class
- Standard penetration testing methodologies

Refer to OWASP guidelines and security testing frameworks for detailed analysis."""
        
        return "# AI Analysis Not Available\n\nPlease configure Gemini API for automated analysis."
    
    def generate_discovery_analysis(self, vuln_data: Dict) -> str:
        """Generate AI analysis of how the vulnerability was discovered"""
        
        analysis_prompt = f"""
You are a cybersecurity expert analyzing how a vulnerability was discovered. 

VULNERABILITY DETAILS:
- Title: {vuln_data.get('title', 'Unknown')}
- Type: {vuln_data.get('vuln_type', 'Unknown')}
- Severity: {vuln_data.get('severity', 'Unknown')}
- Target: {vuln_data.get('target_name', 'Unknown')} ({vuln_data.get('target_url', 'Unknown')})
- Description: {vuln_data.get('description', 'No description available')}
- Technical Details: {vuln_data.get('technical_details', 'No technical details available')}
- Location: {vuln_data.get('location', 'Unknown')}

TASK: Provide a detailed analysis explaining:

1. **DISCOVERY METHODOLOGY**: How was this vulnerability likely discovered?
   - What scanning techniques were used?
   - What patterns or indicators led to its identification?
   - What tools or methods would typically find this?

2. **VULNERABILITY ANALYSIS**: Technical breakdown
   - Root cause of the vulnerability
   - Why it exists (coding error, configuration issue, etc.)
   - Attack surface and entry points

3. **DETECTION SIGNATURES**: What specific signs indicate this vulnerability?
   - HTTP responses, error messages, behaviors
   - Code patterns or configurations that expose it
   - Network traffic or application behavior anomalies

4. **EXPLOITATION PATH**: Step-by-step attack progression
   - Initial reconnaissance steps
   - Vulnerability identification process
   - Exploitation methodology

Please be thorough and technical, explaining each step clearly for educational purposes.
"""
        
        return self.generate_ai_content(analysis_prompt)
    
    def generate_reproduction_guide(self, vuln_data: Dict) -> str:
        """Generate step-by-step reproduction instructions"""
        
        reproduction_prompt = f"""
You are a penetration testing expert creating a detailed PoC (Proof of Concept) reproduction guide.

VULNERABILITY DETAILS:
- Title: {vuln_data.get('title', 'Unknown')}
- Type: {vuln_data.get('vuln_type', 'Unknown')}
- Severity: {vuln_data.get('severity', 'Unknown')}
- Target: {vuln_data.get('target_name', 'Unknown')} ({vuln_data.get('target_url', 'Unknown')})
- Location: {vuln_data.get('location', 'Unknown')}
- Description: {vuln_data.get('description', 'No description available')}

TASK: Create a comprehensive PoC reproduction guide with:

1. **PREREQUISITES**:
   - Required tools and software
   - Environment setup
   - Access requirements

2. **STEP-BY-STEP REPRODUCTION**:
   - Detailed commands with explanations
   - Expected outputs at each step
   - Screenshots or evidence collection points
   - Specific payloads and test cases

3. **MANUAL TESTING METHODS**:
   - Browser-based testing steps
   - Command-line tools usage
   - Burp Suite/OWASP ZAP procedures

4. **AUTOMATED TESTING SCRIPTS**:
   - Python scripts for automation
   - Curl commands
   - Custom payloads

5. **EVIDENCE COLLECTION**:
   - What evidence proves the vulnerability
   - How to document findings
   - Screenshots and logs to capture

6. **IMPACT DEMONSTRATION**:
   - How to safely demonstrate impact
   - Business risk scenarios
   - Potential attack scenarios

Make this guide practical and actionable for someone to follow step-by-step.
Include actual commands, payloads, and code examples where appropriate.
"""
        
        return self.generate_ai_content(reproduction_prompt)
    
    def generate_poc_scripts(self, vuln_data: Dict) -> str:
        """Generate automated PoC scripts"""
        
        script_prompt = f"""
You are an expert in creating automated vulnerability testing scripts.

VULNERABILITY DETAILS:
- Title: {vuln_data.get('title', 'Unknown')}
- Type: {vuln_data.get('vuln_type', 'Unknown')}
- Target: {vuln_data.get('target_url', 'Unknown')}
- Location: {vuln_data.get('location', 'Unknown')}

TASK: Create practical automation scripts:

1. **PYTHON EXPLOITATION SCRIPT**:
   - Complete Python script to test/exploit the vulnerability
   - Include error handling and output formatting
   - Add comments explaining each step

2. **BASH/CURL COMMANDS**:
   - Command-line testing procedures
   - Curl commands with proper headers and payloads
   - One-liner tests for quick verification

3. **BURP SUITE EXTENSIONS** (if applicable):
   - Custom Burp extensions or macros
   - Intruder payload lists
   - Scanner checks

4. **PAYLOAD COLLECTIONS**:
   - Specific payloads for this vulnerability type
   - Bypass techniques
   - Edge cases and variations

Make the scripts production-ready with proper error handling and documentation.
Include both basic and advanced exploitation techniques.
"""
        
        return self.generate_ai_content(script_prompt)
    
    def generate_remediation_guide(self, vuln_data: Dict) -> str:
        """Generate remediation recommendations"""
        
        remediation_prompt = f"""
You are a security consultant providing remediation guidance.

VULNERABILITY DETAILS:
- Title: {vuln_data.get('title', 'Unknown')}
- Type: {vuln_data.get('vuln_type', 'Unknown')}
- Severity: {vuln_data.get('severity', 'Unknown')}
- Technical Details: {vuln_data.get('technical_details', 'No technical details available')}

TASK: Provide comprehensive remediation guidance:

1. **IMMEDIATE ACTIONS**:
   - Emergency mitigation steps
   - Temporary fixes or workarounds
   - Risk reduction measures

2. **PERMANENT FIXES**:
   - Code changes required
   - Configuration updates
   - Architecture improvements

3. **PREVENTION STRATEGIES**:
   - Coding best practices
   - Security controls to implement
   - Testing procedures to prevent recurrence

4. **VERIFICATION STEPS**:
   - How to test that the fix works
   - Regression testing procedures
   - Ongoing monitoring recommendations

5. **DEVELOPER GUIDANCE**:
   - Specific code examples (secure implementations)
   - Common pitfalls to avoid
   - Security libraries or frameworks to use

Provide practical, actionable advice that developers can implement immediately.
"""
        
        return self.generate_ai_content(remediation_prompt)
    
    def analyze_vulnerability(self, vuln_id: int) -> str:
        """Complete vulnerability analysis and PoC generation"""
        
        print(f"[+] Analyzing vulnerability ID: {vuln_id}")
        
        # Fetch vulnerability data
        vuln_data = self.get_vulnerability_from_db(vuln_id)
        if not vuln_data:
            return f"[-] Vulnerability ID {vuln_id} not found in database"
        
        print(f"[+] Found vulnerability: {vuln_data.get('title', 'Unknown')}")
        print("[+] Generating discovery analysis...")
        
        # Generate all sections
        sections = {
            "Discovery Analysis": self.generate_discovery_analysis(vuln_data),
            "Reproduction Guide": self.generate_reproduction_guide(vuln_data),
            "PoC Scripts": self.generate_poc_scripts(vuln_data),
            "Remediation Guide": self.generate_remediation_guide(vuln_data)
        }
        
        # Create comprehensive report
        report = self.create_report(vuln_data, sections)
        
        # Save report
        report_filename = f"vuln_{vuln_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path = self.reports_dir / report_filename
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"[+] Analysis complete! Report saved to: {report_path}")
        return str(report_path)
    
    def create_report(self, vuln_data: Dict, sections: Dict[str, str]) -> str:
        """Create formatted markdown report"""
        
        report = f"""# Vulnerability Analysis Report

## Vulnerability Overview

**ID:** {vuln_data.get('id', 'Unknown')}
**Title:** {vuln_data.get('title', 'Unknown')}
**Type:** {vuln_data.get('vuln_type', 'Unknown')}
**Severity:** {vuln_data.get('severity', 'Unknown')}
**Status:** {vuln_data.get('status', 'Unknown')}
**Found Date:** {vuln_data.get('found_date', 'Unknown')}

**Target Information:**
- **Name:** {vuln_data.get('target_name', 'Unknown')}
- **URL:** {vuln_data.get('target_url', 'Unknown')}
- **Location:** {vuln_data.get('location', 'Unknown')}

**Description:**
{vuln_data.get('description', 'No description available')}

**Technical Details:**
{vuln_data.get('technical_details', 'No technical details available')}

---

## 1. Discovery Analysis

{sections.get('Discovery Analysis', 'Not available')}

---

## 2. Reproduction Guide

{sections.get('Reproduction Guide', 'Not available')}

---

## 3. PoC Scripts and Automation

{sections.get('PoC Scripts', 'Not available')}

---

## 4. Remediation Guide

{sections.get('Remediation Guide', 'Not available')}

---

## Report Information

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tool:** Gemini Vulnerability Analyzer
**Database:** {self.db_path}

---

*This report was automatically generated using AI analysis. Please review and validate all recommendations before implementation.*
"""
        
        return report
    
    def interactive_mode(self):
        """Interactive vulnerability analysis mode"""
        
        print("\n" + "="*60)
        print("🔍 GEMINI VULNERABILITY ANALYZER - INTERACTIVE MODE")
        print("="*60)
        
        while True:
            print("\nAvailable options:")
            print("1. List all vulnerabilities")
            print("2. Analyze specific vulnerability")
            print("3. Batch analyze recent vulnerabilities")
            print("4. Search vulnerabilities by type")
            print("5. Exit")
            
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == '1':
                self.list_all_vulnerabilities()
            elif choice == '2':
                self.analyze_specific_vulnerability()
            elif choice == '3':
                self.batch_analyze_recent()
            elif choice == '4':
                self.search_vulnerabilities()
            elif choice == '5':
                print("[+] Goodbye!")
                break
            else:
                print("[-] Invalid choice. Please try again.")
    
    def list_all_vulnerabilities(self):
        """List all vulnerabilities in interactive mode"""
        vulns = self.list_vulnerabilities()
        
        if not vulns:
            print("[-] No vulnerabilities found in database")
            return
        
        print(f"\n[+] Found {len(vulns)} vulnerabilities:")
        print("-" * 80)
        print(f"{'ID':<4} {'Title':<30} {'Severity':<10} {'Target':<20} {'Date':<12}")
        print("-" * 80)
        
        for vuln in vulns:
            title = vuln['title'][:29] if vuln['title'] else 'Unknown'
            target = vuln['target_name'][:19] if vuln['target_name'] else 'Unknown'
            date = vuln['found_date'][:10] if vuln['found_date'] else 'Unknown'
            
            print(f"{vuln['id']:<4} {title:<30} {vuln['severity']:<10} {target:<20} {date:<12}")
    
    def analyze_specific_vulnerability(self):
        """Analyze a specific vulnerability in interactive mode"""
        try:
            vuln_id = int(input("Enter vulnerability ID to analyze: "))
            report_path = self.analyze_vulnerability(vuln_id)
            
            view_report = input("Would you like to view the report? (y/N): ").lower().strip()
            if view_report == 'y':
                os.system(f'notepad.exe "{report_path}"')  # Windows
                
        except ValueError:
            print("[-] Invalid vulnerability ID")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def batch_analyze_recent(self):
        """Analyze recent vulnerabilities in batch"""
        try:
            count = int(input("How many recent vulnerabilities to analyze? (default 5): ") or "5")
            vulns = self.list_vulnerabilities()[:count]
            
            if not vulns:
                print("[-] No vulnerabilities found")
                return
            
            print(f"[+] Analyzing {len(vulns)} recent vulnerabilities...")
            
            for vuln in vulns:
                print(f"[+] Processing: {vuln['title']}")
                self.analyze_vulnerability(vuln['id'])
                
            print(f"[+] Batch analysis complete! Check {self.reports_dir} for reports.")
            
        except ValueError:
            print("[-] Invalid number")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def search_vulnerabilities(self):
        """Search vulnerabilities by type"""
        search_term = input("Enter vulnerability type to search for: ").strip()
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT v.id, v.title, v.vuln_type, v.severity, t.name as target_name
                FROM vulnerabilities v
                LEFT JOIN targets t ON v.target_id = t.id
                WHERE v.vuln_type LIKE ? OR v.title LIKE ?
                ORDER BY v.found_date DESC
            """, (f"%{search_term}%", f"%{search_term}%"))
            
            results = cursor.fetchall()
            conn.close()
            
            if results:
                print(f"\n[+] Found {len(results)} matching vulnerabilities:")
                for row in results:
                    print(f"ID: {row['id']} | {row['title']} | {row['vuln_type']} | {row['severity']}")
            else:
                print("[-] No matching vulnerabilities found")
                
        except Exception as e:
            print(f"[-] Error searching: {e}")

def main():
    parser = argparse.ArgumentParser(description="Gemini Vulnerability Analyzer & PoC Generator")
    parser.add_argument('-v', '--vulnerability-id', type=int, help='Analyze specific vulnerability ID')
    parser.add_argument('-l', '--list', action='store_true', help='List all vulnerabilities')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('-b', '--batch', type=int, help='Batch analyze N recent vulnerabilities')
    parser.add_argument('--api-key', help='Gemini API key (or set GEMINI_API_KEY env var)')
    parser.add_argument('--db-path', default='bb_pro.db', help='Path to database file')
    
    args = parser.parse_args()
    
    try:
        analyzer = GeminiVulnAnalyzer(api_key=args.api_key, db_path=args.db_path)
        
        if args.list:
            vulns = analyzer.list_vulnerabilities()
            if vulns:
                print(f"Found {len(vulns)} vulnerabilities:")
                for vuln in vulns:
                    print(f"ID: {vuln['id']} | {vuln['title']} | {vuln['severity']} | {vuln['target_name']}")
            else:
                print("No vulnerabilities found")
                
        elif args.vulnerability_id:
            report_path = analyzer.analyze_vulnerability(args.vulnerability_id)
            print(f"Report saved to: {report_path}")
            
        elif args.batch:
            vulns = analyzer.list_vulnerabilities()[:args.batch]
            print(f"Batch analyzing {len(vulns)} vulnerabilities...")
            for vuln in vulns:
                analyzer.analyze_vulnerability(vuln['id'])
            print("Batch analysis complete!")
            
        elif args.interactive:
            analyzer.interactive_mode()
            
        else:
            print("No action specified. Use --help for options or --interactive for interactive mode.")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
