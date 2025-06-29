#!/usr/bin/env python3
"""
🎯 GEMINI-POWERED VULNERABILITY REPRODUCTION ASSISTANT
AI-driven vulnerability analysis and step-by-step PoC generation
"""

import os
import json
import sqlite3
import requests
from pathlib import Path
from datetime import datetime
import argparse

# Gemini API configuration
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent"

DATABASE_PATH = Path.home() / 'bb_pro_workspace' / 'bb_pro.db'

class GeminiVulnAnalyzer:
    def __init__(self):
        self.api_key = GEMINI_API_KEY
        if not self.api_key:
            print("⚠️  Warning: GEMINI_API_KEY not set. Add it to environment variables or settings.")
            print("   You can get one from: https://makersuite.google.com/app/apikey")
    
    def query_gemini(self, prompt):
        """Query Gemini AI for vulnerability analysis"""
        if not self.api_key:
            return {"error": "Gemini API key not configured"}
        
        headers = {
            'Content-Type': 'application/json',
        }
        
        data = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ]
        }
        
        try:
            response = requests.post(
                f"{GEMINI_API_URL}?key={self.api_key}",
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'candidates' in result and result['candidates']:
                    return result['candidates'][0]['content']['parts'][0]['text']
                else:
                    return "No response from Gemini"
            else:
                return f"API Error: {response.status_code} - {response.text}"
                
        except Exception as e:
            return f"Error querying Gemini: {str(e)}"

    def get_vulnerability_from_db(self, vuln_id=None):
        """Get vulnerability details from database"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            if vuln_id:
                cursor.execute('''
                    SELECT v.*, t.domain, t.program_name
                    FROM vulnerabilities v
                    JOIN targets t ON v.target_id = t.id
                    WHERE v.id = ?
                ''', (vuln_id,))
                vuln = cursor.fetchone()
                
                if vuln:
                    return {
                        'id': vuln[0],
                        'target_id': vuln[1],
                        'vulnerability_type': vuln[2],
                        'severity': vuln[3],
                        'title': vuln[4],
                        'description': vuln[5],
                        'location': vuln[6],
                        'payload': vuln[7],
                        'evidence': vuln[8],
                        'impact': vuln[9],
                        'remediation': vuln[10],
                        'estimated_payout': vuln[11],
                        'status': vuln[12],
                        'created_at': vuln[13],
                        'domain': vuln[14],
                        'program_name': vuln[15]
                    }
            else:
                # Get latest vulnerabilities
                cursor.execute('''
                    SELECT v.id, v.vulnerability_type, v.severity, v.title, t.domain
                    FROM vulnerabilities v
                    JOIN targets t ON v.target_id = t.id
                    ORDER BY v.created_at DESC
                    LIMIT 10
                ''')
                vulns = cursor.fetchall()
                return vulns
                
            conn.close()
            return None
            
        except Exception as e:
            print(f"Database error: {e}")
            return None

    def generate_discovery_explanation(self, vuln_data):
        """Generate AI explanation of how the vulnerability was discovered"""
        prompt = f"""
As a cybersecurity AI assistant, explain how this vulnerability was discovered and provide step-by-step reproduction instructions:

VULNERABILITY DETAILS:
- Type: {vuln_data['vulnerability_type']}
- Severity: {vuln_data['severity']}
- Title: {vuln_data['title']}
- Target: {vuln_data['domain']}
- Location: {vuln_data['location']}
- Payload Used: {vuln_data['payload']}
- Description: {vuln_data['description']}

Please provide:

1. DISCOVERY METHODOLOGY:
   - How was this vulnerability identified?
   - What automated or manual techniques were used?
   - What patterns or signatures indicated the vulnerability?

2. STEP-BY-STEP REPRODUCTION:
   - Exact steps to reproduce this vulnerability
   - Required tools and setup
   - Expected vs actual responses
   - How to verify the vulnerability exists

3. TECHNICAL ANALYSIS:
   - Why this vulnerability exists
   - Root cause analysis
   - Security implications

4. PROOF OF CONCEPT:
   - Complete working PoC code
   - Command line examples
   - Screenshots descriptions
   - Expected output

5. IMPACT ASSESSMENT:
   - Real-world attack scenarios
   - Potential damage
   - Business risk

Format the response in clear markdown with code blocks for any technical commands or payloads.
"""
        
        return self.query_gemini(prompt)

    def generate_advanced_poc(self, vuln_data):
        """Generate advanced PoC with multiple attack vectors"""
        prompt = f"""
Create an advanced proof-of-concept for this {vuln_data['vulnerability_type']} vulnerability:

Target: {vuln_data['domain']}
Location: {vuln_data['location']}
Original Payload: {vuln_data['payload']}

Provide:

1. MULTIPLE ATTACK VECTORS:
   - Different payload variations
   - Bypass techniques for common filters
   - Alternative exploitation methods

2. AUTOMATED TESTING SCRIPT:
   - Python script to test the vulnerability
   - Multiple payload attempts
   - Response analysis

3. MANUAL TESTING STEPS:
   - Browser-based testing
   - Burp Suite/OWASP ZAP integration
   - Command-line testing

4. EVIDENCE COLLECTION:
   - What to screenshot
   - Log entries to capture
   - Response headers to document

5. ESCALATION POSSIBILITIES:
   - How to chain this with other vulnerabilities
   - Privilege escalation opportunities
   - Data exfiltration methods

Include working code examples and specific commands.
"""
        
        return self.query_gemini(prompt)

    def analyze_and_reproduce(self, vuln_id):
        """Main function to analyze and provide reproduction steps"""
        print(f"\n🔍 Analyzing vulnerability ID: {vuln_id}")
        print("=" * 60)
        
        # Get vulnerability data
        vuln_data = self.get_vulnerability_from_db(vuln_id)
        if not vuln_data:
            print("❌ Vulnerability not found in database")
            return
        
        print(f"📋 Vulnerability: {vuln_data['title']}")
        print(f"🎯 Target: {vuln_data['domain']}")
        print(f"⚠️  Severity: {vuln_data['severity']}")
        print(f"🔧 Type: {vuln_data['vulnerability_type']}")
        print()
        
        # Generate discovery explanation
        print("🤖 Generating AI analysis...")
        discovery_analysis = self.generate_discovery_explanation(vuln_data)
        
        # Generate advanced PoC
        print("🛠️ Creating advanced PoC...")
        advanced_poc = self.generate_advanced_poc(vuln_data)
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"vuln_analysis_{vuln_id}_{timestamp}.md"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Vulnerability Analysis Report\n\n")
            f.write(f"**Vulnerability ID:** {vuln_id}\n")
            f.write(f"**Target:** {vuln_data['domain']}\n")
            f.write(f"**Type:** {vuln_data['vulnerability_type']}\n")
            f.write(f"**Severity:** {vuln_data['severity']}\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            f.write("## 🔍 Discovery Analysis\n\n")
            f.write(discovery_analysis)
            f.write("\n\n---\n\n")
            f.write("## 🛠️ Advanced Proof of Concept\n\n")
            f.write(advanced_poc)
        
        print(f"\n✅ Analysis complete! Report saved to: {output_file}")
        
        # Display summary
        print("\n" + "=" * 60)
        print("📄 VULNERABILITY SUMMARY")
        print("=" * 60)
        print(discovery_analysis[:500] + "..." if len(discovery_analysis) > 500 else discovery_analysis)

    def list_vulnerabilities(self):
        """List available vulnerabilities"""
        vulns = self.get_vulnerability_from_db()
        if not vulns:
            print("❌ No vulnerabilities found in database")
            return
        
        print("\n📋 Available Vulnerabilities:")
        print("=" * 60)
        for i, vuln in enumerate(vulns, 1):
            print(f"{i:2d}. ID: {vuln[0]} | {vuln[1]} | {vuln[2]} | {vuln[3]} | {vuln[4]}")
        print()

    def interactive_mode(self):
        """Interactive vulnerability analysis"""
        print("\n🎯 GEMINI VULNERABILITY REPRODUCTION ASSISTANT")
        print("=" * 60)
        
        while True:
            print("\nChoose an option:")
            print("1. List available vulnerabilities")
            print("2. Analyze specific vulnerability")
            print("3. Analyze latest vulnerability")
            print("4. Exit")
            
            choice = input("\nEnter choice (1-4): ").strip()
            
            if choice == '1':
                self.list_vulnerabilities()
            
            elif choice == '2':
                vuln_id = input("Enter vulnerability ID: ").strip()
                try:
                    vuln_id = int(vuln_id)
                    self.analyze_and_reproduce(vuln_id)
                except ValueError:
                    print("❌ Invalid vulnerability ID")
            
            elif choice == '3':
                vulns = self.get_vulnerability_from_db()
                if vulns:
                    latest_id = vulns[0][0]
                    print(f"Analyzing latest vulnerability (ID: {latest_id})")
                    self.analyze_and_reproduce(latest_id)
                else:
                    print("❌ No vulnerabilities found")
            
            elif choice == '4':
                print("👋 Goodbye!")
                break
            
            else:
                print("❌ Invalid choice")

def main():
    parser = argparse.ArgumentParser(description='Gemini-powered vulnerability reproduction assistant')
    parser.add_argument('--vuln-id', type=int, help='Specific vulnerability ID to analyze')
    parser.add_argument('--list', action='store_true', help='List available vulnerabilities')
    parser.add_argument('--latest', action='store_true', help='Analyze latest vulnerability')
    parser.add_argument('--interactive', action='store_true', help='Interactive mode')
    
    args = parser.parse_args()
    
    analyzer = GeminiVulnAnalyzer()
    
    if args.list:
        analyzer.list_vulnerabilities()
    elif args.vuln_id:
        analyzer.analyze_and_reproduce(args.vuln_id)
    elif args.latest:
        vulns = analyzer.get_vulnerability_from_db()
        if vulns:
            analyzer.analyze_and_reproduce(vulns[0][0])
        else:
            print("❌ No vulnerabilities found")
    else:
        analyzer.interactive_mode()

if __name__ == "__main__":
    main()
