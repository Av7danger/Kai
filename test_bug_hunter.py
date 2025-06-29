#!/usr/bin/env python3
"""
Test the REAL bug hunting functionality
"""

import requests
import json
import time

def test_bug_hunter():
    """Test the bug hunting functionality"""
    base_url = "http://localhost:8000"
    
    print("🔍 Testing Kai Bug Hunter - REAL Bug Hunting Tool")
    print("=" * 50)
    
    # Test 1: Check system status
    print("\n1. Checking system status...")
    try:
        response = requests.get(f"{base_url}/api/system-status")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ System Status: CPU {data['system_resources']['cpu_usage']}%, Memory {data['system_resources']['memory_usage']}%")
        else:
            print(f"❌ System status failed: {response.status_code}")
    except Exception as e:
        print(f"❌ System status error: {e}")
    
    # Test 2: Start a real bug hunt
    print("\n2. Starting REAL bug hunt...")
    try:
        hunt_data = {
            "target": "httpbin.org",  # Safe test target
            "scope": "*.httpbin.org",
            "ai_provider": "gemini"
        }
        
        response = requests.post(
            f"{base_url}/api/start-hunt",
            json=hunt_data,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                workflow_id = data["workflow_id"]
                print(f"✅ Bug hunt started! Workflow ID: {workflow_id}")
                
                # Monitor the workflow
                print("\n3. Monitoring bug hunt progress...")
                for i in range(10):  # Check for 10 iterations
                    time.sleep(2)
                    try:
                        status_response = requests.get(f"{base_url}/api/workflow/{workflow_id}")
                        if status_response.status_code == 200:
                            workflow_data = status_response.json()
                            if workflow_data.get("success"):
                                workflow = workflow_data["workflow"]
                                status = workflow.get("status", "unknown")
                                results = workflow.get("results", [])
                                
                                print(f"   Status: {status}")
                                if results:
                                    latest_result = results[-1]
                                    print(f"   Latest: {latest_result.get('message', 'N/A')}")
                                
                                if status == "completed":
                                    print("\n🎯 BUG HUNT COMPLETED!")
                                    print("=" * 30)
                                    
                                    # Show findings
                                    subdomains = workflow.get("subdomains", [])
                                    open_ports = workflow.get("open_ports", {})
                                    vulnerabilities = workflow.get("vulnerabilities", [])
                                    
                                    print(f"📊 FINDINGS:")
                                    print(f"   Subdomains found: {len(subdomains)}")
                                    if subdomains:
                                        print(f"   Subdomains: {', '.join(subdomains[:5])}")
                                    
                                    print(f"   Open ports: {len(open_ports)}")
                                    if open_ports:
                                        print(f"   Ports: {list(open_ports.keys())}")
                                    
                                    print(f"   Vulnerabilities found: {len(vulnerabilities)}")
                                    if vulnerabilities:
                                        print("   🔴 VULNERABILITIES:")
                                        for vuln in vulnerabilities:
                                            print(f"      - {vuln['type']} ({vuln['severity']}): {vuln['description']}")
                                    else:
                                        print("   ✅ No vulnerabilities found")
                                    
                                    break
                                elif status == "failed":
                                    print(f"❌ Bug hunt failed: {workflow.get('error', 'Unknown error')}")
                                    break
                            else:
                                print(f"❌ Status check failed: {workflow_data.get('error', 'Unknown error')}")
                        else:
                            print(f"❌ Status check failed: {status_response.status_code}")
                    except Exception as e:
                        print(f"❌ Status check error: {e}")
            else:
                print(f"❌ Bug hunt failed: {data.get('error', 'Unknown error')}")
        else:
            print(f"❌ Bug hunt request failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Bug hunt error: {e}")
    
    print("\n" + "=" * 50)
    print("🏁 Test completed!")

if __name__ == "__main__":
    test_bug_hunter() 