#!/usr/bin/env python3
"""
Test the AI-Powered Bug Hunting functionality
"""

import requests
import json
import time

def test_ai_bug_hunter():
    """Test the AI-powered bug hunting functionality"""
    base_url = "http://localhost:8000"
    
    print("🤖 Testing AI-Powered Kai Bug Hunter")
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
    
    # Test 2: Start AI-powered bug hunt
    print("\n2. Starting AI-powered bug hunt...")
    try:
        # Example bug bounty program data
        hunt_data = {
            "target": "httpbin.org",
            "program_overview": """
            This is a major e-commerce platform with millions of users.
            The application handles sensitive user data including payment information,
            personal details, and order history. The platform uses modern web technologies
            including React frontend, Node.js backend, and various third-party integrations.
            """,
            "scope": "*.httpbin.org, api.httpbin.org, admin.httpbin.org",
            "bounty_ranges": "Critical: $5000-10000, High: $1000-5000, Medium: $500-1000, Low: $100-500",
            "focus_areas": "Authentication bypass, payment processing vulnerabilities, data exposure, API security",
            "ai_provider": "gemini"
        }
        
        response = requests.post(
            f"{base_url}/api/ai-hunt",
            json=hunt_data,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                workflow_id = data["workflow_id"]
                print(f"✅ AI-powered bug hunt started! Workflow ID: {workflow_id}")
                
                # Monitor the workflow
                print("\n3. Monitoring AI-powered bug hunt progress...")
                for i in range(15):  # Check for 15 iterations
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
                                    print("\n🎯 AI-POWERED BUG HUNT COMPLETED!")
                                    print("=" * 40)
                                    
                                    # Show AI analysis
                                    ai_analysis = workflow.get("ai_analysis", {})
                                    if ai_analysis:
                                        print("🤖 AI ANALYSIS:")
                                        print(f"   Priority vulnerabilities: {', '.join(ai_analysis.get('priority_vulnerabilities', [])[:3])}")
                                        print(f"   Attack vectors: {', '.join(ai_analysis.get('attack_vectors', [])[:3])}")
                                        print(f"   High-priority endpoints: {', '.join(ai_analysis.get('high_priority_endpoints', [])[:3])}")
                                    
                                    # Show findings
                                    subdomains = workflow.get("subdomains", [])
                                    open_ports = workflow.get("open_ports", {})
                                    vulnerabilities = workflow.get("vulnerabilities", [])
                                    ai_report = workflow.get("ai_report", {})
                                    
                                    print(f"\n📊 FINDINGS:")
                                    print(f"   Subdomains found: {len(subdomains)}")
                                    if subdomains:
                                        print(f"   Subdomains: {', '.join(subdomains[:5])}")
                                    
                                    print(f"   Open ports: {len(open_ports)}")
                                    if open_ports:
                                        print(f"   Ports: {list(open_ports.keys())}")
                                    
                                    print(f"   Total vulnerabilities: {len(vulnerabilities)}")
                                    
                                    # Show AI-guided findings
                                    ai_guided_vulns = [v for v in vulnerabilities if v.get("ai_guided")]
                                    print(f"   AI-guided findings: {len(ai_guided_vulns)}")
                                    
                                    if vulnerabilities:
                                        print("   🔴 VULNERABILITIES:")
                                        for vuln in vulnerabilities:
                                            ai_marker = "🤖" if vuln.get("ai_guided") else "🔍"
                                            print(f"      {ai_marker} {vuln['type']} ({vuln['severity']}): {vuln['description']}")
                                    else:
                                        print("   ✅ No vulnerabilities found")
                                    
                                    # Show potential bounty
                                    if ai_report:
                                        potential_bounty = ai_report.get("potential_bounty", 0)
                                        print(f"\n💰 POTENTIAL BOUNTY: ${potential_bounty}")
                                        
                                        recommendations = ai_report.get("recommendations", [])
                                        if recommendations:
                                            print("   📋 RECOMMENDATIONS:")
                                            for rec in recommendations:
                                                print(f"      • {rec}")
                                    
                                    break
                                elif status == "failed":
                                    print(f"❌ AI bug hunt failed: {workflow.get('error', 'Unknown error')}")
                                    break
                            else:
                                print(f"❌ Status check failed: {workflow_data.get('error', 'Unknown error')}")
                        else:
                            print(f"❌ Status check failed: {status_response.status_code}")
                    except Exception as e:
                        print(f"❌ Status check error: {e}")
            else:
                print(f"❌ AI bug hunt failed: {data.get('error', 'Unknown error')}")
        else:
            print(f"❌ AI bug hunt request failed: {response.status_code}")
    except Exception as e:
        print(f"❌ AI bug hunt error: {e}")
    
    print("\n" + "=" * 50)
    print("🏁 AI Test completed!")

if __name__ == "__main__":
    test_ai_bug_hunter() 