#!/usr/bin/env python3
"""
Example: AI-Powered Bug Hunting with Real Bug Bounty Program
This demonstrates how to explain everything about a bug bounty program to Gemini
and let it intelligently hunt for bugs.
"""

import requests
import json
import time

def example_ai_bug_hunt():
    """Example of AI-powered bug hunting with comprehensive program analysis"""
    
    print("🎯 AI-POWERED BUG HUNTING EXAMPLE")
    print("=" * 60)
    print("This example shows how to explain a bug bounty program to AI")
    print("and let it intelligently hunt for vulnerabilities.")
    print()
    
    # Example 1: E-commerce Platform
    print("📦 EXAMPLE 1: E-commerce Platform")
    print("-" * 40)
    
    ecommerce_hunt = {
        "target": "httpbin.org",  # Using httpbin.org for safe testing
        "program_overview": """
        SHOPIFY-STYLE E-COMMERCE PLATFORM
        
        This is a major e-commerce platform similar to Shopify with millions of users.
        The application handles:
        - Payment processing (credit cards, PayPal, crypto)
        - User accounts and authentication
        - Order management and inventory
        - Customer data (addresses, payment info, order history)
        - Admin panel for store owners
        - API for mobile apps and third-party integrations
        - File uploads for product images
        
        Business Impact: High-value target due to financial transactions and sensitive data.
        """,
        "scope": "*.httpbin.org, api.httpbin.org, admin.httpbin.org, *.api.httpbin.org",
        "bounty_ranges": "Critical: $10,000-25,000, High: $2,000-10,000, Medium: $500-2,000, Low: $100-500",
        "focus_areas": "Payment processing, authentication bypass, data exposure, API security, file upload vulnerabilities, admin panel access",
        "ai_provider": "gemini"
    }
    
    run_ai_hunt("E-commerce Platform", ecommerce_hunt)
    
    print("\n" + "=" * 60)
    
    # Example 2: Banking Application
    print("🏦 EXAMPLE 2: Banking Application")
    print("-" * 40)
    
    banking_hunt = {
        "target": "httpbin.org",  # Using httpbin.org for safe testing
        "program_overview": """
        ONLINE BANKING PLATFORM
        
        This is a modern online banking application serving thousands of customers.
        The platform includes:
        - Account management and balance checking
        - Money transfers and payments
        - Investment portfolio management
        - Loan applications and processing
        - Mobile banking app backend
        - Two-factor authentication
        - Transaction history and statements
        
        Business Impact: Extremely high-value due to direct financial access and regulatory requirements.
        """,
        "scope": "*.httpbin.org, secure.httpbin.org, api.httpbin.org, mobile.httpbin.org",
        "bounty_ranges": "Critical: $25,000-50,000, High: $5,000-25,000, Medium: $1,000-5,000, Low: $200-1,000",
        "focus_areas": "Account takeover, money transfer vulnerabilities, authentication bypass, session management, API security, data encryption",
        "ai_provider": "gemini"
    }
    
    run_ai_hunt("Banking Application", banking_hunt)
    
    print("\n" + "=" * 60)
    
    # Example 3: Healthcare Platform
    print("🏥 EXAMPLE 3: Healthcare Platform")
    print("-" * 40)
    
    healthcare_hunt = {
        "target": "httpbin.org",  # Using httpbin.org for safe testing
        "program_overview": """
        HEALTHCARE MANAGEMENT SYSTEM
        
        This is a comprehensive healthcare platform used by hospitals and clinics.
        The system manages:
        - Patient records and medical history
        - Appointment scheduling and management
        - Prescription and medication tracking
        - Lab results and medical imaging
        - Doctor and staff management
        - Insurance and billing processing
        - Telemedicine functionality
        
        Business Impact: Critical due to HIPAA compliance and patient privacy requirements.
        """,
        "scope": "*.httpbin.org, patient.httpbin.org, doctor.httpbin.org, admin.httpbin.org",
        "bounty_ranges": "Critical: $15,000-30,000, High: $3,000-15,000, Medium: $750-3,000, Low: $150-750",
        "focus_areas": "Patient data exposure, authentication bypass, session hijacking, API security, file upload vulnerabilities, admin access",
        "ai_provider": "gemini"
    }
    
    run_ai_hunt("Healthcare Platform", healthcare_hunt)

def run_ai_hunt(name, hunt_data):
    """Run an AI-powered bug hunt"""
    print(f"Starting AI hunt for: {name}")
    print(f"Target: {hunt_data['target']}")
    print(f"Focus: {hunt_data['focus_areas']}")
    print()
    
    try:
        # Start the AI hunt
        response = requests.post(
            "http://localhost:8000/api/ai-hunt",
            json=hunt_data,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                workflow_id = data["workflow_id"]
                print(f"✅ AI hunt started! Workflow: {workflow_id}")
                
                # Monitor progress
                print("🔄 Monitoring AI analysis and hunting progress...")
                for i in range(20):  # Monitor for up to 40 seconds
                    time.sleep(2)
                    
                    status_response = requests.get(f"http://localhost:8000/api/workflow/{workflow_id}")
                    if status_response.status_code == 200:
                        workflow_data = status_response.json()
                        if workflow_data.get("success"):
                            workflow = workflow_data["workflow"]
                            status = workflow.get("status", "unknown")
                            results = workflow.get("results", [])
                            
                            if results:
                                latest_result = results[-1]
                                print(f"   Step {latest_result.get('step', '?')}: {latest_result.get('message', 'N/A')}")
                            
                            if status == "completed":
                                print("\n🎯 AI HUNT COMPLETED!")
                                print("-" * 30)
                                
                                # Show AI analysis
                                ai_analysis = workflow.get("ai_analysis", {})
                                if ai_analysis:
                                    print("🤖 AI ANALYSIS RESULTS:")
                                    print(f"   Priority vulnerabilities: {', '.join(ai_analysis.get('priority_vulnerabilities', [])[:3])}")
                                    print(f"   Attack vectors: {', '.join(ai_analysis.get('attack_vectors', [])[:3])}")
                                    print(f"   High-priority endpoints: {', '.join(ai_analysis.get('high_priority_endpoints', [])[:3])}")
                                
                                # Show findings
                                subdomains = workflow.get("subdomains", [])
                                open_ports = workflow.get("open_ports", {})
                                vulnerabilities = workflow.get("vulnerabilities", [])
                                ai_report = workflow.get("ai_report", {})
                                
                                print(f"\n📊 HUNTING RESULTS:")
                                print(f"   Subdomains: {len(subdomains)}")
                                print(f"   Open ports: {len(open_ports)}")
                                print(f"   Total vulnerabilities: {len(vulnerabilities)}")
                                
                                # Show AI-guided findings
                                ai_guided_vulns = [v for v in vulnerabilities if v.get("ai_guided")]
                                print(f"   AI-guided findings: {len(ai_guided_vulns)}")
                                
                                if vulnerabilities:
                                    print("   🔴 VULNERABILITIES FOUND:")
                                    for vuln in vulnerabilities[:5]:  # Show first 5
                                        ai_marker = "🤖" if vuln.get("ai_guided") else "🔍"
                                        print(f"      {ai_marker} {vuln['type']} ({vuln['severity']}): {vuln['description'][:60]}...")
                                
                                # Show potential bounty
                                if ai_report:
                                    potential_bounty = ai_report.get("potential_bounty", 0)
                                    print(f"\n💰 POTENTIAL BOUNTY: ${potential_bounty:,}")
                                    
                                    recommendations = ai_report.get("recommendations", [])
                                    if recommendations:
                                        print("   📋 AI RECOMMENDATIONS:")
                                        for rec in recommendations:
                                            print(f"      • {rec}")
                                
                                break
                            elif status == "failed":
                                print(f"❌ AI hunt failed: {workflow.get('error', 'Unknown error')}")
                                break
                        else:
                            print(f"❌ Status check failed: {workflow_data.get('error', 'Unknown error')}")
                            break
                    else:
                        print(f"❌ Status check failed: {status_response.status_code}")
                        break
            else:
                print(f"❌ AI hunt failed: {data.get('error', 'Unknown error')}")
        else:
            print(f"❌ AI hunt request failed: {response.status_code}")
    except Exception as e:
        print(f"❌ AI hunt error: {e}")
    
    print()

def show_usage_tips():
    """Show tips for using AI-powered bug hunting"""
    print("\n💡 USAGE TIPS FOR AI-POWERED BUG HUNTING:")
    print("=" * 50)
    print("1. 📝 PROGRAM OVERVIEW:")
    print("   - Describe the business context and value")
    print("   - Explain what makes the target valuable")
    print("   - Include technology stack if known")
    print("   - Mention sensitive data types")
    print()
    print("2. 🎯 SCOPE DEFINITION:")
    print("   - List all in-scope domains/subdomains")
    print("   - Include API endpoints")
    print("   - Specify mobile apps if applicable")
    print()
    print("3. 💰 BOUNTY RANGES:")
    print("   - Helps AI prioritize high-value vulnerabilities")
    print("   - Focus on critical and high severity issues")
    print()
    print("4. 🔍 FOCUS AREAS:")
    print("   - Specify business-critical functionality")
    print("   - Mention authentication, payment, data exposure")
    print("   - Include compliance requirements (HIPAA, PCI, etc.)")
    print()
    print("5. 🤖 AI ANALYSIS:")
    print("   - AI will analyze your program description")
    print("   - It will prioritize vulnerability types")
    print("   - It will focus on high-value attack vectors")
    print("   - It will test business logic flaws")
    print()
    print("6. 📊 RESULTS:")
    print("   - AI-guided findings are marked with 🤖")
    print("   - Regular findings are marked with 🔍")
    print("   - Potential bounty is calculated automatically")
    print("   - AI provides actionable recommendations")

if __name__ == "__main__":
    example_ai_bug_hunt()
    show_usage_tips() 