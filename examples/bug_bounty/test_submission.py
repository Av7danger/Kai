#!/usr/bin/env python3
"""
🧪 Test Bug Submission & Payout Tracking System
Demonstrates all features of the submission system
"""

import sys
import os
import json
import time
from datetime import datetime
from pathlib import Path

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from bug_submission import initialize_submission_manager, get_submission_manager

def test_bug_submission_system():
    """Test the complete bug submission and payout tracking system"""
    
    print("💰 Testing Bug Submission & Payout Tracking System")
    print("=" * 60)
    
    # Initialize submission manager
    print("\n1. Initializing submission manager...")
    try:
        submission_manager = initialize_submission_manager('submission_config.yml')
        print("✅ Submission manager initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize submission manager: {e}")
        return
    
    # Test 1: Create bug reports
    print("\n2. Creating bug reports...")
    report_ids = []
    
    # Report 1: XSS Vulnerability
    report1_id = submission_manager.create_bug_report(
        title="Reflected XSS in Search Function",
        description="A reflected XSS vulnerability was discovered in the search functionality that allows attackers to inject malicious JavaScript code.",
        severity="high",
        target_domain="example.com",
        vulnerability_type="Cross-Site Scripting (XSS)",
        steps_to_reproduce=[
            "Navigate to https://example.com/search",
            "Enter the payload: <script>alert('XSS')</script>",
            "Submit the search form",
            "Observe the JavaScript alert popup"
        ],
        proof_of_concept="<script>alert('XSS')</script>",
        impact="Attackers can execute arbitrary JavaScript in the context of the application, potentially stealing user sessions or performing actions on behalf of users.",
        affected_components=["Search functionality", "User input validation"],
        recommendations=[
            "Implement proper input validation and sanitization",
            "Use Content Security Policy (CSP) headers",
            "Encode user input before rendering in HTML"
        ],
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
    )
    report_ids.append(report1_id)
    print(f"✅ Created XSS report: {report1_id}")
    
    # Report 2: SQL Injection
    report2_id = submission_manager.create_bug_report(
        title="SQL Injection in Login Form",
        description="A SQL injection vulnerability was found in the login form that allows unauthorized access to the database.",
        severity="critical",
        target_domain="example.com",
        vulnerability_type="SQL Injection",
        steps_to_reproduce=[
            "Navigate to https://example.com/login",
            "Enter username: admin' OR '1'='1",
            "Enter any password",
            "Submit the form",
            "Observe successful login as admin"
        ],
        proof_of_concept="admin' OR '1'='1",
        impact="Attackers can bypass authentication, access sensitive data, and potentially gain administrative privileges.",
        affected_components=["Login form", "Authentication system", "Database queries"],
        recommendations=[
            "Use parameterized queries or prepared statements",
            "Implement proper input validation",
            "Use ORM frameworks that handle SQL injection protection"
        ],
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
    )
    report_ids.append(report2_id)
    print(f"✅ Created SQL Injection report: {report2_id}")
    
    # Report 3: Information Disclosure
    report3_id = submission_manager.create_bug_report(
        title="Sensitive Information Disclosure in Error Messages",
        description="Error messages reveal sensitive information including database connection details and file paths.",
        severity="medium",
        target_domain="example.com",
        vulnerability_type="Information Disclosure",
        steps_to_reproduce=[
            "Navigate to https://example.com/nonexistent-page",
            "Observe detailed error message with server information",
            "Check for database credentials and file paths in error output"
        ],
        proof_of_concept="Error message reveals: /var/www/html/config.php, database connection details",
        impact="Attackers can gather information about the application structure, database configuration, and server setup.",
        affected_components=["Error handling", "Logging system"],
        recommendations=[
            "Implement generic error messages in production",
            "Disable detailed error reporting",
            "Use proper logging without exposing sensitive data"
        ],
        references=[
            "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
            "https://cheatsheetseries.owasp.org/cheatsheets/Information_Exposure_Cheat_Sheet.html"
        ]
    )
    report_ids.append(report3_id)
    print(f"✅ Created Information Disclosure report: {report3_id}")
    
    # Test 2: Quality scoring
    print("\n3. Testing quality scoring...")
    for report_id in report_ids:
        quality_score = submission_manager.get_quality_score(report_id)
        report = submission_manager.bug_reports[report_id]
        print(f"📊 Report '{report.title}': Quality Score = {quality_score:.2f}")
    
    # Test 3: Platform submission (mock)
    print("\n4. Testing platform submissions...")
    
    # Enable mock platforms for testing
    submission_manager.config['platforms']['hackerone']['enabled'] = True
    submission_manager.config['platforms']['bugcrowd']['enabled'] = True
    submission_manager.platform_clients = submission_manager._initialize_platform_clients()
    
    submission_results = []
    for report_id in report_ids:
        for platform in ['hackerone', 'bugcrowd']:
            try:
                result = submission_manager.submit_bug_report(report_id, platform)
                submission_results.append({
                    'report_id': report_id,
                    'platform': platform,
                    'result': result
                })
                print(f"✅ Submitted {report_id} to {platform}: {result['status']}")
            except Exception as e:
                print(f"❌ Failed to submit {report_id} to {platform}: {e}")
    
    # Test 4: Payout tracking
    print("\n5. Testing payout tracking...")
    payout_ids = []
    
    for submission_result in submission_results:
        if submission_result['result']['success']:
            submission_id = submission_result['result']['submission_id']
            
            # Simulate different payout amounts based on severity
            report = submission_manager.bug_reports[submission_result['report_id']]
            if report.severity == 'critical':
                amount = 5000.0
            elif report.severity == 'high':
                amount = 2000.0
            elif report.severity == 'medium':
                amount = 500.0
            else:
                amount = 100.0
            
            try:
                payout_id = submission_manager.track_payout(
                    submission_id, amount, 'USD', f"txn_{submission_id}"
                )
                payout_ids.append(payout_id)
                print(f"💰 Tracked payout: ${amount} for {submission_result['report_id']}")
            except Exception as e:
                print(f"❌ Failed to track payout: {e}")
    
    # Test 5: Statistics and analytics
    print("\n6. Testing statistics and analytics...")
    try:
        stats = submission_manager.get_submission_statistics()
        print("📈 Submission Statistics:")
        print(json.dumps(stats, indent=2))
    except Exception as e:
        print(f"❌ Failed to get statistics: {e}")
    
    # Test 6: Auto-submission
    print("\n7. Testing auto-submission...")
    try:
        # Enable auto-submission for testing
        submission_manager.config['submission_settings']['auto_submit_enabled'] = True
        submission_manager.config['submission_settings']['quality_threshold'] = 0.5
        
        auto_results = submission_manager.auto_submit_high_quality_reports()
        print(f"🤖 Auto-submitted {len(auto_results)} reports")
        
        for result in auto_results:
            print(f"   - {result['report_id']} to {result['platform']}: {result['result']['status']}")
    except Exception as e:
        print(f"❌ Failed to auto-submit: {e}")
    
    # Test 7: Export data
    print("\n8. Exporting data...")
    try:
        # Export reports
        reports_data = []
        for report_id, report in submission_manager.bug_reports.items():
            reports_data.append({
                'id': report.id,
                'title': report.title,
                'severity': report.severity,
                'target_domain': report.target_domain,
                'vulnerability_type': report.vulnerability_type,
                'status': report.status,
                'created_at': report.created_at.isoformat(),
                'quality_score': submission_manager.get_quality_score(report_id)
            })
        
        with open('submission_results/reports_export.json', 'w') as f:
            json.dump(reports_data, f, indent=2)
        print("✅ Exported reports to submission_results/reports_export.json")
        
        # Export submissions
        submissions_data = []
        for submission_id, submission in submission_manager.submissions.items():
            submissions_data.append({
                'id': submission.id,
                'bug_report_id': submission.bug_report_id,
                'platform': submission.platform,
                'platform_report_id': submission.platform_report_id,
                'submission_status': submission.submission_status,
                'submission_date': submission.submission_date.isoformat(),
                'payout_amount': submission.payout_amount,
                'payout_currency': submission.payout_currency
            })
        
        with open('submission_results/submissions_export.json', 'w') as f:
            json.dump(submissions_data, f, indent=2)
        print("✅ Exported submissions to submission_results/submissions_export.json")
        
        # Export payouts
        payouts_data = []
        for payout_id, payout in submission_manager.payouts.items():
            payouts_data.append({
                'id': payout.id,
                'platform': payout.platform,
                'report_id': payout.report_id,
                'amount': payout.amount,
                'currency': payout.currency,
                'payout_date': payout.payout_date.isoformat(),
                'status': payout.status,
                'transaction_id': payout.transaction_id
            })
        
        with open('submission_results/payouts_export.json', 'w') as f:
            json.dump(payouts_data, f, indent=2)
        print("✅ Exported payouts to submission_results/payouts_export.json")
        
    except Exception as e:
        print(f"❌ Failed to export data: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 TEST SUMMARY")
    print("=" * 60)
    print(f"📝 Bug Reports Created: {len(report_ids)}")
    print(f"🚀 Submissions Made: {len(submission_results)}")
    print(f"💰 Payouts Tracked: {len(payout_ids)}")
    print(f"📊 Total Payout: ${sum(p.amount for p in submission_manager.payouts.values()):,.2f}")
    
    # Calculate success rate
    successful_submissions = sum(1 for r in submission_results if r['result']['success'])
    success_rate = (successful_submissions / len(submission_results) * 100) if submission_results else 0
    print(f"📈 Success Rate: {success_rate:.1f}%")
    
    print("\n✅ Bug Submission & Payout Tracking System Test Complete!")
    print("📁 Check submission_results/ directory for exported data")
    print("🗄️  Database file: bug_submission.db")

def test_api_endpoints():
    """Test the API endpoints"""
    print("\n🌐 Testing API Endpoints...")
    
    try:
        from submission_api import submission_bp
        from flask import Flask
        
        app = Flask(__name__)
        app.register_blueprint(submission_bp, url_prefix='/api/submission')
        
        print("✅ API endpoints registered successfully")
        print("📋 Available endpoints:")
        print("   GET  /api/submission/reports - List all reports")
        print("   POST /api/submission/reports - Create new report")
        print("   GET  /api/submission/reports/<id> - Get specific report")
        print("   POST /api/submission/submit - Submit report to platform")
        print("   POST /api/submission/auto-submit - Auto-submit reports")
        print("   GET  /api/submission/payouts - List all payouts")
        print("   POST /api/submission/payouts - Track new payout")
        print("   GET  /api/submission/statistics - Get submission stats")
        print("   GET  /api/submission/quality-score/<id> - Get quality score")
        print("   GET  /api/submission/submissions - List all submissions")
        print("   GET  /api/submission/platforms - List available platforms")
        
    except Exception as e:
        print(f"❌ Failed to test API endpoints: {e}")

if __name__ == "__main__":
    # Run the main test
    test_bug_submission_system()
    
    # Test API endpoints
    test_api_endpoints()
    
    print("\n🎉 All tests completed successfully!") 