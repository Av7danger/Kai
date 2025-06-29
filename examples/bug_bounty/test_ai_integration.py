#!/usr/bin/env python3
"""
🧪 Test AI Integration
Demonstrate the AI-powered analysis functionality
"""

import json
from ai_integration import get_ai_integration
from ai_api import ai_bp
from flask import Flask

def test_ai_analysis():
    """Test AI analysis functionality"""
    print("🤖 Testing AI Integration...")
    
    # Initialize AI integration
    ai_integration = get_ai_integration()
    
    # Sample reconnaissance data
    sample_recon_data = {
        'domain': 'example.com',
        'subdomains': [
            'admin.example.com',
            'api.example.com',
            'test.example.com',
            'dev.example.com'
        ],
        'live_hosts': [
            'admin.example.com',
            'api.example.com'
        ],
        'technologies': {
            'WordPress': '5.8.1',
            'PHP': '7.4.21',
            'Apache': '2.4.41',
            'MySQL': '5.7.32'
        },
        'vulnerabilities': [
            {
                'type': 'xss',
                'title': 'Reflected XSS in search parameter',
                'severity': 'medium',
                'url': 'https://example.com/search?q=test'
            },
            {
                'type': 'sqli',
                'title': 'SQL Injection in login form',
                'severity': 'high',
                'url': 'https://admin.example.com/login'
            }
        ],
        'port_scan': {
            '80': ['http'],
            '443': ['https'],
            '22': ['ssh'],
            '3306': ['mysql']
        }
    }
    
    print("\n📊 Sample Reconnaissance Data:")
    print(json.dumps(sample_recon_data, indent=2))
    
    # Run AI analysis
    print("\n🔍 Running AI Analysis...")
    analysis_result = ai_integration.analyze_recon_data(sample_recon_data)
    
    print("\n📈 Analysis Results:")
    print(f"Target: {analysis_result['target']}")
    print(f"Risk Score: {analysis_result['risk_score']:.1f}/10")
    print(f"Timestamp: {analysis_result['timestamp']}")
    
    print("\n🔍 Key Findings:")
    for finding in analysis_result['findings']:
        print(f"  • {finding['description']} (Confidence: {finding.get('confidence', 0.8):.1f})")
    
    print("\n💡 Attack Suggestions:")
    for suggestion in analysis_result['suggestions']:
        print(f"  • {suggestion['description']}")
        if 'payloads' in suggestion:
            print(f"    Payloads: {', '.join(suggestion['payloads'][:2])}")
    
    print("\n🎯 Priority Targets:")
    for target in analysis_result['priority_targets']:
        print(f"  • {target}")
    
    # Generate custom payloads
    print("\n⚡ Generating Custom Payloads...")
    custom_payloads = ai_integration.generate_custom_payloads(analysis_result)
    
    print(f"\nGenerated {len(custom_payloads)} payloads:")
    for i, payload in enumerate(custom_payloads[:5], 1):
        print(f"  {i}. {payload}")
    
    # Generate bug report
    print("\n📝 Generating Bug Report...")
    vulnerability_data = {
        'title': 'Reflected XSS in Search Parameter',
        'description': 'A reflected XSS vulnerability was found in the search functionality',
        'severity': 'medium',
        'impact': 'Attackers can execute arbitrary JavaScript in user browsers',
        'steps': [
            'Navigate to https://example.com/search',
            'Enter payload: <script>alert("XSS")</script>',
            'Submit the search form',
            'Observe JavaScript execution'
        ],
        'poc': '<script>alert("XSS")</script>'
    }
    
    bug_report = ai_integration.generate_bug_report(vulnerability_data)
    
    print("\n📄 Generated Bug Report:")
    print(f"Title: {bug_report['title']}")
    print(f"Severity: {bug_report['severity']}")
    print(f"Impact: {bug_report['impact']}")
    print(f"Steps to Reproduce: {len(bug_report['steps_to_reproduce'])} steps")
    print(f"Recommendations: {len(bug_report['recommendations'])} suggestions")
    
    # Get statistics
    print("\n📊 AI Integration Statistics:")
    stats = ai_integration.get_statistics()
    print(f"Total Analyses: {stats['total_analyses']}")
    print(f"Total Reports: {stats['total_reports']}")
    print(f"Average Risk Score: {stats['average_risk_score']:.1f}")
    
    print("\n✅ AI Integration Test Completed!")

def test_api_endpoints():
    """Test API endpoints"""
    print("\n🌐 Testing API Endpoints...")
    
    # Create Flask app for testing
    app = Flask(__name__)
    app.register_blueprint(ai_bp, url_prefix='/api/ai')
    
    with app.test_client() as client:
        # Test analyze endpoint
        print("\n🔍 Testing /api/ai/analyze...")
        sample_data = {
            'domain': 'test.com',
            'subdomains': ['admin.test.com'],
            'vulnerabilities': [{'type': 'xss', 'severity': 'medium'}]
        }
        
        response = client.post('/api/ai/analyze', 
                             json=sample_data,
                             content_type='application/json')
        
        if response.status_code == 200:
            result = response.get_json()
            print(f"✅ Analysis successful - Risk Score: {result['analysis']['risk_score']}")
        else:
            print(f"❌ Analysis failed: {response.get_json()}")
        
        # Test payloads endpoint
        print("\n⚡ Testing /api/ai/payloads...")
        response = client.post('/api/ai/payloads',
                             json={'categories': ['xss'], 'count': 5},
                             content_type='application/json')
        
        if response.status_code == 200:
            result = response.get_json()
            print(f"✅ Generated {result['count']} payloads")
        else:
            print(f"❌ Payload generation failed: {response.get_json()}")
        
        # Test stats endpoint
        print("\n📊 Testing /api/ai/stats...")
        response = client.get('/api/ai/stats')
        
        if response.status_code == 200:
            result = response.get_json()
            print(f"✅ Stats retrieved - Total analyses: {result['statistics']['total_analyses']}")
        else:
            print(f"❌ Stats retrieval failed: {response.get_json()}")

if __name__ == '__main__':
    print("🚀 AI Integration Test Suite")
    print("=" * 50)
    
    # Test core functionality
    test_ai_analysis()
    
    # Test API endpoints
    test_api_endpoints()
    
    print("\n🎉 All tests completed!")
    print("\nNext steps:")
    print("1. Integrate AI endpoints into your main dashboard")
    print("2. Configure AI providers in ai_agent_config.yml")
    print("3. Set up environment variables for API keys")
    print("4. Run the full bug bounty framework") 