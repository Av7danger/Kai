#!/usr/bin/env python3
"""
Test script for Behind the Scenes functionality
Tests AI reasoning, chat interaction, and system internals
"""

import requests
import json
import time
import sys
from datetime import datetime

BASE_URL = "http://localhost:5000"

def test_api_endpoint(endpoint, method="GET", data=None):
    """Test an API endpoint"""
    response = None
    try:
        url = f"{BASE_URL}{endpoint}"
        if method == "GET":
            response = requests.get(url)
        elif method == "POST":
            response = requests.post(url, json=data)
        
        if response and response.status_code == 200:
            print(f"✅ {method} {endpoint} - Success")
            return response.json()
        else:
            status_code = response.status_code if response else "No response"
            print(f"❌ {method} {endpoint} - Failed: {status_code}")
            return None
    except Exception as e:
        print(f"❌ {method} {endpoint} - Error: {str(e)}")
        return None

def test_reasoning_logs():
    """Test reasoning logs functionality"""
    print("\n🧠 Testing Reasoning Logs...")
    
    # Get reasoning logs
    logs = test_api_endpoint("/api/reasoning-logs")
    if logs:
        print(f"   Found {logs.get('total', 0)} reasoning logs")
        for log in logs.get('logs', [])[:3]:  # Show first 3 logs
            print(f"   - [{log.get('timestamp')}] {log.get('type')}: {log.get('message')}")

def test_ai_state():
    """Test AI state functionality"""
    print("\n🤖 Testing AI State...")
    
    # Get AI state
    state = test_api_endpoint("/api/ai-state")
    if state:
        print(f"   Current Phase: {state.get('current_phase')}")
        print(f"   Confidence: {state.get('confidence')}%")
        print(f"   Decisions Made: {state.get('decisions_made')}")
        print(f"   Active Tools: {', '.join(state.get('tools_active', []))}")

def test_decision_tree():
    """Test decision tree functionality"""
    print("\n🌳 Testing Decision Tree...")
    
    # Get decision tree
    tree = test_api_endpoint("/api/decision-tree")
    if tree:
        print(f"   Total Decisions: {tree.get('total_decisions', 0)}")
        for decision in tree.get('decisions', [])[:3]:  # Show first 3 decisions
            print(f"   - [{decision.get('timestamp')}] {decision.get('type')}: {decision.get('reasoning')}")

def test_chat_functionality():
    """Test chat interaction with AI"""
    print("\n💬 Testing Chat Functionality...")
    
    # Test chat history
    history = test_api_endpoint("/api/chat-history")
    if history:
        print(f"   Chat History: {history.get('total', 0)} messages")
    
    # Test sending a message
    test_messages = [
        "Why did you choose this approach?",
        "What tools are you currently using?",
        "What's your current confidence level?",
        "How long will this take?",
        "Can you change your strategy?"
    ]
    
    for message in test_messages:
        print(f"\n   Testing: '{message}'")
        response = test_api_endpoint("/api/chat", "POST", {"message": message})
        if response:
            print(f"   AI Response: {response.get('ai_response', 'No response')}")

def test_simulation():
    """Test activity simulation"""
    print("\n🎭 Testing Activity Simulation...")
    
    # Simulate activity
    for i in range(3):
        print(f"   Simulation {i+1}/3...")
        result = test_api_endpoint("/api/simulate-activity")
        if result:
            print(f"   - New logs: {result.get('new_logs', 0)}")
            print(f"   - Confidence: {result.get('ai_state', {}).get('confidence', 0)}%")
        time.sleep(1)

def test_phase_updates():
    """Test phase progression"""
    print("\n🔄 Testing Phase Updates...")
    
    # Update phases
    for i in range(3):
        result = test_api_endpoint("/api/update-phase")
        if result:
            print(f"   Phase {i+1}: {result.get('current_phase')}")

def test_reset_functionality():
    """Test AI state reset"""
    print("\n🔄 Testing Reset Functionality...")
    
    # Reset AI state
    result = test_api_endpoint("/api/reset-ai-state")
    if result:
        print(f"   Reset successful: {result.get('status')}")
        print(f"   New confidence: {result.get('ai_state', {}).get('confidence', 0)}%")

def test_integration():
    """Test integration with main dashboard APIs"""
    print("\n🔗 Testing Integration...")
    
    # Test main dashboard APIs
    endpoints = [
        "/api/diagnostics",
        "/api/tools/status", 
        "/api/programs",
        "/api/vulnerabilities",
        "/api/logs",
        "/api/system/status",
        "/api/health"
    ]
    
    for endpoint in endpoints:
        test_api_endpoint(endpoint)

def main():
    """Main test function"""
    print("🔍 Behind the Scenes Test Suite")
    print("=" * 50)
    
    # Check if server is running
    try:
        health = requests.get(f"{BASE_URL}/api/health", timeout=5)
        if health.status_code != 200:
            print("❌ Server is not responding properly")
            return
    except:
        print("❌ Server is not running. Please start the server first:")
        print("   python main.py")
        return
    
    print("✅ Server is running")
    
    # Run all tests
    test_reasoning_logs()
    test_ai_state()
    test_decision_tree()
    test_chat_functionality()
    test_simulation()
    test_phase_updates()
    test_reset_functionality()
    test_integration()
    
    print("\n" + "=" * 50)
    print("🎉 Behind the Scenes Test Suite Completed!")
    print("\nAccess the dashboard at:")
    print(f"   Main Dashboard: {BASE_URL}")
    print(f"   Behind Scenes: {BASE_URL}/behind-scenes")

if __name__ == "__main__":
    main() 