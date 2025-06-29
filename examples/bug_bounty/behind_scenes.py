#!/usr/bin/env python3
"""
Behind the Scenes - AI Reasoning & System Internals Dashboard
Provides detailed view of Gemini AI reasoning, system internals, and interactive chat
"""

from flask import Flask, render_template, jsonify, request
import json
import time
from datetime import datetime
import threading
import queue

app = Flask(__name__)

# Global state for reasoning logs and chat
reasoning_logs = []
chat_history = []
ai_state = {
    'current_phase': 'Initialization',
    'confidence': 85,
    'decisions_made': 0,
    'tools_active': [],
    'reasoning_context': {}
}

class AIReasoningEngine:
    """Simulates Gemini AI reasoning and decision making"""
    
    def __init__(self):
        self.reasoning_queue = queue.Queue()
        self.decision_history = []
        self.current_context = {}
        
    def add_reasoning_log(self, log_type, message, context=None):
        """Add a reasoning log entry"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = {
            'timestamp': timestamp,
            'type': log_type,
            'message': message,
            'context': context or {}
        }
        reasoning_logs.append(log_entry)
        
        # Keep only last 100 entries
        if len(reasoning_logs) > 100:
            reasoning_logs.pop(0)
            
        return log_entry
    
    def make_decision(self, decision_type, reasoning, options=None):
        """Simulate AI decision making"""
        decision = {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'type': decision_type,
            'reasoning': reasoning,
            'options': options or [],
            'selected': None
        }
        
        # Simulate decision logic
        if decision_type == 'workflow_selection':
            decision['selected'] = 'reconnaissance_first'
            decision['reasoning'] += ' - Chose reconnaissance-first due to unknown attack surface'
        elif decision_type == 'tool_selection':
            decision['selected'] = 'nuclei'
            decision['reasoning'] += ' - Selected nuclei for comprehensive vulnerability scanning'
        elif decision_type == 'priority_assignment':
            decision['selected'] = 'critical'
            decision['reasoning'] += ' - Prioritized critical vulnerabilities for immediate attention'
            
        self.decision_history.append(decision)
        ai_state['decisions_made'] += 1
        
        return decision
    
    def update_context(self, new_context):
        """Update AI reasoning context"""
        self.current_context.update(new_context)
        ai_state['reasoning_context'] = self.current_context.copy()
    
    def generate_response(self, user_message):
        """Generate AI response to user questions"""
        lower_message = user_message.lower()
        
        # Predefined responses based on keywords
        responses = {
            'why': {
                'message': 'I chose this approach because it maximizes efficiency while minimizing false positives. The reconnaissance-first strategy allows me to understand the attack surface before launching targeted attacks.',
                'reasoning': 'User asked about decision reasoning - provided strategic explanation'
            },
            'how': {
                'message': 'I use a combination of static analysis, dynamic testing, and machine learning to identify vulnerabilities. Each decision is based on the current context and historical success patterns.',
                'reasoning': 'User asked about methodology - explained technical approach'
            },
            'what': {
                'message': 'I\'m currently analyzing the target domain, mapping the attack surface, and selecting the most effective testing tools based on the discovered technologies.',
                'reasoning': 'User asked about current status - provided activity update'
            },
            'change': {
                'message': 'I can adapt my strategy based on your input. What specific changes would you like me to make to the current workflow?',
                'reasoning': 'User requested strategy change - offered flexibility'
            },
            'status': {
                'message': f'Current status: {ai_state["current_phase"]}. I\'ve made {ai_state["decisions_made"]} decisions with {ai_state["confidence"]}% confidence.',
                'reasoning': 'User asked for status - provided current state summary'
            },
            'tools': {
                'message': f'I\'m currently using {", ".join(ai_state["tools_active"]) if ai_state["tools_active"] else "standard toolset"}. These tools were selected based on the target\'s technology stack.',
                'reasoning': 'User asked about tools - listed current toolset'
            },
            'confidence': {
                'message': f'My confidence level is currently {ai_state["confidence"]}%. This is based on the quality of reconnaissance data and the success rate of similar targets.',
                'reasoning': 'User asked about confidence - provided confidence metrics'
            },
            'time': {
                'message': 'Estimated completion time: 15-20 minutes. This includes vulnerability discovery, exploitation verification, and report generation.',
                'reasoning': 'User asked about timing - provided time estimates'
            }
        }
        
        # Find matching response
        for key, response in responses.items():
            if key in lower_message:
                self.add_reasoning_log('chat', response['reasoning'])
                return response['message']
        
        # Default response
        default_response = {
            'message': 'I understand your question. I\'m currently focused on optimizing the testing strategy for maximum vulnerability discovery. Is there something specific about my current approach you\'d like me to explain or modify?',
            'reasoning': 'User asked general question - provided helpful default response'
        }
        self.add_reasoning_log('chat', default_response['reasoning'])
        return default_response['message']

# Initialize AI reasoning engine
ai_engine = AIReasoningEngine()

@app.route('/behind-scenes')
def behind_scenes():
    """Serve the behind the scenes dashboard"""
    return render_template('behind_scenes.html')

@app.route('/api/reasoning-logs')
def get_reasoning_logs():
    """Get current reasoning logs"""
    return jsonify({
        'logs': reasoning_logs[-50:],  # Last 50 entries
        'total': len(reasoning_logs)
    })

@app.route('/api/ai-state')
def get_ai_state():
    """Get current AI state"""
    return jsonify(ai_state)

@app.route('/api/decision-tree')
def get_decision_tree():
    """Get AI decision tree"""
    decisions = ai_engine.decision_history[-20:]  # Last 20 decisions
    return jsonify({
        'decisions': decisions,
        'total_decisions': len(ai_engine.decision_history)
    })

@app.route('/api/chat', methods=['POST'])
def chat_with_ai():
    """Handle chat interaction with AI"""
    data = request.get_json()
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'error': 'No message provided'}), 400
    
    # Add user message to chat history
    chat_entry = {
        'timestamp': datetime.now().isoformat(),
        'sender': 'user',
        'message': user_message
    }
    chat_history.append(chat_entry)
    
    # Generate AI response
    ai_response = ai_engine.generate_response(user_message)
    
    # Add AI response to chat history
    ai_chat_entry = {
        'timestamp': datetime.now().isoformat(),
        'sender': 'ai',
        'message': ai_response
    }
    chat_history.append(ai_chat_entry)
    
    # Keep only last 100 chat messages
    if len(chat_history) > 100:
        chat_history[:] = chat_history[-100:]
    
    return jsonify({
        'user_message': user_message,
        'ai_response': ai_response,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/chat-history')
def get_chat_history():
    """Get chat history"""
    return jsonify({
        'messages': chat_history[-50:],  # Last 50 messages
        'total': len(chat_history)
    })

@app.route('/api/simulate-activity')
def simulate_activity():
    """Simulate AI activity for demonstration"""
    import random
    
    # Simulate different types of reasoning
    reasoning_types = ['analysis', 'decision', 'reasoning', 'execution']
    reasoning_messages = [
        'Analyzing new endpoint discovered during reconnaissance',
        'Deciding to prioritize XSS testing based on technology stack',
        'Reasoning: This target shows signs of custom authentication',
        'Analysis: Multiple subdomains detected, expanding scope',
        'Decision: Switching to manual testing for complex vulnerabilities',
        'Execution: Running nuclei with custom templates',
        'Analysis: SQL injection vulnerability confirmed',
        'Decision: Prioritizing critical vulnerabilities',
        'Reasoning: Target uses modern framework, focusing on logic flaws',
        'Execution: Deploying payload generation for XSS testing'
    ]
    
    # Add random reasoning log
    log_type = random.choice(reasoning_types)
    message = random.choice(reasoning_messages)
    ai_engine.add_reasoning_log(log_type, message)
    
    # Update AI state
    ai_state['confidence'] = max(50, min(95, ai_state['confidence'] + random.randint(-5, 5)))
    ai_state['tools_active'] = random.sample(['nuclei', 'ffuf', 'sqlmap', 'gobuster', 'nikto'], random.randint(2, 4))
    
    # Simulate decision making
    if random.random() < 0.3:  # 30% chance of making a decision
        decision_types = ['workflow_selection', 'tool_selection', 'priority_assignment']
        decision_type = random.choice(decision_types)
        reasoning = f"AI decision: {decision_type.replace('_', ' ')}"
        ai_engine.make_decision(decision_type, reasoning)
    
    return jsonify({
        'status': 'Activity simulated',
        'new_logs': len(reasoning_logs),
        'ai_state': ai_state
    })

@app.route('/api/update-phase')
def update_phase():
    """Update current AI phase"""
    phases = [
        'Initialization',
        'Target Analysis', 
        'Reconnaissance',
        'Vulnerability Discovery',
        'Exploitation Testing',
        'Report Generation',
        'Completed'
    ]
    
    current_index = phases.index(ai_state['current_phase'])
    if current_index < len(phases) - 1:
        ai_state['current_phase'] = phases[current_index + 1]
        ai_engine.add_reasoning_log('phase_change', f'Phase changed to: {ai_state["current_phase"]}')
    
    return jsonify({
        'current_phase': ai_state['current_phase'],
        'phase_index': phases.index(ai_state['current_phase'])
    })

@app.route('/api/reset-ai-state')
def reset_ai_state():
    """Reset AI state for fresh start"""
    global reasoning_logs, chat_history, ai_state
    
    reasoning_logs.clear()
    chat_history.clear()
    ai_state = {
        'current_phase': 'Initialization',
        'confidence': 85,
        'decisions_made': 0,
        'tools_active': [],
        'reasoning_context': {}
    }
    
    ai_engine.decision_history.clear()
    ai_engine.current_context.clear()
    
    # Add initial reasoning log
    ai_engine.add_reasoning_log('initialization', 'AI state reset - starting fresh analysis')
    
    return jsonify({
        'status': 'AI state reset successfully',
        'ai_state': ai_state
    })

if __name__ == '__main__':
    # Add some initial reasoning logs
    ai_engine.add_reasoning_log('initialization', 'Behind the Scenes dashboard initialized')
    ai_engine.add_reasoning_log('analysis', 'System ready for interactive AI debugging')
    ai_engine.add_reasoning_log('decision', 'Ready to respond to user questions and provide insights')
    
    print("🔍 Behind the Scenes Dashboard")
    print("Access at: http://localhost:5000/behind-scenes")
    print("Features:")
    print("- Real-time AI reasoning logs")
    print("- Interactive chat with Gemini AI")
    print("- Decision tree visualization")
    print("- System state monitoring")
    print("- Performance metrics")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 