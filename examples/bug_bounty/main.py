#!/usr/bin/env python3
"""
Kali Linux Optimized Bug Bounty Framework
Autonomous AI-powered vulnerability discovery and exploitation
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import subprocess
import json
import os
import sys
import time
import threading
import queue
from datetime import datetime
import sqlite3
import uuid
from pathlib import Path

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from kali_optimizer import KaliOptimizer
from autonomous_bug_hunter import AutonomousBugHunter

app = Flask(__name__)
app.secret_key = 'kali-bug-bounty-secret-key-2024'

# Global instances
kali_optimizer = KaliOptimizer()
bug_hunter = AutonomousBugHunter()

# Global state
current_program = None
execution_logs = []
system_status = {
    'cpu_usage': 0,
    'memory_usage': 0,
    'network_status': 'Unknown',
    'disk_usage': 0
}

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

# Add after ai_state global
global_workflow_state = {
    'paused': False,
    'current_step': 'Initialization',
    'steps': [
        'Initialization',
        'Target Analysis',
        'Reconnaissance',
        'Vulnerability Discovery',
        'Exploitation Testing',
        'Report Generation',
        'Completed'
    ],
    'step_index': 0,
    'last_tool': None,
    'history': []  # List of dicts: {step, action, timestamp, details}
}

# Database setup
def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect('bug_bounty.db')
    cursor = conn.cursor()
    
    # Programs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS programs (
            id TEXT PRIMARY KEY,
            target_domain TEXT NOT NULL,
            scope TEXT,
            workflow_type TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            results TEXT
        )
    ''')
    
    # Vulnerabilities table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            program_id TEXT,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            poc TEXT,
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (program_id) REFERENCES programs (id)
        )
    ''')
    
    # Execution logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS execution_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            FOREIGN KEY (program_id) REFERENCES programs (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('enhanced_dashboard.html')

@app.route('/behind-scenes')
def behind_scenes():
    """Behind the scenes dashboard"""
    return render_template('behind_scenes.html')

@app.route('/api/diagnostics')
def get_diagnostics():
    """Get system diagnostics"""
    try:
        diagnostics = kali_optimizer.get_system_diagnostics()
        return jsonify(diagnostics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/status')
def get_tools_status():
    """Get Kali tools status"""
    try:
        tools_status = kali_optimizer.check_tools_availability()
        return jsonify(tools_status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/programs', methods=['GET', 'POST'])
def handle_programs():
    """Handle program creation and listing"""
    if request.method == 'POST':
        data = request.get_json()
        
        program_id = str(uuid.uuid4())
        target_domain = data.get('target_domain')
        scope = data.get('scope', '')
        workflow_type = data.get('workflow_type', 'autonomous')
        
        # Save to database
        conn = sqlite3.connect('bug_bounty.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO programs (id, target_domain, scope, workflow_type, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (program_id, target_domain, scope, workflow_type, 'pending'))
        conn.commit()
        conn.close()
        
        # Start execution in background
        threading.Thread(target=execute_program, args=(program_id, target_domain, scope, workflow_type)).start()
        
        return jsonify({
            'program_id': program_id,
            'status': 'started',
            'message': f'Program started for {target_domain}'
        })
    
    else:
        # GET - list programs
        conn = sqlite3.connect('bug_bounty.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM programs ORDER BY created_at DESC LIMIT 50')
        programs = []
        for row in cursor.fetchall():
            programs.append({
                'id': row[0],
                'target_domain': row[1],
                'scope': row[2],
                'workflow_type': row[3],
                'status': row[4],
                'created_at': row[5],
                'updated_at': row[6],
                'results': row[7]
            })
        conn.close()
        return jsonify(programs)

@app.route('/api/programs/<program_id>')
def get_program(program_id):
    """Get specific program details"""
    conn = sqlite3.connect('bug_bounty.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM programs WHERE id = ?', (program_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return jsonify({
            'id': row[0],
            'target_domain': row[1],
            'scope': row[2],
            'workflow_type': row[3],
            'status': row[4],
            'created_at': row[5],
            'updated_at': row[6],
            'results': row[7]
        })
    else:
        return jsonify({'error': 'Program not found'}), 404

@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Get all vulnerabilities"""
    conn = sqlite3.connect('bug_bounty.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT v.*, p.target_domain 
        FROM vulnerabilities v 
        JOIN programs p ON v.program_id = p.id 
        ORDER BY v.created_at DESC
    ''')
    
    vulnerabilities = []
    for row in cursor.fetchall():
        vulnerabilities.append({
            'id': row[0],
            'program_id': row[1],
            'type': row[2],
            'severity': row[3],
            'title': row[4],
            'description': row[5],
            'poc': row[6],
            'status': row[7],
            'created_at': row[8],
            'target_domain': row[9]
        })
    conn.close()
    return jsonify(vulnerabilities)

@app.route('/api/logs')
def get_logs():
    """Get execution logs"""
    conn = sqlite3.connect('bug_bounty.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT l.*, p.target_domain 
        FROM execution_logs l 
        JOIN programs p ON l.program_id = p.id 
        ORDER BY l.timestamp DESC 
        LIMIT 100
    ''')
    
    logs = []
    for row in cursor.fetchall():
        logs.append({
            'id': row[0],
            'program_id': row[1],
            'timestamp': row[2],
            'level': row[3],
            'message': row[4],
            'target_domain': row[5]
        })
    conn.close()
    return jsonify(logs)

@app.route('/api/system/status')
def get_system_status():
    """Get current system status"""
    return jsonify(system_status)

def execute_program(program_id, target_domain, scope, workflow_type):
    """Execute bug bounty program in background"""
    try:
        # Update status
        conn = sqlite3.connect('bug_bounty.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE programs SET status = ? WHERE id = ?', ('running', program_id))
        conn.commit()
        conn.close()
        
        # Add log entry
        add_log_entry(program_id, 'INFO', f'Starting {workflow_type} workflow for {target_domain}')
        
        # Execute based on workflow type
        if workflow_type == 'autonomous':
            results = bug_hunter.run_autonomous_workflow(target_domain, scope, program_id)
        else:
            results = bug_hunter.run_basic_workflow(target_domain, scope, program_id)
        
        # Update program with results
        conn = sqlite3.connect('bug_bounty.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE programs 
            SET status = ?, results = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', ('completed', json.dumps(results), program_id))
        conn.commit()
        conn.close()
        
        add_log_entry(program_id, 'INFO', f'Program completed successfully for {target_domain}')
        
    except Exception as e:
        # Update status on error
        conn = sqlite3.connect('bug_bounty.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE programs SET status = ? WHERE id = ?', ('error', program_id))
        conn.commit()
        conn.close()
        
        add_log_entry(program_id, 'ERROR', f'Program failed: {str(e)}')

def add_log_entry(program_id, level, message):
    """Add log entry to database"""
    conn = sqlite3.connect('bug_bounty.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO execution_logs (program_id, level, message)
        VALUES (?, ?, ?)
    ''', (program_id, level, message))
    conn.commit()
    conn.close()

@app.route('/api/optimize')
def optimize_system():
    """Run system optimization"""
    try:
        optimization_results = kali_optimizer.optimize_system()
        return jsonify({
            'status': 'success',
            'results': optimization_results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

class AIReasoningEngine:
    """Simulates Gemini AI reasoning and decision making"""
    
    def __init__(self):
        self.reasoning_queue = queue.Queue()
        self.decision_history = []
        self.current_context = {}
        self.recent_user_msgs = []
        self.recent_ai_msgs = []
        
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
    
    def add_chat_history(self, sender, message):
        if sender == 'user':
            self.recent_user_msgs.append(message)
            if len(self.recent_user_msgs) > 10:
                self.recent_user_msgs.pop(0)
        else:
            self.recent_ai_msgs.append(message)
            if len(self.recent_ai_msgs) > 10:
                self.recent_ai_msgs.pop(0)
    
    def parse_command(self, user_message):
        msg = user_message.lower().strip()
        if msg.startswith('pause workflow'):
            return 'pause'
        if msg.startswith('resume workflow'):
            return 'resume'
        if msg.startswith('skip to '):
            step = msg.replace('skip to ', '').strip().title()
            return ('skip', step)
        if msg.startswith('rerun '):
            step = msg.replace('rerun ', '').strip().title()
            return ('rerun', step)
        if msg.startswith('change tool to '):
            tool = msg.replace('change tool to ', '').strip()
            return ('change_tool', tool)
        if msg in ['what step', 'current step', 'what\'s the current step?', 'show me the workflow']:
            return 'show_workflow'
        if msg.startswith('summarize') or 'summary' in msg:
            return 'summarize'
        return None
    
    def handle_command(self, command):
        global global_workflow_state
        if command == 'pause':
            global_workflow_state['paused'] = True
            return 'Workflow paused. No further steps will be executed until resumed.'
        if command == 'resume':
            global_workflow_state['paused'] = False
            return 'Workflow resumed. Continuing from current step.'
        if isinstance(command, tuple) and command[0] == 'skip':
            step = command[1]
            if step in global_workflow_state['steps']:
                global_workflow_state['current_step'] = step
                global_workflow_state['step_index'] = global_workflow_state['steps'].index(step)
                return f'Skipped to step: {step}. Workflow updated.'
            else:
                return f'Unknown step: {step}. Valid steps: {', '.join(global_workflow_state['steps'])}'
        if isinstance(command, tuple) and command[0] == 'rerun':
            step = command[1]
            if step in global_workflow_state['steps']:
                return f'Re-running step: {step}. (Simulation only: actual rerun logic not implemented)'
            else:
                return f'Unknown step: {step}. Valid steps: {', '.join(global_workflow_state['steps'])}'
        if isinstance(command, tuple) and command[0] == 'change_tool':
            tool = command[1]
            global_workflow_state['last_tool'] = tool
            return f'Changed tool to: {tool}. All subsequent actions will use this tool where applicable.'
        if command == 'show_workflow':
            idx = global_workflow_state['step_index']
            step = global_workflow_state['current_step']
            paused = global_workflow_state['paused']
            return f'Current step: {step} (Step {idx+1}/{len(global_workflow_state["steps"])}). Workflow is {"paused" if paused else "active"}.'
        if command == 'summarize':
            hist = global_workflow_state['history'][-5:]
            if not hist:
                return 'No recent workflow actions to summarize.'
            summary = '\n'.join([f"[{h['timestamp']}] {h['step']}: {h['action']}" for h in hist])
            return f'Recent workflow summary:\n{summary}'
        return None
    
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
        
        # Context-aware follow-up
        if user_message.lower().strip() in ['why did you do that?', 'why?', 'what was the reason?']:
            if global_workflow_state['history']:
                last = global_workflow_state['history'][-1]
                reason = last.get('details', 'No details available.')
                resp = f"The last action was: {last['action']} in step {last['step']}. Reason: {reason}"
            else:
                resp = 'No recent actions to explain.'
            self.add_chat_history('ai', resp)
            return resp
        if user_message.lower().strip() in ['what\'s next?', 'next step?', 'what now?']:
            idx = global_workflow_state['step_index']
            if idx+1 < len(global_workflow_state['steps']):
                next_step = global_workflow_state['steps'][idx+1]
                resp = f"The next step is: {next_step}."
            else:
                resp = 'Workflow is at the final step.'
            self.add_chat_history('ai', resp)
            return resp
        # Clarification for ambiguous queries
        if len(user_message.split()) < 3:
            resp = 'Could you clarify your question or provide more details?'
            self.add_chat_history('ai', resp)
            return resp
        # Fallback to default
        resp = super().generate_response(user_message) if hasattr(super(), 'generate_response') else 'I am here to help with workflow and reasoning. Please ask a specific question or command.'
        self.add_chat_history('ai', resp)
        return resp

# Initialize AI reasoning engine
ai_engine = AIReasoningEngine()

# Add some initial reasoning logs
ai_engine.add_reasoning_log('initialization', 'Behind the Scenes dashboard initialized')
ai_engine.add_reasoning_log('analysis', 'System ready for interactive AI debugging')
ai_engine.add_reasoning_log('decision', 'Ready to respond to user questions and provide insights')

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
    ai_engine.add_chat_history('user', user_message)
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
    
    ai_engine.add_chat_history('ai', ai_response)
    
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
    print("🚀 Kali Linux Optimized Bug Bounty Framework")
    print("=" * 50)
    print("Features:")
    print("- Autonomous AI-powered bug hunting")
    print("- Kali Linux optimization")
    print("- Real-time system monitoring")
    print("- Enhanced dashboard with live updates")
    print("- Behind the scenes AI reasoning")
    print("=" * 50)
    print("Access the dashboard at: http://localhost:5000")
    print("Behind the scenes at: http://localhost:5000/behind-scenes")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 