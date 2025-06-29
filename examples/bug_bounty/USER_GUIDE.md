# 🎯 Kali Linux Optimized Bug Bounty Framework - User Guide

## 🚀 Quick Start

### 1. Start the Application
```bash
cd examples/bug_bounty
python main.py
```

### 2. Access the Dashboards
- **Main Dashboard**: http://localhost:5000
- **Behind the Scenes**: http://localhost:5000/behind-scenes

---

## 📊 Main Dashboard Features

### 🎯 Submit Target
1. **Target Domain**: Enter the domain you want to test (e.g., `example.com`)
2. **Scope**: Define the scope (e.g., `*.example.com`, `api.example.com`)
3. **Click "🚀 Start Hunting"** to begin the autonomous bug hunting process

### 🛠️ Tool Status
- **Green**: Tool is available and ready
- **Red**: Tool is missing or not installed
- **Yellow**: Tool needs updates
- **Blue**: Tool is currently running

### 📋 Live Logs
- Real-time execution logs
- Color-coded by severity (Info, Warning, Error, Success)
- Auto-scrolling with latest activities

### 📊 System Resources
- **CPU Usage**: Current processor utilization
- **Memory Usage**: RAM consumption
- **Network Status**: Connection status
- **Tools Available**: Number of ready tools

---

## 🔍 Behind the Scenes Dashboard

### 🧠 Gemini AI Reasoning
- **Live reasoning logs** showing AI decision-making
- **Analysis entries**: AI analyzing targets and data
- **Decision entries**: AI making workflow choices
- **Execution entries**: AI performing actions
- **Error entries**: Issues encountered and resolutions

### 🌳 AI Decision Tree
- **Condition nodes**: AI evaluating scenarios
- **Action nodes**: AI executing decisions
- **Result nodes**: Outcomes of AI actions
- **Timeline**: Chronological decision flow

### 🤖 System State
- **Current Phase**: Active workflow step
- **Active Tools**: Currently running tools
- **AI Confidence**: Confidence level (0-100%)
- **Memory Usage**: System resource consumption

### ⏱️ Workflow Timeline
- **Step-by-step progression** through the bug hunting process
- **Real-time updates** as workflow advances
- **Status indicators** for each step

---

## 💬 Interactive Chat with Gemini AI

### 🎮 Workflow Control Commands
```
pause workflow          - Pause the current workflow
resume workflow         - Resume the paused workflow
skip to exploitation    - Jump to exploitation phase
rerun reconnaissance    - Re-run the reconnaissance step
change tool to sqlmap   - Switch to using sqlmap
summarize              - Get a summary of recent actions
what step              - Show current workflow step
show me the workflow   - Display workflow status
```

### 🧠 Context-Aware Questions
```
Why did you do that?    - Explain the last action
What's next?           - Show the next step
What tools are you using? - List current tools
How confident are you?  - Show AI confidence level
```

### 💡 Tips for Effective Chat
- **Be specific**: "Why did you choose nuclei?" vs "Why?"
- **Use commands**: Type exact commands for workflow control
- **Ask follow-ups**: Build on previous questions
- **Check status**: Use "what step" to understand current state

---

## 🔧 Advanced Features

### 🎭 Activity Simulation
- Click "Refresh" to simulate new AI activity
- Watch reasoning logs update in real-time
- See decision trees grow with new choices

### 📈 Performance Metrics
- **Vulnerabilities Found**: Total discovered
- **AI Decisions Made**: Number of AI choices
- **Tools Executed**: Tools used in workflow
- **Execution Time**: Time taken for operations
- **Success Rate**: Percentage of successful operations

### 🔄 Phase Management
- **Automatic progression** through workflow phases
- **Manual phase control** via chat commands
- **Phase summaries** and status updates

---

## 🛠️ Troubleshooting

### ❌ Common Issues

#### Server Won't Start
```bash
# Check if port 5000 is in use
netstat -an | findstr :5000

# Kill process using port 5000 (Windows)
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

#### Tools Not Found
- Ensure you're on Kali Linux or have the tools installed
- Check tool paths in system PATH
- Some tools may be limited on Windows

#### Database Errors
```bash
# Remove and recreate database
rm bug_bounty.db
python main.py
```

### 🔍 Debug Mode
- Check browser console for JavaScript errors
- Monitor terminal output for Python errors
- Use the test scripts to verify functionality

---

## 📋 Test Scripts

### 🧪 Run All Tests
```bash
python test_behind_scenes.py
```

### 🔍 Individual Tests
```bash
# Test reasoning logs
curl http://localhost:5000/api/reasoning-logs

# Test AI state
curl http://localhost:5000/api/ai-state

# Test chat
curl -X POST http://localhost:5000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What step are you on?"}'
```

---

## 🎯 Best Practices

### 🎯 Target Selection
- **Start with test domains** (e.g., `testphp.vulnweb.com`)
- **Use proper scope** to avoid unauthorized testing
- **Document your findings** for reporting

### 🤖 AI Interaction
- **Be patient** with AI responses
- **Use clear commands** for workflow control
- **Monitor reasoning logs** to understand AI decisions
- **Ask for explanations** when AI makes unexpected choices

### 📊 Monitoring
- **Watch live logs** for real-time updates
- **Check system resources** to avoid overload
- **Monitor tool status** to ensure availability
- **Review performance metrics** for optimization

---

## 🔗 API Endpoints

### 📊 Dashboard APIs
- `GET /api/diagnostics` - System diagnostics
- `GET /api/tools/status` - Tool availability
- `GET /api/programs` - List programs
- `GET /api/vulnerabilities` - List vulnerabilities
- `GET /api/logs` - Execution logs

### 🧠 AI APIs
- `GET /api/reasoning-logs` - AI reasoning history
- `GET /api/ai-state` - Current AI state
- `GET /api/decision-tree` - AI decision tree
- `POST /api/chat` - Chat with AI
- `GET /api/chat-history` - Chat history

### 🎭 Control APIs
- `POST /api/simulate-activity` - Simulate AI activity
- `POST /api/update-phase` - Update workflow phase
- `POST /api/reset-ai-state` - Reset AI state

---

## 🎉 Getting Help

### 📚 Documentation
- Check this guide for common questions
- Review the code comments for technical details
- Use the test scripts to verify functionality

### 🐛 Reporting Issues
1. Check the troubleshooting section
2. Run the test scripts to isolate the problem
3. Check browser console and terminal output
4. Document the steps to reproduce the issue

### 💡 Tips for Success
- **Start small**: Test with simple targets first
- **Learn the workflow**: Understand each phase before advancing
- **Use the chat**: Ask Gemini for explanations and guidance
- **Monitor resources**: Keep an eye on system performance
- **Document everything**: Record your findings and decisions

---

## 🚀 Next Steps

1. **Explore the dashboards** and familiarize yourself with the interface
2. **Try the chat commands** to control the workflow
3. **Run a test program** with a safe target domain
4. **Monitor the behind-the-scenes** to understand AI reasoning
5. **Experiment with different scopes** and workflow types
6. **Customize the system** based on your needs

**Happy Bug Hunting! 🐛✨** 