# 🎯 Kali Linux Optimized Bug Bounty Framework

A modern, AI-powered bug bounty hunting framework with autonomous vulnerability discovery, real-time monitoring, and interactive AI reasoning.

## 🚀 Features

### 🤖 AI-Powered Bug Hunting
- **Autonomous Workflows**: AI-driven vulnerability discovery and exploitation
- **Gemini AI Integration**: Advanced reasoning and decision-making
- **Context-Aware Chat**: Interactive AI assistant for workflow control
- **Real-time Reasoning**: Live AI decision logs and explanations

### 📊 Modern Dashboard
- **Enhanced UI**: Dark theme with responsive design
- **Live Monitoring**: Real-time system resources and tool status
- **Workflow Visualization**: Step-by-step progress tracking
- **Performance Metrics**: Comprehensive statistics and analytics

### 🛠️ Kali Linux Optimization
- **Tool Detection**: Automatic Kali tool availability checking
- **System Diagnostics**: CPU, memory, network monitoring
- **Performance Optimization**: Resource management and tuning
- **Error Handling**: Robust subprocess management with retries

### 🔍 Behind the Scenes
- **AI Reasoning Logs**: Detailed AI decision-making process
- **Decision Trees**: Visual representation of AI choices
- **Workflow Control**: Chat-based workflow management
- **Interactive Debugging**: Real-time AI state monitoring

## 📋 Requirements

- Python 3.8+
- Flask
- psutil
- requests
- Kali Linux (recommended) or Windows with tools installed

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd examples/bug_bounty
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the application**
   ```bash
   python main.py
   ```

4. **Access the dashboards**
   - Main Dashboard: http://localhost:5000
   - Behind the Scenes: http://localhost:5000/behind-scenes

## 🎯 Usage

### Main Dashboard
1. **Submit Target**: Enter domain and scope
2. **Monitor Progress**: Watch live logs and system resources
3. **View Results**: Check discovered vulnerabilities and reports

### Behind the Scenes
1. **AI Reasoning**: Monitor AI decision-making process
2. **Interactive Chat**: Control workflow via natural language
3. **System State**: View current AI state and confidence

### Chat Commands
```
pause workflow          - Pause current workflow
resume workflow         - Resume paused workflow
skip to exploitation    - Jump to exploitation phase
change tool to sqlmap   - Switch to specific tool
summarize              - Get workflow summary
what step              - Show current step
```

## 📁 Project Structure

```
examples/bug_bounty/
├── main.py                 # Main Flask application
├── kali_optimizer.py       # System optimization and tool detection
├── autonomous_bug_hunter.py # AI-powered bug hunting logic
├── subprocess_handler.py   # Robust subprocess management
├── templates/
│   ├── enhanced_dashboard.html    # Main dashboard UI
│   └── behind_scenes.html         # AI reasoning dashboard
├── test_behind_scenes.py   # Test suite for AI features
├── test_windows_compatible.py # Windows compatibility tests
├── USER_GUIDE.md          # Comprehensive user guide
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🔧 API Endpoints

### Dashboard APIs
- `GET /api/diagnostics` - System diagnostics
- `GET /api/tools/status` - Tool availability
- `GET /api/programs` - List programs
- `GET /api/vulnerabilities` - List vulnerabilities
- `GET /api/logs` - Execution logs

### AI APIs
- `GET /api/reasoning-logs` - AI reasoning history
- `GET /api/ai-state` - Current AI state
- `GET /api/decision-tree` - AI decision tree
- `POST /api/chat` - Chat with AI
- `GET /api/chat-history` - Chat history

### Control APIs
- `POST /api/simulate-activity` - Simulate AI activity
- `POST /api/update-phase` - Update workflow phase
- `POST /api/reset-ai-state` - Reset AI state

## 🧪 Testing

### Run All Tests
```bash
python test_behind_scenes.py
```

### Windows Compatibility
```bash
python test_windows_compatible.py
```

## 🛠️ Troubleshooting

### Common Issues
1. **Server won't start**: Check if port 5000 is in use
2. **Tools not found**: Ensure Kali tools are installed and in PATH
3. **Database errors**: Delete `bug_bounty.db` and restart

### Debug Mode
- Check browser console for JavaScript errors
- Monitor terminal output for Python errors
- Use test scripts to verify functionality

## 🎯 Best Practices

### Target Selection
- Start with test domains (e.g., `testphp.vulnweb.com`)
- Use proper scope to avoid unauthorized testing
- Document findings for reporting

### AI Interaction
- Be patient with AI responses
- Use clear commands for workflow control
- Monitor reasoning logs to understand decisions
- Ask for explanations when needed

### System Monitoring
- Watch live logs for real-time updates
- Check system resources to avoid overload
- Monitor tool status to ensure availability
- Review performance metrics for optimization

## 🔒 Security Notes

- This tool is for authorized security testing only
- Always obtain proper permission before testing
- Follow responsible disclosure practices
- Respect rate limits and system resources

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- Check the `USER_GUIDE.md` for detailed documentation
- Review the test scripts for usage examples
- Monitor the terminal output for error messages

---

**Happy Bug Hunting! 🐛✨**
