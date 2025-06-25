# 🎯 Bug Bounty Hunting with CAI Framework & Google Gemini

Enhanced bug bounty hunting using the CAI (Cybersecurity AI) framework with Google Gemini integration for superior vulnerability discovery and analysis.

## 🌟 Features

- **Google Gemini Integration**: Advanced AI analysis with superior pattern recognition
- **Comprehensive Toolset**: 20+ security testing tools integrated
- **Automated Workflows**: Complete bug bounty hunting pipelines
- **Intelligent Analysis**: AI-powered vulnerability correlation and false positive reduction
- **Responsible Disclosure**: Built-in reporting templates and ethics guidelines

## 🚀 Quick Setup

### 1. Run the Setup Script
```bash
python setup_bug_bounty.py
```

This will:
- Install CAI framework and dependencies
- Install bug bounty tools (subfinder, nuclei, ffuf, etc.)
- Download common wordlists
- Create configuration templates

### 2. Configure API Keys

Copy `bug_bounty_config.env` to `.env` and add your API keys:

```bash
# Primary AI Model (Recommended)
GOOGLE_API_KEY=your_google_gemini_api_key_here
CAI_MODEL=gemini/gemini-1.5-pro-latest

# Search & Intelligence
SHODAN_API_KEY=your_shodan_api_key_here
GOOGLE_SEARCH_API_KEY=your_google_search_api_key_here
GOOGLE_SEARCH_CX=your_custom_search_engine_id_here
```

### 3. Get Your Gemini API Key

1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the key to your `.env` file

## 🎯 Usage Examples

### Quick Reconnaissance
```bash
python bug_bounty_workflow.py example.com quick
```

### Full Bug Bounty Assessment
```bash
python bug_bounty_workflow.py example.com full
```

### Focused Vulnerability Hunting
```bash
# XSS hunting
python bug_bounty_workflow.py example.com xss

# SQL injection testing
python bug_bounty_workflow.py example.com sqli

# SSRF testing
python bug_bounty_workflow.py example.com ssrf

# IDOR testing
python bug_bounty_workflow.py example.com idor
```

### Using the Enhanced Agent Directly
```python
import asyncio
from gemini_bug_bounty_agent import BugBountyAgent

async def hunt():
    hunter = BugBountyAgent(["example.com", "*.example.com"])
    results = await hunter.hunt("example.com")
    print(results["findings"])

asyncio.run(hunt())
```

## 📊 Workflow Phases

### Phase 1: Reconnaissance
- **Subdomain enumeration** using multiple tools
- **Technology stack detection** and analysis
- **Initial security assessment** with Gemini AI
- **Scope expansion** based on findings

### Phase 2: Asset Discovery
- **Service discovery** and port scanning
- **Web application identification**
- **API endpoint discovery** and analysis
- **Attack surface mapping**

### Phase 3: Vulnerability Assessment
- **Automated scanning** with Nuclei
- **Directory and file discovery**
- **Parameter analysis** and injection testing
- **Technology-specific vulnerability checks**

### Phase 4: Deep Analysis
- **AI-powered correlation** of findings
- **Attack chain identification**
- **Business logic flaw analysis**
- **Risk assessment** and prioritization

### Phase 5: Reporting
- **Executive summary** generation
- **Technical report** with PoC
- **Remediation guidance**
- **Responsible disclosure** recommendations

## 🛠️ Integrated Tools

### Reconnaissance Tools
- **Subfinder**: Subdomain discovery
- **Assetfinder**: Asset enumeration
- **Amass**: Network mapping
- **Shodan**: Internet-wide scanning
- **Wayback URLs**: Historical URL discovery

### Vulnerability Scanners
- **Nuclei**: Template-based vulnerability scanning
- **SQLMap**: SQL injection testing
- **FFUF**: Web fuzzing and discovery
- **Dalfox**: XSS testing
- **Custom tools**: Parameter analysis, API testing

### Analysis & Intelligence
- **Google Search**: OSINT research
- **Perplexity AI**: Enhanced research capabilities
- **Gemini AI**: Advanced pattern recognition
- **Custom analysis**: Technology detection, correlation

## 🤖 Why Gemini for Bug Bounty?

### Superior Capabilities
- **Enhanced Pattern Recognition**: Better identification of complex attack patterns
- **Reduced False Positives**: More accurate vulnerability assessment
- **Attack Chain Analysis**: Superior understanding of multi-step attacks
- **Context Awareness**: Better correlation of findings across different tools

### Optimized for Security
- **Security-focused training**: Better understanding of cybersecurity concepts
- **Code analysis**: Superior ability to analyze code for vulnerabilities
- **Payload generation**: More effective exploit payload creation
- **Report quality**: Better technical writing for vulnerability reports

## 📁 Project Structure

```
examples/bug_bounty/
├── gemini_bug_bounty_agent.py    # Main agent with Gemini integration
├── advanced_tools.py             # Enhanced security testing tools
├── bug_bounty_workflow.py        # Complete workflow automation
├── setup_bug_bounty.py          # Setup and installation script
├── .env.example                  # Configuration template
└── README.md                     # This file

Generated Results:
bug_bounty_results/
├── bb_<timestamp>/
│   ├── findings.json            # Complete results in JSON
│   ├── executive_summary.md     # Executive summary
│   ├── technical_report.md      # Detailed technical report
│   └── deep_analysis.md         # AI-powered deep analysis
```

## 🔧 Advanced Configuration

### Custom Model Configuration
```python
# Use different Gemini models
CAI_MODEL=gemini/gemini-1.5-pro-latest      # Latest Pro model
CAI_MODEL=gemini/gemini-1.5-flash-latest    # Faster, cost-effective

# Adjust model parameters
GEMINI_TEMPERATURE=0.3    # Lower for more focused responses
GEMINI_MAX_TOKENS=8192    # Adjust response length
```

### Tool Customization
```python
# Custom wordlists
WORDLISTS_DIR=/path/to/custom/wordlists

# Rate limiting
RATE_LIMIT=10            # Requests per second
MAX_THREADS=50           # Concurrent operations

# Proxy configuration (for Burp Suite integration)
HTTP_PROXY=http://127.0.0.1:8080
HTTPS_PROXY=http://127.0.0.1:8080
```

## 🛡️ Ethical Guidelines

### Scope Compliance
- Always define and respect target scope
- Obtain proper authorization before testing
- Avoid testing production systems without permission

### Responsible Disclosure
- Report vulnerabilities through proper channels
- Provide clear reproduction steps
- Suggest remediation guidance
- Maintain confidentiality of findings

### Impact Consideration
- Avoid destructive testing
- Minimize impact on target systems
- Use stealth techniques when appropriate
- Respect rate limits and system resources

## 📚 Learning Resources

### Bug Bounty Platforms
- [HackerOne](https://hackerone.com/) - Leading bug bounty platform
- [Bugcrowd](https://bugcrowd.com/) - Crowdsourced security platform
- [Intigriti](https://intigriti.com/) - European bug bounty platform

### Training & Practice
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Free web security training
- [HackTheBox](https://hackthebox.eu/) - Penetration testing labs
- [TryHackMe](https://tryhackme.com/) - Cybersecurity training platform

### CAI Framework
- [CAI Documentation](https://github.com/aliasrobotics/cai) - Official documentation
- [CAI Research Paper](https://arxiv.org/pdf/2504.06017) - Technical details
- [CAI Examples](../../../examples/) - Additional examples and patterns

## 🆘 Troubleshooting

### Common Issues

**API Key Errors**
```bash
# Verify your Gemini API key
curl -H "Authorization: Bearer $GOOGLE_API_KEY" \
     "https://generativelanguage.googleapis.com/v1/models"
```

**Tool Installation Issues**
```bash
# Install Go tools manually
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update tool databases
nuclei -update-templates
```

**Permission Issues**
```bash
# Ensure tools are in PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Set appropriate permissions
chmod +x setup_bug_bounty.py
```

### Support

- **GitHub Issues**: [CAI Repository](https://github.com/aliasrobotics/cai/issues)
- **Discord**: [CAI Community](https://discord.gg/fnUFcTaQAC)
- **Email**: research@aliasrobotics.com

## 📜 License

This project is dual-licensed:
- **MIT License**: For research and educational use
- **Commercial License**: For commercial bug bounty operations

See the main [LICENSE](../../LICENSE) file for details.

## 🏆 Achievements

CAI Framework has demonstrated excellence in:
- HackTheBox CTF competitions (Top 1 Spain, Top 20 World)
- Real-world bug bounty discoveries
- Academic research and publications
- Community adoption and contribution

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Users are responsible for compliance with applicable laws and regulations. Always obtain proper authorization before testing systems you do not own.
