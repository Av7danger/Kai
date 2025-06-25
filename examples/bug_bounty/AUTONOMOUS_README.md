# Autonomous Bug Bounty Hunter with Gemini AI

A fully autonomous bug bounty hunting system powered by Google Gemini AI, designed for intelligent, adaptive, and comprehensive security testing with minimal human intervention.

## 🎯 Features

### **Autonomous Intelligence**
- **Self-Adapting Workflows**: AI dynamically adjusts testing strategy based on findings
- **Intelligent Scope Management**: Automatic validation and enforcement of bug bounty scope
- **Smart Decision Making**: AI-powered prioritization and task selection
- **Adaptive Learning**: System improves based on previous findings and feedback

### **Advanced Process Management**
- **Intelligent Error Handling**: Graceful recovery from failures with context-aware retry logic
- **Comprehensive Logging**: Multi-level logging with session tracking and metrics
- **Resource Management**: Memory and process monitoring with automatic optimization
- **Graceful Shutdown**: Clean interruption handling with result preservation

### **Professional Reporting**
- **Structured Vulnerability Reports**: Industry-standard bug bounty report format
- **Executive Summaries**: Business-focused impact analysis
- **Technical Documentation**: Detailed reproduction steps and remediation guidance
- **Metrics and Analytics**: Performance tracking and success rate analysis

## 🚀 Quick Start

### 1. Setup Environment
```bash
# Run the setup script
python setup_bug_bounty.py

# Or install manually
pip install cai-framework
```

### 2. Configure API Keys
```bash
# Copy environment template
cp .env.example .env

# Add your Gemini API key
GOOGLE_API_KEY=your_gemini_api_key_here
```

### 3. Create Scope Configuration
```bash
# Generate scope template
python autonomous_controller.py --create-template

# Edit the generated file with your bug bounty program details
# Example: bug_bounty_scope.yaml
```

### 4. Run Autonomous Hunt
```bash
# Start fully autonomous hunt
python autonomous_controller.py --config bug_bounty_scope.yaml
```

## 📋 Scope Configuration

Create a detailed scope configuration file (`bug_bounty_scope.yaml`):

```yaml
# Bug Bounty Program Scope Configuration

targets:
  - "example.com"
  - "api.example.com"
  - "staging.example.com"

in_scope:
  - "*.example.com"
  - "example.com"
  - "api.example.com"
  - "mobile.example.com"

out_of_scope:
  - "mail.example.com"
  - "internal.example.com"
  - "*.internal.example.com"
  - "admin.example.com"

allowed_methods:
  - "GET"
  - "POST"
  - "PUT"
  - "DELETE"
  - "PATCH"
  - "OPTIONS"

forbidden_paths:
  - "/admin/delete"
  - "/admin/reset"
  - "/admin/users/delete"
  - "/system/shutdown"

# Testing Configuration
rate_limit: 10              # Requests per second
max_depth: 3               # Maximum crawling depth
timeout: 7200              # Session timeout (2 hours)
business_hours_only: false # Respect business hours
safe_mode: true           # Extra safety checks

# Advanced Options
stealth_mode: true        # Use stealth techniques
user_agent_rotation: true # Rotate user agents
proxy_rotation: false    # Use proxy rotation
```

## 🧠 Autonomous Workflow

The system executes a comprehensive 5-phase autonomous workflow:

### **Phase 1: Intelligence Gathering**
- OSINT collection and target validation
- Technology stack identification
- Attack surface mapping
- Business context analysis
- Scope validation and expansion

### **Phase 2: Adaptive Reconnaissance**
- Multi-technique subdomain enumeration
- Intelligent port scanning
- API endpoint discovery
- Content discovery with smart wordlists
- Certificate and historical data analysis

### **Phase 3: Smart Vulnerability Discovery**
- Technology-specific vulnerability testing
- Business logic flaw analysis
- Authentication bypass testing
- Input validation testing (XXS, SQLi, etc.)
- Custom payload generation

### **Phase 4: Intelligent Exploitation**
- Proof-of-concept enhancement
- Impact demonstration
- Business risk calculation
- Remediation guidance generation
- False positive validation

### **Phase 5: Automated Reporting**
- Structured vulnerability reports
- Executive summaries
- Technical documentation
- Next steps generation
- Metrics compilation

---

**⚖️ Legal Notice**: This tool is designed for authorized security testing only. Users are responsible for ensuring proper authorization and compliance with applicable laws and regulations. Always follow responsible disclosure practices.
