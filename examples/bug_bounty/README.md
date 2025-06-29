# 🐛 Kali Bug Hunter

**Advanced Bug Bounty Framework - Optimized for Kali Linux**

A streamlined, modern bug bounty framework designed specifically for Kali Linux with an intuitive web interface, automated scanning, and comprehensive reporting.

## ✨ Features

### 🎯 Core Features
- **Target Management** - Add and manage bug bounty targets
- **Automated Scanning** - Comprehensive vulnerability scanning with Kali tools
- **Real-time Dashboard** - Modern web interface with live updates
- **Vulnerability Tracking** - Track and categorize discovered vulnerabilities
- **Report Generation** - Professional HTML reports with detailed findings
- **Kali Linux Optimization** - Optimized for Kali Linux tools and environment

### 🛠️ Integrated Tools
- **Nmap** - Port scanning and service detection
- **Nuclei** - Vulnerability scanning
- **Subfinder** - Subdomain enumeration
- **Amass** - Advanced subdomain discovery
- **FFuf** - Web fuzzing and directory discovery
- **Httpx** - HTTP probing and web discovery

### 🎨 Modern Interface
- **Dark Theme** - Professional dark interface optimized for security work
- **Responsive Design** - Works on desktop, tablet, and mobile
- **Real-time Updates** - Live status updates and progress tracking
- **Intuitive Navigation** - Clean, organized interface

## 🚀 Quick Start

### Prerequisites
- Kali Linux (recommended) or Ubuntu/Debian
- Python 3.8+
- Internet connection for tool installation

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd bug_bounty
   ```

2. **Run the setup script**
   ```bash
   chmod +x kali_setup.sh
   ./kali_setup.sh
   ```

3. **Start the application**
   ```bash
   ./start.sh
   ```

4. **Access the dashboard**
   - Open your browser and go to: `http://localhost:5000`
   - Login with: `username=kali, password=kali`

## 📁 Project Structure

```
bug_bounty/
├── kali_bug_hunter.py          # Main application
├── kali_config.yml             # Configuration file
├── kali_setup.sh               # Setup script
├── start.sh                    # Start script
├── stop.sh                     # Stop script
├── status.sh                   # Status script
├── test_kali_tools.sh          # Tool testing script
├── templates/                  # Web templates
│   ├── kali_dashboard.html     # Main dashboard
│   └── kali_login.html         # Login page
├── kali_results/               # Output directory
│   ├── reports/                # Generated reports
│   ├── scans/                  # Scan results
│   ├── payloads/               # Generated payloads
│   └── exports/                # Data exports
├── logs/                       # Application logs
└── venv/                       # Python virtual environment
```

## 🔧 Configuration

The application is configured via `kali_config.yml`:

```yaml
kali:
  tools_path: "/usr/bin"
  enable_kali_tools: true
  auto_update: true
  theme: "dark"

scanning:
  default_scan_type: "comprehensive"
  max_concurrent_scans: 3
  scan_timeout: 3600
  enable_ai_analysis: true

tools:
  nmap: true
  nuclei: true
  ffuf: true
  subfinder: true
  amass: true
  httpx: true

dashboard:
  port: 5000
  host: "0.0.0.0"
  debug: false
  theme: "dark"

security:
  enable_encryption: true
  session_timeout: 3600
  max_login_attempts: 5
```

## 🎯 Usage

### Adding Targets
1. Go to the dashboard
2. Enter the target domain in the "Target Management" section
3. Optionally add program name and reward range
4. Click "Add Target"

### Starting Scans
1. Find your target in the targets list
2. Click the "Scan" button
3. Monitor progress in real-time
4. View results in the "Vulnerabilities" section

### Viewing Reports
- Reports are automatically generated after scans complete
- Access reports from the `kali_results/reports/` directory
- Reports include detailed vulnerability information and recommendations

## 🛠️ Management Commands

```bash
# Start the application
./start.sh

# Stop the application
./stop.sh

# Check application status
./status.sh

# Test Kali tools availability
./test_kali_tools.sh

# View logs
tail -f logs/kali_bug_hunter.log
```

## 🔍 Scanning Types

### Quick Scan
- Basic port scanning
- Common vulnerability checks
- Fast execution (5-10 minutes)

### Comprehensive Scan
- Full subdomain enumeration
- Deep vulnerability scanning
- Technology fingerprinting
- Extended execution (15-30 minutes)

### Custom Scan
- User-defined scan parameters
- Selective tool usage
- Configurable timeouts

## 📊 Dashboard Features

### Statistics Overview
- Total targets
- Active scans
- Vulnerabilities found
- Available Kali tools

### Target Management
- Add new targets
- View target status
- Start scans
- Track progress

### Vulnerability Tracking
- Severity classification
- CVSS scoring
- Status tracking
- Detailed descriptions

### Tool Status
- Real-time tool availability
- Installation status
- Version information

## 🔒 Security Features

- **Session Management** - Secure user sessions with timeout
- **Input Validation** - Comprehensive input sanitization
- **SQL Injection Protection** - Parameterized queries
- **XSS Protection** - Output encoding
- **CSRF Protection** - Token-based protection
- **Rate Limiting** - Request throttling

## 🐛 Troubleshooting

### Common Issues

**Dashboard not accessible**
```bash
# Check if service is running
./status.sh

# Check firewall settings
sudo ufw status

# Check port availability
netstat -tlnp | grep 5000
```

**Tools not found**
```bash
# Test tool availability
./test_kali_tools.sh

# Install missing tools
sudo apt update
sudo apt install <tool-name>
```

**Permission errors**
```bash
# Fix file permissions
chmod 755 *.sh
chmod 644 kali_config.yml

# Fix directory permissions
chmod 755 kali_results/
```

### Logs
- Application logs: `logs/kali_bug_hunter.log`
- System logs: `journalctl -u kali-bug-hunter.service`

## 🔄 Updates

### Updating the Application
```bash
# Pull latest changes
git pull origin main

# Reinstall dependencies
source venv/bin/activate
pip install -r requirements.txt

# Restart the service
./stop.sh
./start.sh
```

### Updating Kali Tools
```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Update Go tools
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

## 🆘 Support

- **Documentation**: Check this README and inline code comments
- **Issues**: Report bugs and feature requests via GitHub issues
- **Community**: Join our community discussions

## 🎉 Acknowledgments

- Kali Linux team for the excellent security tools
- ProjectDiscovery for Nuclei and other tools
- The open-source security community

---

**Happy Bug Hunting! 🐛🔍**
