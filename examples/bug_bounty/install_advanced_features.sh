#!/bin/bash

# 🎯 Bug Bounty Hunter Pro - Advanced Features Installation Script
# This script installs all dependencies for the enhanced bug bounty framework

echo "🎯 Bug Bounty Hunter Pro - Advanced Installation"
echo "=================================================="
echo ""

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_warning "This script should not be run as root. Please run as a regular user."
   exit 1
fi

# Update system packages
print_info "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install essential system packages
print_info "Installing essential system packages..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    nmap \
    masscan \
    gobuster \
    ffuf \
    subfinder \
    amass \
    httpx \
    nuclei \
    sqlmap \
    nikto \
    dirb \
    dirbuster \
    wfuzz \
    hydra \
    john \
    hashcat \
    metasploit-framework \
    burpsuite \
    zaproxy \
    wireshark \
    tcpdump \
    netcat \
    socat \
    dnsutils \
    whois \
    openssl \
    jq \
    tree \
    vim \
    nano \
    tmux \
    screen

print_status "System packages installed successfully"

# Install Go tools for advanced reconnaissance
print_info "Installing Go and Go-based security tools..."
sudo rm -rf /usr/local/go
wget -O /tmp/go.tar.gz https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc

# Install Go-based tools
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
mkdir -p $GOPATH/bin

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf@latest
go install github.com/OJ/gobuster/v3@latest

print_status "Go tools installed successfully"

# Install Python virtual environment and dependencies
print_info "Setting up Python environment..."
cd "$(dirname "$0")"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_status "Virtual environment created"
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
print_info "Installing Python dependencies..."
pip install -r requirements.txt

# Install additional advanced dependencies
pip install \
    flask \
    requests \
    beautifulsoup4 \
    lxml \
    selenium \
    scrapy \
    dnspython \
    python-whois \
    python-nmap \
    shodan \
    censys \
    virustotal-api \
    sublist3r \
    dirsearch \
    paramiko \
    fabric \
    celery \
    redis \
    gunicorn \
    uwsgi \
    sqlalchemy \
    alembic \
    cryptography \
    pyjwt \
    bcrypt \
    passlib \
    python-multipart \
    python-jose \
    fastapi \
    uvicorn \
    streamlit \
    plotly \
    pandas \
    numpy \
    scikit-learn \
    matplotlib \
    seaborn \
    opencv-python \
    pillow \
    reportlab \
    fpdf2 \
    jinja2 \
    markupsafe \
    wtforms \
    flask-wtf \
    flask-sqlalchemy \
    flask-migrate \
    flask-login \
    flask-mail \
    click \
    colorama \
    tqdm \
    rich \
    typer \
    httpx \
    aiohttp \
    asyncio \
    aiofiles

print_status "Python dependencies installed successfully"

# Install Nuclei templates
print_info "Installing Nuclei templates..."
nuclei -update-templates

# Install wordlists
print_info "Installing comprehensive wordlists..."
sudo mkdir -p /usr/share/wordlists

# Download SecLists
if [ ! -d "/usr/share/wordlists/SecLists" ]; then
    sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
    print_status "SecLists installed"
fi

# Download common wordlists
cd /tmp

# Download subdomain wordlists
wget -O subdomains-top1million.txt https://wordlists-cdn.assetnote.io/data/manual/subdomains-top1million.txt
sudo mv subdomains-top1million.txt /usr/share/wordlists/

# Download directory wordlists
wget -O common.txt https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt
sudo mv common.txt /usr/share/wordlists/

# Download parameter wordlists
wget -O burp-parameter-names.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt
sudo mv burp-parameter-names.txt /usr/share/wordlists/

print_status "Wordlists installed successfully"

# Setup workspace directories
print_info "Setting up workspace directories..."
mkdir -p ~/bb_pro_workspace/{targets,scans,reports,payloads,wordlists,scripts,logs}
mkdir -p ~/bb_pro_workspace/results/{intelligence,vulnerabilities,exports}

print_status "Workspace directories created"

# Install browser for Selenium (optional)
print_info "Installing browser drivers for automated testing..."
wget -O /tmp/chromedriver.zip https://chromedriver.storage.googleapis.com/114.0.5735.90/chromedriver_linux64.zip
unzip /tmp/chromedriver.zip -d /tmp/
sudo mv /tmp/chromedriver /usr/local/bin/
sudo chmod +x /usr/local/bin/chromedriver

# Install Chrome browser
wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt update
sudo apt install -y google-chrome-stable

print_status "Browser and drivers installed"

# Create configuration files
print_info "Creating configuration files..."

# Create API keys configuration template
cat > ~/bb_pro_workspace/api_keys.env << EOF
# API Keys for Bug Bounty Hunter Pro
# Copy this file and add your actual API keys

# Shodan API Key (for IP intelligence)
SHODAN_API_KEY=your_shodan_api_key_here

# VirusTotal API Key (for domain/IP reputation)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Censys API Keys (for certificate transparency)
CENSYS_API_ID=your_censys_api_id_here
CENSYS_API_SECRET=your_censys_api_secret_here

# SecurityTrails API Key (for DNS history)
SECURITYTRAILS_API_KEY=your_securitytrails_api_key_here

# Hunter.io API Key (for email enumeration)
HUNTER_API_KEY=your_hunter_api_key_here

# Slack Webhook (for notifications)
SLACK_WEBHOOK_URL=your_slack_webhook_url_here

# Discord Webhook (for notifications)
DISCORD_WEBHOOK_URL=your_discord_webhook_url_here

# Email Configuration (for notifications)
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your_email@gmail.com
EMAIL_PASSWORD=your_app_password_here
EOF

# Create system service for background processing
print_info "Setting up system service..."
sudo tee /etc/systemd/system/bb-hunter-pro.service > /dev/null << EOF
[Unit]
Description=Bug Bounty Hunter Pro Background Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
Environment=PATH=$(pwd)/venv/bin
ExecStart=$(pwd)/venv/bin/python web_ui.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable bb-hunter-pro.service

print_status "System service configured"

# Create useful aliases
print_info "Creating useful aliases..."
cat >> ~/.bashrc << EOF

# Bug Bounty Hunter Pro Aliases
alias bbpro='cd $(pwd) && source venv/bin/activate'
alias bb-start='sudo systemctl start bb-hunter-pro'
alias bb-stop='sudo systemctl stop bb-hunter-pro'
alias bb-status='sudo systemctl status bb-hunter-pro'
alias bb-logs='sudo journalctl -u bb-hunter-pro -f'
alias bb-update='cd $(pwd) && git pull && source venv/bin/activate && pip install -r requirements.txt'
EOF

# Make scripts executable
chmod +x *.sh
chmod +x *.py

print_status "Aliases and permissions configured"

# Install database and initial setup
print_info "Setting up database and initial data..."
source venv/bin/activate
python -c "
from web_ui import BugBountyUI
ui = BugBountyUI()
print('Database initialized with sample data')
"

print_status "Database setup completed"

# Final security hardening
print_info "Applying security configurations..."

# Create .gitignore for sensitive files
cat > .gitignore << EOF
# Bug Bounty Hunter Pro - Sensitive Files
*.env
api_keys.env
*.db
*.sqlite
*.sqlite3
venv/
__pycache__/
*.pyc
*.pyo
*.log
logs/
results/
workspace/
.DS_Store
Thumbs.db
*.swp
*.swo
*~
.coverage
htmlcov/
.pytest_cache/
.tox/
dist/
build/
*.egg-info/
EOF

# Set appropriate permissions
chmod 600 ~/bb_pro_workspace/api_keys.env
chmod 755 ~/bb_pro_workspace
chmod -R 755 ~/bb_pro_workspace/results

print_status "Security configurations applied"

echo ""
echo "🎉 Installation Complete!"
echo "========================"
echo ""
print_status "Bug Bounty Hunter Pro with Advanced Features is now installed!"
echo ""
echo "📋 What's been installed:"
echo "  • Complete bug bounty framework with web UI"
echo "  • Advanced reconnaissance tools (subfinder, httpx, nuclei, etc.)"
echo "  • Comprehensive wordlists (SecLists, custom lists)"
echo "  • Python environment with all dependencies"
echo "  • System service for background processing"
echo "  • Browser automation capabilities"
echo "  • Database with sample data"
echo ""
echo "🚀 Quick Start:"
echo "  1. Add your API keys: nano ~/bb_pro_workspace/api_keys.env"
echo "  2. Start the service: bb-start"
echo "  3. Access web UI: http://localhost:5000"
echo "  4. Or use aliases: bbpro (to activate environment)"
echo ""
echo "📚 Documentation:"
echo "  • Read ADVANCED_FEATURES_GUIDE.md for detailed usage"
echo "  • Check RUN_ON_KALI_LINUX.md for Kali-specific setup"
echo "  • Review FINAL_KALI_DEPLOYMENT_GUIDE.md for deployment"
echo ""
echo "🔧 Useful Commands:"
echo "  • bb-start    - Start the web service"
echo "  • bb-stop     - Stop the web service"
echo "  • bb-status   - Check service status"
echo "  • bb-logs     - View service logs"
echo "  • bb-update   - Update to latest version"
echo ""
print_info "Restart your terminal or run 'source ~/.bashrc' to use the new aliases"
echo ""
print_status "Happy hunting! 🎯"
