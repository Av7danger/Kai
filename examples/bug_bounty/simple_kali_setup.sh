#!/bin/bash
# 🚀 SIMPLE KALI DEPLOYMENT SCRIPT
# Run this script on your Kali Linux system to set up the bug bounty framework

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; }

# Banner
echo -e "${GREEN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║       🚀 KALI LINUX BUG BOUNTY FRAMEWORK SETUP             ║
║          Complete deployment in under 10 minutes            ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running on Kali
if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
    warn "Not running on Kali Linux - some optimizations may not work"
fi

# Create project directory
log "Creating project directory..."
mkdir -p ~/bug_bounty_pro
cd ~/bug_bounty_pro

# Update system
log "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install essential packages
log "Installing essential packages..."
sudo apt install -y python3 python3-pip python3-venv git curl wget build-essential

# Install security tools
log "Installing security tools..."
sudo apt install -y subfinder httpx nuclei nmap gobuster ffuf nikto sqlmap amass

# Install Go if not present
if ! command -v go &> /dev/null; then
    log "Installing Go..."
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
fi

# Setup Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
mkdir -p $GOPATH

# Install Go-based security tools
log "Installing Go security tools..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest

# Create Python virtual environment
log "Setting up Python environment..."
python3 -m venv ~/bug_bounty_venv
source ~/bug_bounty_venv/bin/activate

# Install Python packages
log "Installing Python dependencies..."
pip install google-generativeai aiohttp aiofiles psutil asyncio-throttle requests beautifulsoup4 lxml pyyaml colorama rich click tqdm

# Setup environment variables
log "Configuring environment..."
cat >> ~/.bashrc << 'EOL'

# Bug Bounty Framework Environment
export GEMINI_API_KEY="your_api_key_here"
export BB_WORKSPACE=$HOME/bb_pro_workspace
export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin
export GOPATH=$HOME/go

# Bug Bounty Aliases
alias bbpro="cd $HOME/bug_bounty_pro && source ~/bug_bounty_venv/bin/activate && python3 kali_bb_pro.py"
alias bbhunt="cd $HOME/bug_bounty_pro && source ~/bug_bounty_venv/bin/activate && python3 kali_bb_pro.py quick-hunt"
alias bbstatus="cd $HOME/bug_bounty_pro && source ~/bug_bounty_venv/bin/activate && python3 kali_bb_pro.py status"
alias bbai="cd $HOME/bug_bounty_pro && source ~/bug_bounty_venv/bin/activate && python3 kali_bb_pro.py ai-assistant"
EOL

# Create workspace
log "Creating workspace..."
mkdir -p ~/bb_pro_workspace/{results,logs,reports,tools,wordlists}

# Download wordlists
log "Setting up wordlists..."
cd ~/bb_pro_workspace/wordlists
wget -q https://wordlists-cdn.assetnote.io/data/manual/subdomains-top1million-110000.txt

# Update nuclei templates
log "Updating Nuclei templates..."
nuclei -update-templates &>/dev/null || true

# Create sample configuration
log "Creating sample configuration..."
cat > ~/bug_bounty_pro/quick_start_config.py << 'EOL'
"""
🔧 QUICK START CONFIGURATION
Edit this file with your settings before hunting
"""

# Gemini API Configuration
GEMINI_API_KEY = "your_gemini_api_key_here"  # Replace with your actual API key

# Hunter Profile
HUNTER_PROFILE = {
    "experience_level": "intermediate",  # beginner, intermediate, advanced, expert
    "daily_hours": 8,                   # Hours per day
    "monthly_target": 50000,            # Monthly earnings goal ($)
    "risk_tolerance": "medium",         # low, medium, high
    "specializations": [                # Your expertise areas
        "web_app", 
        "api", 
        "business_logic",
        "mobile"
    ]
}

# Platform Configuration (optional)
PLATFORMS = {
    "hackerone": {"username": ""},
    "bugcrowd": {"username": ""},
    "intigriti": {"username": ""}
}

# Hunting Preferences
HUNTING_CONFIG = {
    "max_concurrent_targets": 5,
    "scan_intensity": "medium",        # low, medium, high, stealth
    "report_format": "markdown",       # markdown, json, html
    "auto_submit": False               # Auto-submit findings (use with caution)
}
EOL

# Create sample targets file
cat > ~/bug_bounty_pro/practice_targets.txt << 'EOL'
# Practice targets for testing (use responsibly)
testphp.vulnweb.com
demo.testfire.net
dvwa.local
bwapp.local
EOL

log "Setup complete! 🎉"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "1. Edit your API key: nano ~/bug_bounty_pro/quick_start_config.py"
echo "2. Reload environment: source ~/.bashrc"
echo "3. Test the setup: bbstatus"
echo "4. Start hunting: bbhunt testphp.vulnweb.com"
echo ""
echo -e "${YELLOW}Note: You still need to copy the Python scripts from your Windows machine${NC}"
echo "Copy these files to ~/bug_bounty_pro/:"
echo "  - kali_bb_pro.py"
echo "  - ultra_optimized_gemini_system.py" 
echo "  - personal_bug_bounty_optimizer.py"
echo "  - All other .py files from examples/bug_bounty/"
echo ""
echo -e "${GREEN}Happy hunting! 💰${NC}"
