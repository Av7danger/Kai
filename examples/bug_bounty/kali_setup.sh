#!/bin/bash

# 🐛 Kali Bug Hunter Setup Script
# Simplified setup for Kali Linux

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_error "This script should not be run as root"
    exit 1
fi

# Check if running on Kali Linux
if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
    print_warning "This script is optimized for Kali Linux. Other distributions may work but are not guaranteed."
fi

print_status "Starting Kali Bug Hunter Setup..."

# Update system packages
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Python dependencies
print_status "Installing Python dependencies..."
sudo apt install -y python3 python3-pip python3-venv python3-dev

# Install required system packages
print_status "Installing required system packages..."
sudo apt install -y \
    git \
    curl \
    wget \
    unzip \
    sqlite3 \
    nginx \
    ufw \
    htop \
    tree

# Install Kali tools (if not already installed)
print_status "Checking Kali tools..."
KALI_TOOLS=(
    "nmap"
    "masscan"
    "subfinder"
    "amass"
    "theharvester"
    "dnsrecon"
    "whatweb"
    "wafw00f"
    "gobuster"
    "dirb"
    "assetfinder"
    "eyewitness"
    "spiderfoot"
    "nuclei"
    "httpx"
    "nikto"
    "wpscan"
    "joomscan"
    "sqlmap"
    "xsser"
    "arachni"
    "ffuf"
    "dalfox"
    "metasploit-framework"
    "hydra"
    "medusa"
    "patator"
    "crackmapexec"
    "responder"
    "impacket-scripts"
    "hashcat"
    "john"
    "binwalk"
    "strings"
    "exiftool"
    "steghide"
    "foremost"
    "volatility"
    "radare2"
    "gdb"
    "aircrack-ng"
    "reaver"
    "bettercap"
    "kismet"
    "recon-ng"
    "sherlock"
    "social-engineer-toolkit"
)

# Install via apt
APT_TOOLS=(
    nmap masscan subfinder amass theharvester dnsrecon whatweb wafw00f gobuster dirb assetfinder eyewitness spiderfoot nuclei httpx nikto joomscan sqlmap xsser ffuf dalfox metasploit-framework hydra medusa patator crackmapexec responder impacket-scripts hashcat john binwalk strings exiftool steghide foremost volatility radare2 gdb aircrack-ng reaver bettercap kismet recon-ng social-engineer-toolkit
)

print_status "Installing tools via apt..."
sudo apt install -y ${APT_TOOLS[@]}

# Special installs
print_status "Installing wpscan (via gem)..."
sudo gem install wpscan || true

print_status "Installing arachni (via gem, may take time)..."
sudo gem install arachni || true

print_status "Installing sherlock (via pip)..."
pip install sherlock || true

# Note: shodan and maltego require manual/API setup
print_warning "Shodan and Maltego require manual/API setup. Skipping automatic install."

# Create virtual environment
print_status "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python packages
print_status "Installing Python packages..."
pip install --upgrade pip
pip install \
    flask \
    flask-login \
    pyyaml \
    requests \
    sqlite3 \
    python-dotenv \
    colorama \
    rich

# Create project structure
print_status "Creating project structure..."
mkdir -p kali_results/{reports,scans,payloads,exports}
mkdir -p logs
mkdir -p config

# Set up configuration
print_status "Setting up configuration..."
if [ ! -f kali_config.yml ]; then
    cat > kali_config.yml << 'EOF'
# Kali Bug Hunter Configuration
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
EOF
    print_success "Configuration file created"
fi

# Set up firewall
print_status "Configuring firewall..."
sudo ufw --force enable
sudo ufw allow ssh
sudo ufw allow 5000/tcp  # Dashboard port
sudo ufw allow 80/tcp     # HTTP
sudo ufw allow 443/tcp    # HTTPS
print_success "Firewall configured"

# Create systemd service (optional)
print_status "Creating systemd service..."
sudo tee /etc/systemd/system/kali-bug-hunter.service > /dev/null << EOF
[Unit]
Description=Kali Bug Hunter
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
Environment=PATH=$(pwd)/venv/bin
ExecStart=$(pwd)/venv/bin/python kali_bug_hunter.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable kali-bug-hunter.service
print_success "Systemd service created and enabled"

# Create startup script
cat > start.sh << 'EOF'
#!/bin/bash
# Start Kali Bug Hunter

echo "🐛 Starting Kali Bug Hunter..."

# Activate virtual environment
source venv/bin/activate

# Start the application
python kali_bug_hunter.py
EOF

chmod +x start.sh

# Create stop script
cat > stop.sh << 'EOF'
#!/bin/bash
# Stop Kali Bug Hunter

echo "🛑 Stopping Kali Bug Hunter..."

# Stop the service
sudo systemctl stop kali-bug-hunter.service

echo "Kali Bug Hunter stopped"
EOF

chmod +x stop.sh

# Create status script
cat > status.sh << 'EOF'
#!/bin/bash
# Check Kali Bug Hunter status

echo "📊 Kali Bug Hunter Status:"

# Check service status
sudo systemctl status kali-bug-hunter.service --no-pager

# Check if dashboard is accessible
if curl -s http://localhost:5000 > /dev/null; then
    echo "✅ Dashboard is accessible at http://localhost:5000"
else
    echo "❌ Dashboard is not accessible"
fi
EOF

chmod +x status.sh

# Create quick test script
cat > test_kali_tools.sh << 'EOF'
#!/bin/bash
# Test Kali tools availability

echo "🔧 Testing Kali Tools..."

TOOLS=("nmap" "nuclei" "ffuf" "subfinder" "amass" "httpx")

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✅ $tool is available"
    else
        echo "❌ $tool is not available"
    fi
done
EOF

chmod +x test_kali_tools.sh

# Set proper permissions
chmod 755 *.sh
chmod 644 kali_config.yml

print_success "Setup completed successfully!"

# Display next steps
echo ""
echo "🎉 Kali Bug Hunter has been set up successfully!"
echo ""
echo "📋 Next Steps:"
echo "1. Start the application: ./start.sh"
echo "2. Access the dashboard: http://localhost:5000"
echo "3. Login with: username=kali, password=kali"
echo "4. Check status: ./status.sh"
echo "5. Test tools: ./test_kali_tools.sh"
echo ""
echo "🔧 Management Commands:"
echo "  Start:   ./start.sh"
echo "  Stop:    ./stop.sh"
echo "  Status:  ./status.sh"
echo "  Test:    ./test_kali_tools.sh"
echo ""
echo "📁 Project Structure:"
echo "  kali_bug_hunter.py    - Main application"
echo "  kali_config.yml       - Configuration"
echo "  kali_results/         - Output directory"
echo "  templates/            - Web templates"
echo "  venv/                 - Python virtual environment"
echo ""
echo "🚀 Happy Bug Hunting!" 