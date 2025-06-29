#!/bin/bash

# Kali Linux Quick Setup Script for Kai Bug Bounty Framework
# Run this script on a fresh Kali Linux installation

set -e

echo "🚀 Kai Bug Bounty Framework - Kali Linux Setup"
echo "=============================================="

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
   print_error "This script should not be run as root. Please run as a regular user."
   exit 1
fi

# Check if we're on Kali Linux
if ! grep -q "kali" /etc/os-release; then
    print_warning "This script is designed for Kali Linux. You're running: $(cat /etc/os-release | grep PRETTY_NAME)"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

print_status "Starting Kali Linux setup..."

# Step 1: Update system
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Step 2: Install essential packages
print_status "Installing essential packages..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    git \
    curl \
    wget \
    unzip \
    golang-go \
    nmap \
    masscan \
    subfinder \
    amass \
    httpx \
    nuclei \
    ffuf \
    gobuster \
    sqlmap \
    nikto \
    wpscan \
    dirb \
    theharvester \
    dnsrecon \
    wafw00f \
    whatweb

# Step 3: Install Go-based tools
print_status "Installing Go-based tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest

# Step 4: Add Go bin to PATH
print_status "Configuring Go PATH..."
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
export PATH=$PATH:~/go/bin

# Step 5: Create project directories
print_status "Creating project directories..."
mkdir -p data/logs data/kali_results/{exports,payloads,reports,scans}
chmod 755 data/ data/kali_results/

# Step 6: Create virtual environment
print_status "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Step 7: Install Python dependencies
print_status "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Step 8: Configure system limits for better performance
print_status "Configuring system limits..."
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Step 9: Optimize network settings
print_status "Optimizing network settings..."
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535

# Step 10: Create startup script
print_status "Creating startup script..."
cat > start_kai.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python main.py
EOF

chmod +x start_kai.sh

# Step 11: Create systemd service (optional)
print_status "Creating systemd service..."
sudo tee /etc/systemd/system/kai-bug-hunter.service > /dev/null << EOF
[Unit]
Description=Kai Bug Bounty Framework
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
Environment=PATH=$(pwd)/venv/bin
ExecStart=$(pwd)/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Step 12: Test installation
print_status "Testing installation..."
source venv/bin/activate

# Test Python imports
python3 -c "import fastapi, uvicorn, psutil; print('Python dependencies OK')"

# Test tool availability
print_status "Testing tool availability..."
tools_to_test=("nmap" "subfinder" "amass" "nuclei" "ffuf" "sqlmap")
for tool in "${tools_to_test[@]}"; do
    if command -v "$tool" &> /dev/null; then
        print_success "$tool is available"
    else
        print_warning "$tool is not available"
    fi
done

# Step 13: Final configuration
print_status "Final configuration..."

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    cat > .env << EOF
# Kai Bug Bounty Framework Configuration
KAI_DEBUG=false
KAI_LOG_LEVEL=INFO
KAI_MAX_WORKERS=10
KAI_HOST=0.0.0.0
KAI_PORT=8000
EOF
fi

# Copy example configuration
if [ -f agents.yml.example ] && [ ! -f agents.yml ]; then
    cp agents.yml.example agents.yml
    print_status "Created agents.yml from example"
fi

print_success "Setup completed successfully!"
echo
echo "🎯 Next steps:"
echo "1. Start the application: ./start_kai.sh"
echo "2. Or use systemd: sudo systemctl enable kai-bug-hunter && sudo systemctl start kai-bug-hunter"
echo "3. Access dashboard: http://localhost:8000"
echo "4. Check API docs: http://localhost:8000/docs"
echo
echo "📁 Project structure:"
echo "  ├── data/                    # Logs and results"
echo "  ├── app/                     # Application code"
echo "  ├── venv/                    # Python virtual environment"
echo "  ├── start_kai.sh            # Startup script"
echo "  └── main.py                  # Main application"
echo
echo "🔧 Useful commands:"
echo "  - Start: ./start_kai.sh"
echo "  - Stop: Ctrl+C"
echo "  - Logs: tail -f data/bug_hunter.log"
echo "  - Status: curl http://localhost:8000/api/system-status"
echo
print_success "Happy bug hunting! 🐛" 