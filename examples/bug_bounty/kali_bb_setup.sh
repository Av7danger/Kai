#!/bin/bash
"""
🐉 KALI LINUX BUG BOUNTY PRO SETUP SCRIPT
⚡ Automated installation and configuration for professional bug bounty hunting
🎯 Installs all necessary tools, dependencies, and optimizations

Usage: sudo ./kali_bb_setup.sh
"""

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Banner
print_banner() {
    echo -e "${PURPLE}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════════╗
    ║     🐉 KALI LINUX BUG BOUNTY PRO SETUP                          ║
    ║        Professional-grade bug bounty hunting environment          ║
    ║         💰 Optimized for maximum profit and efficiency           ║
    ╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        warning "Running as root. Some tools may not work properly."
        warning "Consider running as a regular user with sudo privileges."
    fi
}

# Update system
update_system() {
    log "Updating system packages..."
    apt update && apt upgrade -y
}

# Install essential tools
install_essential_tools() {
    log "Installing essential bug bounty tools..."
    
    # Core recon tools
    apt install -y \
        subfinder \
        amass \
        httpx \
        nuclei \
        nmap \
        gobuster \
        dirsearch \
        ffuf \
        nikto \
        sqlmap \
        feroxbuster \
        masscan \
        zmap
    
    # Additional useful tools
    apt install -y \
        curl \
        wget \
        git \
        jq \
        unzip \
        python3 \
        python3-pip \
        golang-go \
        nodejs \
        npm \
        ruby \
        gem
}

# Install Go-based tools
install_go_tools() {
    log "Installing Go-based security tools..."
    
    # Set Go environment
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
    
    # Create Go workspace
    mkdir -p $HOME/go/{bin,src,pkg}
    
    # Install tools
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/owasp-amass/amass/v3/...@master
    go install -v github.com/tomnomnom/assetfinder@latest
    go install -v github.com/tomnomnom/httprobe@latest
    go install -v github.com/tomnomnom/waybackurls@latest
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/ffuf/ffuf@latest
    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest
    go install -v github.com/hahwul/dalfox/v2@latest
    go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
    go install -v github.com/s0md3v/smap/cmd/smap@latest
}

# Install Python dependencies
install_python_deps() {
    log "Installing Python dependencies..."
    
    pip3 install --upgrade pip
    pip3 install \
        google-generativeai \
        aiohttp \
        aiofiles \
        psutil \
        asyncio-throttle \
        requests \
        beautifulsoup4 \
        lxml \
        selenium \
        pyyaml \
        python-dotenv \
        colorama \
        tabulate \
        rich \
        click \
        tqdm
}

# Setup wordlists
setup_wordlists() {
    log "Setting up wordlists..."
    
    WORDLIST_DIR="/usr/share/wordlists"
    
    # Create wordlist directory if it doesn't exist
    mkdir -p $WORDLIST_DIR
    
    # Download SecLists
    if [ ! -d "$WORDLIST_DIR/SecLists" ]; then
        cd $WORDLIST_DIR
        git clone https://github.com/danielmiessler/SecLists.git
        cd SecLists
        tar -xzf rockyou.txt.tar.gz
    fi
    
    # Download other useful wordlists
    cd $WORDLIST_DIR
    
    # Common subdomains
    if [ ! -f "subdomains-top1million-110000.txt" ]; then
        wget https://wordlists-cdn.assetnote.io/data/manual/subdomains-top1million-110000.txt
    fi
    
    # Directory wordlists
    if [ ! -f "directory-list-2.3-medium.txt" ]; then
        wget https://raw.githubusercontent.com/daviddias/node-dirbuster/master/lists/directory-list-2.3-medium.txt
    fi
    
    # Parameter wordlists
    if [ ! -f "burp-parameter-names.txt" ]; then
        wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt
    fi
}

# Configure Nuclei templates
setup_nuclei() {
    log "Setting up Nuclei templates..."
    
    # Update Nuclei templates
    nuclei -update-templates -silent
    
    # Create custom template directory
    mkdir -p $HOME/.config/nuclei/templates/custom
    
    # Download additional community templates
    cd $HOME/.config/nuclei/templates
    if [ ! -d "community-templates" ]; then
        git clone https://github.com/projectdiscovery/nuclei-templates.git community-templates
    fi
}

# Setup bug bounty workspace
setup_workspace() {
    log "Setting up bug bounty workspace..."
    
    WORKSPACE="$HOME/bb_pro_workspace"
    mkdir -p $WORKSPACE/{targets,results,reports,logs,exploits,payloads,screenshots,evidence,wordlists,scripts,campaigns,intelligence}
    
    # Create useful scripts directory
    mkdir -p $WORKSPACE/scripts
    
    # Create a quick recon script
    cat > $WORKSPACE/scripts/quick_recon.sh << 'EOF'
#!/bin/bash
# Quick reconnaissance script
target=$1
if [ -z "$target" ]; then
    echo "Usage: $0 <target.com>"
    exit 1
fi

echo "Starting recon for $target"
mkdir -p results/$target

# Subdomain discovery
echo "Finding subdomains..."
subfinder -d $target -silent > results/$target/subdomains.txt
assetfinder --subs-only $target >> results/$target/subdomains.txt
sort -u results/$target/subdomains.txt -o results/$target/subdomains.txt

# HTTP probing
echo "Probing HTTP services..."
httpx -l results/$target/subdomains.txt -silent -status-code -title > results/$target/live_hosts.txt

# Quick vulnerability scan
echo "Running quick vulnerability scan..."
nuclei -l results/$target/live_hosts.txt -severity high,critical -silent > results/$target/vulnerabilities.txt

echo "Recon complete! Check results/$target/"
EOF
    
    chmod +x $WORKSPACE/scripts/quick_recon.sh
    
    # Create environment configuration
    cat > $WORKSPACE/.env << 'EOF'
# Bug Bounty Pro Environment Configuration
export BB_WORKSPACE=$HOME/bb_pro_workspace
export PATH=$PATH:$HOME/go/bin
export GOPATH=$HOME/go

# Tool configurations
export NUCLEI_TEMPLATES_PATH=$HOME/.config/nuclei/templates
export WORDLIST_PATH=/usr/share/wordlists

# Aliases
alias bbpro='cd $BB_WORKSPACE && python3 kali_bb_pro.py'
alias quickrecon='$BB_WORKSPACE/scripts/quick_recon.sh'
alias subenum='subfinder -d'
alias httpprobe='httpx -l'
alias vulnscan='nuclei -l'
EOF
    
    info "Workspace created at $WORKSPACE"
}

# Install additional useful tools
install_additional_tools() {
    log "Installing additional useful tools..."
    
    # Browser tools
    apt install -y firefox-esr chromium
    
    # Development tools
    apt install -y vim neovim tmux screen
    
    # Network tools
    apt install -y netcat-traditional socat tcpdump wireshark-qt
    
    # Image and media tools
    apt install -y imagemagick ffmpeg
    
    # Install Docker (for containerized tools)
    if ! command -v docker &> /dev/null; then
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        usermod -aG docker $USER
        rm get-docker.sh
    fi
}

# Configure shell environment
configure_shell() {
    log "Configuring shell environment..."
    
    # Add bug bounty aliases to bashrc
    cat >> $HOME/.bashrc << 'EOF'

# Bug Bounty Pro Aliases
alias bbpro='cd $HOME/bb_pro_workspace && python3 kali_bb_pro.py'
alias bbworkspace='cd $HOME/bb_pro_workspace'
alias subenum='subfinder -d'
alias httpprobe='httpx -l'
alias vulnscan='nuclei -l'
alias dirscan='gobuster dir -u'
alias portscan='nmap -sV -sC'

# Environment variables
export BB_WORKSPACE=$HOME/bb_pro_workspace
export PATH=$PATH:$HOME/go/bin
export GOPATH=$HOME/go
EOF
    
    # Source the new configuration
    source $HOME/.bashrc
}

# Create desktop shortcuts
create_shortcuts() {
    log "Creating desktop shortcuts..."
    
    DESKTOP_DIR="$HOME/Desktop"
    mkdir -p $DESKTOP_DIR
    
    # Bug Bounty Pro launcher
    cat > $DESKTOP_DIR/BugBountyPro.desktop << EOF
[Desktop Entry]
Name=Bug Bounty Pro
Comment=Professional Bug Bounty Hunting CLI
Exec=gnome-terminal -- bash -c 'cd $HOME/bb_pro_workspace && python3 kali_bb_pro.py status; bash'
Icon=applications-internet
Terminal=false
Type=Application
Categories=Network;Security;
EOF
    
    chmod +x $DESKTOP_DIR/BugBountyPro.desktop
}

# Setup monitoring and logging
setup_monitoring() {
    log "Setting up monitoring and logging..."
    
    # Create log rotation configuration
    cat > /etc/logrotate.d/bugbounty << 'EOF'
/home/*/bb_pro_workspace/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
    
    # Setup system monitoring script
    cat > $HOME/bb_pro_workspace/scripts/monitor.sh << 'EOF'
#!/bin/bash
# System monitoring for bug bounty activities

while true; do
    echo "$(date): CPU: $(cat /proc/loadavg | cut -d' ' -f1)% | Memory: $(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100.0)}') | Disk: $(df -h / | awk 'NR==2{print $5}')" >> $HOME/bb_pro_workspace/logs/system_monitor.log
    sleep 60
done
EOF
    
    chmod +x $HOME/bb_pro_workspace/scripts/monitor.sh
}

# Final optimizations
apply_optimizations() {
    log "Applying system optimizations..."
    
    # Increase file descriptor limits
    cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 65535
* hard nofile 65535
EOF
    
    # Optimize network settings for scanning
    cat >> /etc/sysctl.conf << 'EOF'
# Bug bounty optimizations
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 65536 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000
EOF
    
    sysctl -p
    
    # Create performance tuning script
    cat > $HOME/bb_pro_workspace/scripts/performance_tune.sh << 'EOF'
#!/bin/bash
# Performance tuning for bug bounty hunting

echo "Applying performance optimizations..."

# Increase max open files
ulimit -n 65535

# Set CPU governor to performance
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable swap for better performance
swapoff -a

echo "Performance optimizations applied!"
EOF
    
    chmod +x $HOME/bb_pro_workspace/scripts/performance_tune.sh
}

# Print completion message
print_completion() {
    echo -e "${GREEN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                    🎉 SETUP COMPLETE! 🎉                        ║
    ║                                                                   ║
    ║  Your Kali Linux system is now optimized for bug bounty hunting! ║
    ║                                                                   ║
    ║  Next steps:                                                      ║
    ║  1. Reboot your system to apply all optimizations                ║
    ║  2. Set your Gemini API key in quick_start_config.py             ║
    ║  3. Run: ./kali_bb_pro.py status                                 ║
    ║  4. Start hunting: ./kali_bb_pro.py quick-hunt target.com        ║
    ║                                                                   ║
    ║  Workspace: ~/bb_pro_workspace                                    ║
    ║  Tools installed: 30+                                            ║
    ║  Ready to make money! 💰                                         ║
    ╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Main installation function
main() {
    print_banner
    check_root
    
    log "Starting Bug Bounty Pro installation..."
    
    update_system
    install_essential_tools
    install_go_tools
    install_python_deps
    setup_wordlists
    setup_nuclei
    setup_workspace
    install_additional_tools
    configure_shell
    create_shortcuts
    setup_monitoring
    apply_optimizations
    
    print_completion
    
    info "Installation completed successfully!"
    info "Please reboot your system and then run: ./kali_bb_pro.py status"
}

# Run main function
main "$@"
