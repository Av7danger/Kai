#!/bin/bash
# Enhanced Bug Bounty Framework - Phase 1 Installation Script
# Automated setup for Docker, testing, real tools, and web dashboard

set -e  # Exit on any error

echo "🚀 Enhanced Bug Bounty Framework - Phase 1 Installation"
echo "=================================================="

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

# Check if running on supported OS
check_os() {
    print_status "Checking operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        print_success "Linux detected"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        print_success "macOS detected"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        OS="windows"
        print_success "Windows detected"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python $PYTHON_VERSION found"
    else
        print_error "Python 3 is required but not found"
        exit 1
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        print_success "pip3 found"
    else
        print_error "pip3 is required but not found"
        exit 1
    fi
    
    # Check Git
    if command -v git &> /dev/null; then
        print_success "Git found"
    else
        print_error "Git is required but not found"
        exit 1
    fi
}

# Install Docker
install_docker() {
    print_status "Installing Docker..."
    
    if command -v docker &> /dev/null; then
        print_success "Docker already installed"
        return
    fi
    
    case $OS in
        "linux")
            # Install Docker on Linux
            curl -fsSL https://get.docker.com -o get-docker.sh
            sudo sh get-docker.sh
            sudo usermod -aG docker $USER
            rm get-docker.sh
            ;;
        "macos")
            print_warning "Please install Docker Desktop for Mac from https://www.docker.com/products/docker-desktop"
            print_warning "Press Enter after installation to continue..."
            read
            ;;
        "windows")
            print_warning "Please install Docker Desktop for Windows from https://www.docker.com/products/docker-desktop"
            print_warning "Press Enter after installation to continue..."
            read
            ;;
    esac
    
    # Verify Docker installation
    if command -v docker &> /dev/null; then
        print_success "Docker installed successfully"
    else
        print_error "Docker installation failed"
        exit 1
    fi
}

# Install Docker Compose
install_docker_compose() {
    print_status "Installing Docker Compose..."
    
    if command -v docker-compose &> /dev/null; then
        print_success "Docker Compose already installed"
        return
    fi
    
    case $OS in
        "linux")
            sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            sudo chmod +x /usr/local/bin/docker-compose
            ;;
        "macos"|"windows")
            print_success "Docker Compose included with Docker Desktop"
            ;;
    esac
    
    # Verify installation
    if command -v docker-compose &> /dev/null; then
        print_success "Docker Compose installed successfully"
    else
        print_error "Docker Compose installation failed"
        exit 1
    fi
}

# Install Go (required for security tools)
install_go() {
    print_status "Installing Go..."
    
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | cut -d' ' -f3)
        print_success "Go $GO_VERSION already installed"
        return
    fi
    
    case $OS in
        "linux")
            GO_VERSION="1.21.5"
            wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
            sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            echo 'export GOPATH=$HOME/go' >> ~/.bashrc
            echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
            source ~/.bashrc
            rm go${GO_VERSION}.linux-amd64.tar.gz
            ;;
        "macos")
            if command -v brew &> /dev/null; then
                brew install go
            else
                print_warning "Please install Go from https://golang.org/dl/"
                print_warning "Press Enter after installation to continue..."
                read
            fi
            ;;
        "windows")
            print_warning "Please install Go from https://golang.org/dl/"
            print_warning "Press Enter after installation to continue..."
            read
            ;;
    esac
    
    # Verify Go installation
    if command -v go &> /dev/null; then
        print_success "Go installed successfully"
    else
        print_error "Go installation failed"
        exit 1
    fi
}

# Install security tools
install_security_tools() {
    print_status "Installing security tools..."
    
    # Create tools directory
    mkdir -p ~/security-tools
    cd ~/security-tools
    
    # Install Subfinder
    print_status "Installing Subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    
    # Install Httpx
    print_status "Installing Httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    
    # Install Nuclei
    print_status "Installing Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    
    # Install Amass
    print_status "Installing Amass..."
    go install -v github.com/OWASP/Amass/v4/...@master
    
    # Update Nuclei templates
    print_status "Updating Nuclei templates..."
    nuclei -update-templates
    
    print_success "Security tools installed successfully"
    
    # Return to original directory
    cd - > /dev/null
}

# Install Python dependencies
install_python_dependencies() {
    print_status "Installing Python dependencies..."
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    pip install -r requirements.txt
    
    print_success "Python dependencies installed successfully"
}

# Setup environment
setup_environment() {
    print_status "Setting up environment..."
    
    # Copy environment file
    if [ ! -f .env ]; then
        cp .env.example .env
        print_success "Environment file created (.env)"
        print_warning "Please edit .env file with your configuration"
    else
        print_success "Environment file already exists"
    fi
    
    # Create necessary directories
    mkdir -p data logs reports config temp
    chmod 755 data logs reports config temp
    
    print_success "Directory structure created"
}

# Run tests
run_tests() {
    print_status "Running test suite..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Run tests
    python -m pytest tests/ -v --tb=short
    
    if [ $? -eq 0 ]; then
        print_success "All tests passed!"
    else
        print_warning "Some tests failed, but installation can continue"
    fi
}

# Build Docker images
build_docker_images() {
    print_status "Building Docker images..."
    
    # Build main application image
    docker build -t enhanced-bug-bounty:latest .
    
    if [ $? -eq 0 ]; then
        print_success "Docker image built successfully"
    else
        print_error "Docker image build failed"
        exit 1
    fi
}

# Start services
start_services() {
    print_status "Starting services with Docker Compose..."
    
    # Start services in detached mode
    docker-compose up -d
    
    if [ $? -eq 0 ]; then
        print_success "Services started successfully"
        print_status "Dashboard available at: http://localhost:8000"
        print_status "Grafana available at: http://localhost:3000"
        print_status "Prometheus available at: http://localhost:9090"
    else
        print_error "Failed to start services"
        exit 1
    fi
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    # Check if services are running
    sleep 10  # Wait for services to start
    
    # Test dashboard endpoint
    if curl -f -s http://localhost:8000/health > /dev/null; then
        print_success "Dashboard is responding"
    else
        print_warning "Dashboard is not responding yet (may need more time to start)"
    fi
    
    # Test framework import
    source venv/bin/activate
    python -c "
from enhanced_integration import enhanced_framework
from real_security_tools import security_tools
print('✅ Framework components imported successfully')
print('✅ Real security tools integrated')
print('✅ Phase 1 installation completed!')
" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        print_success "Framework verification passed"
    else
        print_warning "Framework verification failed - check Python dependencies"
    fi
}

# Print final instructions
print_final_instructions() {
    echo ""
    echo "🎉 Phase 1 Installation Complete!"
    echo "=================================="
    echo ""
    echo "✅ Docker containerization ready"
    echo "✅ Comprehensive test suite available"
    echo "✅ Real security tools integrated:"
    echo "   • Subfinder (subdomain enumeration)"
    echo "   • Httpx (HTTP probing)"
    echo "   • Nuclei (vulnerability scanning)"
    echo "   • Amass (asset discovery)"
    echo "✅ Web dashboard available"
    echo ""
    echo "🌐 Access Points:"
    echo "   • Dashboard: http://localhost:8000"
    echo "   • API Docs: http://localhost:8000/api/docs"
    echo "   • Grafana: http://localhost:3000 (admin/changeme)"
    echo "   • Prometheus: http://localhost:9090"
    echo ""
    echo "🚀 Quick Start:"
    echo "   1. Edit .env file with your configuration"
    echo "   2. Open dashboard: http://localhost:8000"
    echo "   3. Start your first scan!"
    echo ""
    echo "🧪 Run Tests:"
    echo "   source venv/bin/activate && python -m pytest tests/ -v"
    echo ""
    echo "🐳 Docker Commands:"
    echo "   • Stop services: docker-compose down"
    echo "   • View logs: docker-compose logs -f"
    echo "   • Restart: docker-compose restart"
    echo ""
    echo "📚 Next Steps (Phase 2):"
    echo "   • Authentication system"
    echo "   • Cloud deployment"
    echo "   • Advanced monitoring"
    echo "   • CI/CD pipeline"
    echo ""
    print_success "Installation completed successfully! 🎯"
}

# Main installation flow
main() {
    echo "Starting Phase 1 installation..."
    echo ""
    
    check_os
    check_prerequisites
    install_docker
    install_docker_compose
    install_go
    install_security_tools
    install_python_dependencies
    setup_environment
    run_tests
    build_docker_images
    start_services
    verify_installation
    print_final_instructions
}

# Run main function
main "$@"
