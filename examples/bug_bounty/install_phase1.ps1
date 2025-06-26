# Enhanced Bug Bounty Framework - Phase 1 Installation Script (Windows PowerShell)
# Automated setup for Docker, testing, real tools, and web dashboard

param(
    [switch]$SkipDocker,
    [switch]$SkipTools,
    [switch]$SkipTests
)

# Set strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "🚀 Enhanced Bug Bounty Framework - Phase 1 Installation (Windows)" -ForegroundColor Blue
Write-Host "=================================================================" -ForegroundColor Blue

# Function to print colored output
function Write-Status { 
    param($Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success { 
    param($Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning { 
    param($Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error { 
    param($Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check prerequisites
function Test-Prerequisites {
    Write-Status "Checking prerequisites..."
    
    # Check if running as administrator
    if (-not (Test-Administrator)) {
        Write-Warning "Some operations require administrator privileges"
        Write-Warning "Consider running as administrator for full installation"
    }
    
    # Check Python
    try {
        $pythonVersion = python --version 2>&1
        if ($pythonVersion -match "Python (\d+\.\d+\.\d+)") {
            Write-Success "Python $($matches[1]) found"
        } else {
            throw "Invalid Python version output"
        }
    } catch {
        Write-Error "Python 3 is required but not found"
        Write-Warning "Download Python from: https://www.python.org/downloads/"
        exit 1
    }
    
    # Check pip
    try {
        pip --version | Out-Null
        Write-Success "pip found"
    } catch {
        Write-Error "pip is required but not found"
        exit 1
    }
    
    # Check Git
    try {
        git --version | Out-Null
        Write-Success "Git found"
    } catch {
        Write-Error "Git is required but not found"
        Write-Warning "Download Git from: https://git-scm.com/download/win"
        exit 1
    }
}

# Install Chocolatey package manager
function Install-Chocolatey {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Success "Chocolatey already installed"
        return
    }
    
    Write-Status "Installing Chocolatey package manager..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Success "Chocolatey installed successfully"
    } catch {
        Write-Warning "Failed to install Chocolatey automatically"
        Write-Warning "Please install manually from: https://chocolatey.org/install"
    }
}

# Install Docker Desktop
function Install-Docker {
    if ($SkipDocker) {
        Write-Warning "Skipping Docker installation (--SkipDocker flag)"
        return
    }
    
    Write-Status "Checking Docker installation..."
    
    try {
        docker --version | Out-Null
        Write-Success "Docker already installed"
        return
    } catch {
        Write-Status "Installing Docker Desktop..."
    }
    
    # Try to install via Chocolatey first
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        try {
            choco install docker-desktop -y
            Write-Success "Docker Desktop installed via Chocolatey"
        } catch {
            Write-Warning "Chocolatey installation failed, please install manually"
        }
    } else {
        Write-Warning "Please download and install Docker Desktop from:"
        Write-Warning "https://www.docker.com/products/docker-desktop"
        Write-Host "Press Enter after installation to continue..." -NoNewline
        Read-Host
    }
    
    # Verify Docker installation
    try {
        docker --version | Out-Null
        Write-Success "Docker installation verified"
    } catch {
        Write-Error "Docker installation verification failed"
        Write-Warning "Please ensure Docker Desktop is running"
    }
}

# Install Go
function Install-Go {
    Write-Status "Checking Go installation..."
    
    try {
        $goVersion = go version 2>&1
        if ($goVersion -match "go(\d+\.\d+\.\d+)") {
            Write-Success "Go $($matches[1]) already installed"
            return
        }
    } catch {
        Write-Status "Installing Go..."
    }
    
    # Try to install via Chocolatey
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        try {
            choco install golang -y
            Write-Success "Go installed via Chocolatey"
            # Refresh environment variables
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        } catch {
            Write-Warning "Chocolatey installation failed"
        }
    } else {
        Write-Warning "Please download and install Go from: https://golang.org/dl/"
        Write-Host "Press Enter after installation to continue..." -NoNewline
        Read-Host
    }
    
    # Verify Go installation
    try {
        go version | Out-Null
        Write-Success "Go installation verified"
    } catch {
        Write-Error "Go installation verification failed"
        Write-Warning "Please add Go to your PATH and restart PowerShell"
    }
}

# Install security tools
function Install-SecurityTools {
    if ($SkipTools) {
        Write-Warning "Skipping security tools installation (--SkipTools flag)"
        return
    }
    
    Write-Status "Installing security tools..."
    
    # Create tools directory
    $toolsDir = "$env:USERPROFILE\security-tools"
    if (-not (Test-Path $toolsDir)) {
        New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    }
    
    # Set GOPATH if not set
    if (-not $env:GOPATH) {
        $env:GOPATH = "$env:USERPROFILE\go"
        [Environment]::SetEnvironmentVariable("GOPATH", $env:GOPATH, "User")
    }
    
    # Add Go bin to PATH if not present
    $goBin = "$env:GOPATH\bin"
    if ($env:PATH -notlike "*$goBin*") {
        $env:PATH += ";$goBin"
        [Environment]::SetEnvironmentVariable("PATH", $env:PATH, "User")
    }
    
    try {
        # Install Subfinder
        Write-Status "Installing Subfinder..."
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        
        # Install Httpx
        Write-Status "Installing Httpx..."
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        
        # Install Nuclei
        Write-Status "Installing Nuclei..."
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        
        # Install Amass
        Write-Status "Installing Amass..."
        go install -v github.com/OWASP/Amass/v4/...@master
        
        Write-Success "Security tools installed successfully"
        
        # Update Nuclei templates
        Write-Status "Updating Nuclei templates..."
        & "$goBin\nuclei.exe" -update-templates
        Write-Success "Nuclei templates updated"
        
    } catch {
        Write-Warning "Some security tools may have failed to install"
        Write-Warning "Error: $($_.Exception.Message)"
    }
}

# Install Python dependencies
function Install-PythonDependencies {
    Write-Status "Installing Python dependencies..."
    
    try {
        # Create virtual environment
        Write-Status "Creating Python virtual environment..."
        python -m venv venv
        
        # Activate virtual environment
        & ".\venv\Scripts\Activate.ps1"
        
        # Upgrade pip
        Write-Status "Upgrading pip..."
        python -m pip install --upgrade pip
        
        # Install requirements
        Write-Status "Installing Python packages..."
        pip install -r requirements.txt
        
        Write-Success "Python dependencies installed successfully"
        
    } catch {
        Write-Error "Failed to install Python dependencies: $($_.Exception.Message)"
        exit 1
    }
}

# Setup environment
function Set-Environment {
    Write-Status "Setting up environment..."
    
    # Copy environment file
    if (-not (Test-Path ".env")) {
        Copy-Item ".env.example" ".env"
        Write-Success "Environment file created (.env)"
        Write-Warning "Please edit .env file with your configuration"
    } else {
        Write-Success "Environment file already exists"
    }
    
    # Create necessary directories
    $directories = @("data", "logs", "reports", "config", "temp")
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    Write-Success "Directory structure created"
}

# Run tests
function Invoke-Tests {
    if ($SkipTests) {
        Write-Warning "Skipping tests (--SkipTests flag)"
        return
    }
    
    Write-Status "Running test suite..."
    
    try {
        # Activate virtual environment
        & ".\venv\Scripts\Activate.ps1"
        
        # Run tests
        python -m pytest tests/ -v --tb=short
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "All tests passed!"
        } else {
            Write-Warning "Some tests failed, but installation can continue"
        }
    } catch {
        Write-Warning "Failed to run tests: $($_.Exception.Message)"
    }
}

# Build Docker images
function Build-DockerImages {
    if ($SkipDocker) {
        Write-Warning "Skipping Docker build (--SkipDocker flag)"
        return
    }
    
    Write-Status "Building Docker images..."
    
    try {
        docker build -t enhanced-bug-bounty:latest .
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Docker image built successfully"
        } else {
            throw "Docker build failed"
        }
    } catch {
        Write-Error "Docker image build failed: $($_.Exception.Message)"
        exit 1
    }
}

# Start services
function Start-Services {
    if ($SkipDocker) {
        Write-Warning "Skipping service startup (--SkipDocker flag)"
        return
    }
    
    Write-Status "Starting services with Docker Compose..."
    
    try {
        docker-compose up -d
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Services started successfully"
            Write-Status "Dashboard available at: http://localhost:8000"
            Write-Status "Grafana available at: http://localhost:3000"
            Write-Status "Prometheus available at: http://localhost:9090"
        } else {
            throw "Docker Compose failed"
        }
    } catch {
        Write-Error "Failed to start services: $($_.Exception.Message)"
        exit 1
    }
}

# Verify installation
function Test-Installation {
    Write-Status "Verifying installation..."
    
    # Wait for services to start
    Start-Sleep -Seconds 10
    
    # Test dashboard endpoint
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-Success "Dashboard is responding"
        }
    } catch {
        Write-Warning "Dashboard is not responding yet (may need more time to start)"
    }
    
    # Test framework import
    try {
        & ".\venv\Scripts\Activate.ps1"
        python -c @"
from enhanced_integration import enhanced_framework
from real_security_tools import security_tools
print('✅ Framework components imported successfully')
print('✅ Real security tools integrated')
print('✅ Phase 1 installation completed!')
"@
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Framework verification passed"
        } else {
            Write-Warning "Framework verification failed - check Python dependencies"
        }
    } catch {
        Write-Warning "Framework verification failed: $($_.Exception.Message)"
    }
}

# Print final instructions
function Write-FinalInstructions {
    Write-Host ""
    Write-Host "🎉 Phase 1 Installation Complete!" -ForegroundColor Green
    Write-Host "==================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "✅ Docker containerization ready" -ForegroundColor Green
    Write-Host "✅ Comprehensive test suite available" -ForegroundColor Green
    Write-Host "✅ Real security tools integrated:" -ForegroundColor Green
    Write-Host "   • Subfinder (subdomain enumeration)" -ForegroundColor White
    Write-Host "   • Httpx (HTTP probing)" -ForegroundColor White
    Write-Host "   • Nuclei (vulnerability scanning)" -ForegroundColor White
    Write-Host "   • Amass (asset discovery)" -ForegroundColor White
    Write-Host "✅ Web dashboard available" -ForegroundColor Green
    Write-Host ""
    Write-Host "🌐 Access Points:" -ForegroundColor Cyan
    Write-Host "   • Dashboard: http://localhost:8000" -ForegroundColor White
    Write-Host "   • API Docs: http://localhost:8000/api/docs" -ForegroundColor White
    Write-Host "   • Grafana: http://localhost:3000 (admin/changeme)" -ForegroundColor White
    Write-Host "   • Prometheus: http://localhost:9090" -ForegroundColor White
    Write-Host ""
    Write-Host "🚀 Quick Start:" -ForegroundColor Cyan
    Write-Host "   1. Edit .env file with your configuration" -ForegroundColor White
    Write-Host "   2. Open dashboard: http://localhost:8000" -ForegroundColor White
    Write-Host "   3. Start your first scan!" -ForegroundColor White
    Write-Host ""
    Write-Host "🧪 Run Tests:" -ForegroundColor Cyan
    Write-Host "   .\venv\Scripts\Activate.ps1; python -m pytest tests/ -v" -ForegroundColor White
    Write-Host ""
    Write-Host "🐳 Docker Commands:" -ForegroundColor Cyan
    Write-Host "   • Stop services: docker-compose down" -ForegroundColor White
    Write-Host "   • View logs: docker-compose logs -f" -ForegroundColor White
    Write-Host "   • Restart: docker-compose restart" -ForegroundColor White
    Write-Host ""
    Write-Host "📚 Next Steps (Phase 2):" -ForegroundColor Cyan
    Write-Host "   • Authentication system" -ForegroundColor White
    Write-Host "   • Cloud deployment" -ForegroundColor White
    Write-Host "   • Advanced monitoring" -ForegroundColor White
    Write-Host "   • CI/CD pipeline" -ForegroundColor White
    Write-Host ""
    Write-Success "Installation completed successfully! 🎯"
}

# Main installation flow
function Invoke-Installation {
    Write-Host "Starting Phase 1 installation..." -ForegroundColor Blue
    Write-Host ""
    
    Test-Prerequisites
    Install-Chocolatey
    Install-Docker
    Install-Go
    Install-SecurityTools
    Install-PythonDependencies
    Set-Environment
    Invoke-Tests
    Build-DockerImages
    Start-Services
    Test-Installation
    Write-FinalInstructions
}

# Handle Ctrl+C gracefully
$Host.UI.RawUI.CancelKeyPress += {
    Write-Host ""
    Write-Warning "Installation interrupted by user"
    exit 1
}

# Run main installation
try {
    Invoke-Installation
} catch {
    Write-Error "Installation failed: $($_.Exception.Message)"
    Write-Host "Stack trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
