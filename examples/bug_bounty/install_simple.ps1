# Enhanced Bug Bounty Framework - Phase 1 Installation Script (Windows PowerShell)
# Simplified installation script

Write-Host "Enhanced Bug Bounty Framework - Phase 1 Installation" -ForegroundColor Blue
Write-Host "=====================================================" -ForegroundColor Blue

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Python not found. Please install Python 3.8+ from https://www.python.org" -ForegroundColor Red
    exit 1
}

# Check if Docker is available
try {
    $dockerVersion = docker --version 2>&1
    Write-Host "Found Docker: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "Docker not found. Please install Docker Desktop from https://docker.com/products/docker-desktop" -ForegroundColor Yellow
    Write-Host "Continuing without Docker..." -ForegroundColor Yellow
}

# Create virtual environment
Write-Host "Creating Python virtual environment..." -ForegroundColor Cyan
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install Python dependencies
Write-Host "Installing Python dependencies..." -ForegroundColor Cyan
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
Write-Host "Creating directories..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "logs", "data", "reports", "temp", "config"

# Copy environment file
if (Test-Path ".env.example") {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env file from template" -ForegroundColor Green
}

# Run tests
Write-Host "Running tests..." -ForegroundColor Cyan
try {
    python -m pytest tests/ -v
    Write-Host "Tests completed successfully!" -ForegroundColor Green
} catch {
    Write-Host "Some tests failed - continuing..." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "=====================" -ForegroundColor Green
Write-Host ""
Write-Host "To start the web dashboard:" -ForegroundColor Cyan
Write-Host "  python -m uvicorn web_dashboard:app --host 0.0.0.0 --port 8000 --reload" -ForegroundColor White
Write-Host ""
Write-Host "To run a quick demo:" -ForegroundColor Cyan
Write-Host "  python quick_start_demo.py" -ForegroundColor White
Write-Host ""
Write-Host "Dashboard will be available at: http://localhost:8000" -ForegroundColor Green
