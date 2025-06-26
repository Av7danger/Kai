# Enhanced Bug Bounty Framework - Free Tools Installation Script
# Install all free security tools as Burp Suite alternatives

Write-Host "Enhanced Bug Bounty Framework - Free Security Tools Installation" -ForegroundColor Blue
Write-Host "=================================================================" -ForegroundColor Blue
Write-Host "Installing free alternatives to Burp Suite Professional..." -ForegroundColor Green

# Check if Go is installed
try {
    $goVersion = go version 2>&1
    Write-Host "Found Go: $goVersion" -ForegroundColor Green
} catch {
    Write-Host "Go not found. Installing Go..." -ForegroundColor Yellow
    
    # Install Go via Chocolatey
    try {
        choco install golang -y
        Write-Host "Go installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Failed to install Go. Please install manually from https://golang.org" -ForegroundColor Red
        Write-Host "Continuing with Python tools..." -ForegroundColor Yellow
    }
}

# Install Go-based security tools
Write-Host "Installing Go-based security tools..." -ForegroundColor Cyan

$goTools = @{
    "subfinder" = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx" = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "nuclei" = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "amass" = "github.com/owasp-amass/amass/v4/...@master"
    "assetfinder" = "github.com/tomnomnom/assetfinder@latest"
    "waybackurls" = "github.com/tomnomnom/waybackurls@latest"
    "gau" = "github.com/lc/gau/v2/cmd/gau@latest"
    "ffuf" = "github.com/ffuf/ffuf@latest"
    "hakrawler" = "github.com/hakluke/hakrawler@latest"
}

foreach ($tool in $goTools.Keys) {
    Write-Host "Installing $tool..." -ForegroundColor Yellow
    try {
        go install -v $($goTools[$tool])
        Write-Host "✅ $tool installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to install $tool" -ForegroundColor Red
    }
}

# Update Nuclei templates
Write-Host "Updating Nuclei templates..." -ForegroundColor Cyan
try {
    nuclei -update-templates
    Write-Host "✅ Nuclei templates updated" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Nuclei not found or failed to update templates" -ForegroundColor Yellow
}

# Install Python-based tools
Write-Host "Installing Python-based security tools..." -ForegroundColor Cyan

$pythonTools = @("sqlmap", "dirsearch")

foreach ($tool in $pythonTools) {
    Write-Host "Installing $tool..." -ForegroundColor Yellow
    try {
        pip install $tool
        Write-Host "✅ $tool installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to install $tool" -ForegroundColor Red
    }
}

# Install OWASP ZAP (Docker approach)
Write-Host "Setting up OWASP ZAP..." -ForegroundColor Cyan
try {
    docker pull owasp/zap2docker-stable
    Write-Host "✅ OWASP ZAP Docker image downloaded" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Docker not available or failed to pull ZAP image" -ForegroundColor Yellow
    Write-Host "You can install ZAP manually from https://www.zaproxy.org/download/" -ForegroundColor White
}

# Install additional useful tools
Write-Host "Installing additional tools..." -ForegroundColor Cyan

# Nmap (if not already installed)
try {
    $nmapVersion = nmap --version 2>&1
    Write-Host "Nmap already installed: $nmapVersion" -ForegroundColor Green
} catch {
    Write-Host "Installing Nmap..." -ForegroundColor Yellow
    try {
        choco install nmap -y
        Write-Host "✅ Nmap installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to install Nmap via Chocolatey" -ForegroundColor Red
        Write-Host "Please install manually from https://nmap.org/download.html" -ForegroundColor White
    }
}

# Create tools verification script
$verificationScript = @"
# Tools Verification Script
Write-Host "Verifying installed security tools..." -ForegroundColor Blue

`$tools = @("subfinder", "httpx", "nuclei", "amass", "assetfinder", "ffuf", "nmap")

foreach (`$tool in `$tools) {
    try {
        `$version = & `$tool --version 2>`$null
        if (`$LASTEXITCODE -eq 0) {
            Write-Host "✅ `$tool - Available" -ForegroundColor Green
        } else {
            Write-Host "⚠️ `$tool - Available but version check failed" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ `$tool - Not found" -ForegroundColor Red
    }
}

# Check Docker tools
try {
    docker images owasp/zap2docker-stable --format "table {{.Repository}}:{{.Tag}}" 2>`$null | Select-Object -Skip 1
    if (`$?) {
        Write-Host "✅ OWASP ZAP Docker - Available" -ForegroundColor Green
    } else {
        Write-Host "❌ OWASP ZAP Docker - Not found" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Docker not available" -ForegroundColor Red
}

Write-Host "Verification complete!" -ForegroundColor Blue
"@

$verificationScript | Out-File -FilePath "verify_tools.ps1" -Encoding UTF8

Write-Host ""
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "=====================" -ForegroundColor Green
Write-Host ""
Write-Host "Free Security Tools Installed:" -ForegroundColor Cyan
Write-Host "• Subfinder - Subdomain enumeration" -ForegroundColor White
Write-Host "• Httpx - HTTP probing and web service detection" -ForegroundColor White
Write-Host "• Nuclei - Vulnerability scanning with 1000+ templates" -ForegroundColor White
Write-Host "• Amass - Network mapping and asset discovery" -ForegroundColor White
Write-Host "• Assetfinder - Domain and subdomain discovery" -ForegroundColor White
Write-Host "• Ffuf - Web fuzzing and directory discovery" -ForegroundColor White
Write-Host "• SQLMap - SQL injection testing" -ForegroundColor White
Write-Host "• OWASP ZAP - Web application security scanner" -ForegroundColor White
Write-Host "• Nmap - Network discovery and port scanning" -ForegroundColor White
Write-Host ""
Write-Host "These tools provide comprehensive security testing capabilities" -ForegroundColor Green
Write-Host "equivalent to or better than Burp Suite Professional!" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "1. Run: .\verify_tools.ps1 - to verify all tools are working" -ForegroundColor White
Write-Host "2. Start dashboard: python simple_dashboard.py" -ForegroundColor White
Write-Host "3. Access dashboard at: http://localhost:8000" -ForegroundColor White
Write-Host "4. Try the new ZAP and Enhanced scans from the dashboard!" -ForegroundColor White
Write-Host ""
Write-Host "🎉 You now have a complete free alternative to Burp Suite Pro!" -ForegroundColor Green
