# Tools Verification Script
Write-Host "Verifying installed security tools..." -ForegroundColor Blue

$tools = @("subfinder", "httpx", "nuclei", "amass", "assetfinder", "ffuf", "nmap")

foreach ($tool in $tools) {
    try {
        $version = & $tool --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ $tool - Available" -ForegroundColor Green
        } else {
            Write-Host "⚠️ $tool - Available but version check failed" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ $tool - Not found" -ForegroundColor Red
    }
}

# Check Docker tools
try {
    docker images owasp/zap2docker-stable --format "table {{.Repository}}:{{.Tag}}" 2>$null | Select-Object -Skip 1
    if ($?) {
        Write-Host "✅ OWASP ZAP Docker - Available" -ForegroundColor Green
    } else {
        Write-Host "❌ OWASP ZAP Docker - Not found" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Docker not available" -ForegroundColor Red
}

Write-Host "Verification complete!" -ForegroundColor Blue
