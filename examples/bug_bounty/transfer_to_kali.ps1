# 📦 TRANSFER FILES TO KALI LINUX
# Run this PowerShell script on Windows to transfer files to your Kali Linux system

param(
    [Parameter(Mandatory=$true)]
    [string]$KaliIP,
    
    [Parameter(Mandatory=$true)]
    [string]$KaliUser,
    
    [string]$KaliPath = "~/bug_bounty_pro"
)

Write-Host "🚀 Transferring Bug Bounty Framework to Kali Linux" -ForegroundColor Green
Write-Host "Target: $KaliUser@$KaliIP" -ForegroundColor Yellow

# Check if we're in the right directory
$currentPath = Get-Location
if (-not (Test-Path "kali_bb_pro.py")) {
    Write-Host "❌ Error: Please run this script from the bug_bounty directory" -ForegroundColor Red
    Write-Host "Current path: $currentPath" -ForegroundColor Yellow
    Write-Host "Expected files: kali_bb_pro.py, ultra_optimized_gemini_system.py, etc." -ForegroundColor Yellow
    exit 1
}

# Files to transfer
$files = @(
    "kali_bb_pro.py",
    "ultra_optimized_gemini_system.py", 
    "personal_bug_bounty_optimizer.py",
    "quick_start_config.py",
    "gemini_analytics_dashboard.py",
    "production_deployment.py",
    "system_validator.py",
    "advanced_multi_target_orchestrator.py",
    "intelligent_vulnerability_correlator.py",
    "complete_platform_integration.py",
    "explainable_ai_module.py",
    "human_in_the_loop_framework.py",
    "dynamic_legal_compliance_module.py",
    "advanced_data_provenance_module.py",
    "strategic_ai_framework_integration.py",
    "quick_start.py",
    "batch_hunt.sh",
    "simple_kali_setup.sh",
    "RUN_ON_KALI_LINUX.md",
    "HOW_TO_USE.md",
    "practice_targets.txt",
    "demo_targets.txt"
)

Write-Host "📋 Files to transfer:" -ForegroundColor Cyan
foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "  ✅ $file" -ForegroundColor Green
    } else {
        Write-Host "  ❌ $file (missing)" -ForegroundColor Red
    }
}

Write-Host "`n🔄 Starting transfer..." -ForegroundColor Yellow

# Create zip package
$zipFile = "bug_bounty_framework.zip"
Write-Host "📦 Creating package: $zipFile" -ForegroundColor Cyan

if (Test-Path $zipFile) {
    Remove-Item $zipFile -Force
}

# Add existing files to zip
$existingFiles = $files | Where-Object { Test-Path $_ }
Compress-Archive -Path $existingFiles -DestinationPath $zipFile -Force

Write-Host "✅ Package created successfully" -ForegroundColor Green

# Transfer using SCP (requires Windows Subsystem for Linux or OpenSSH)
Write-Host "🚁 Transferring to Kali Linux..." -ForegroundColor Cyan

try {
    # Try using SCP
    $scpCommand = "scp `"$zipFile`" ${KaliUser}@${KaliIP}:${KaliPath}/"
    Write-Host "Command: $scpCommand" -ForegroundColor Gray
    
    Invoke-Expression $scpCommand
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Transfer completed successfully!" -ForegroundColor Green
        
        Write-Host "`n🎯 Next steps on your Kali Linux system:" -ForegroundColor Yellow
        Write-Host "1. SSH to Kali: ssh $KaliUser@$KaliIP" -ForegroundColor White
        Write-Host "2. Extract files: cd $KaliPath && unzip $zipFile" -ForegroundColor White
        Write-Host "3. Run setup: chmod +x simple_kali_setup.sh && ./simple_kali_setup.sh" -ForegroundColor White
        Write-Host "4. Configure API: nano quick_start_config.py" -ForegroundColor White
        Write-Host "5. Start hunting: python3 kali_bb_pro.py status" -ForegroundColor White
        
    } else {
        throw "SCP transfer failed"
    }
    
} catch {
    Write-Host "❌ SCP transfer failed. Trying alternative methods..." -ForegroundColor Red
    
    Write-Host "`n📋 Manual transfer instructions:" -ForegroundColor Yellow
    Write-Host "1. Copy $zipFile to your Kali Linux system using:" -ForegroundColor White
    Write-Host "   - USB drive" -ForegroundColor Gray
    Write-Host "   - Shared folder" -ForegroundColor Gray
    Write-Host "   - File sharing service" -ForegroundColor Gray
    Write-Host "   - WinSCP or similar tool" -ForegroundColor Gray
    
    Write-Host "`n2. On Kali Linux, run:" -ForegroundColor White
    Write-Host "   mkdir -p $KaliPath" -ForegroundColor Gray
    Write-Host "   cd $KaliPath" -ForegroundColor Gray
    Write-Host "   unzip $zipFile" -ForegroundColor Gray
    Write-Host "   chmod +x simple_kali_setup.sh" -ForegroundColor Gray
    Write-Host "   ./simple_kali_setup.sh" -ForegroundColor Gray
}

Write-Host "`n🎉 Transfer script completed!" -ForegroundColor Green
Write-Host "Package location: $((Get-Location).Path)\$zipFile" -ForegroundColor Cyan

# Cleanup option
$cleanup = Read-Host "`nDelete the zip file? (y/N)"
if ($cleanup -eq 'y' -or $cleanup -eq 'Y') {
    Remove-Item $zipFile -Force
    Write-Host "🗑️ Zip file deleted" -ForegroundColor Gray
}
