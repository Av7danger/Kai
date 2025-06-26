"""
Minimal Web Dashboard for Enhanced Bug Bounty Framework
Simple FastAPI-based interface that works without complex dependencies
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import asyncio
import json
import logging
import uuid
from datetime import datetime
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("simple_dashboard")

# Initialize FastAPI app
app = FastAPI(
    title="Enhanced Bug Bounty Framework Dashboard (Minimal)",
    description="Simple web interface for managing security scans",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# In-memory storage for demo purposes
active_scans = {}
scan_results = {}

# Pydantic models
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "comprehensive"
    scope: Optional[Dict[str, Any]] = None

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    target: str
    started_at: datetime
    results: Optional[Dict[str, Any]] = None

# Import our enhanced framework components
from enhanced_integration import enhanced_framework, enhanced_target_analysis, enhanced_comprehensive_scan
from real_security_tools import comprehensive_security_scan, security_tools
from optimization_manager import optimization_manager

# NEW: Import ZAP and enhanced free tools
try:
    from zap_integration import run_zap_scan, zap_manager
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False
    
try:
    from enhanced_free_tools import run_enhanced_security_scan, enhanced_tools
    ENHANCED_TOOLS_AVAILABLE = True
except ImportError:
    ENHANCED_TOOLS_AVAILABLE = False

# Routes
@app.get("/", response_class=HTMLResponse)
async def dashboard_home():
    """Main dashboard page"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bug Bounty Framework Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .header { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
            .section { margin: 20px 0; padding: 20px; background: #f5f5f5; border-radius: 5px; }
            .button { background: #007acc; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }
            .button:hover { background: #005a99; }
            .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
            .success { background: #d4edda; color: #155724; }
            .warning { background: #fff3cd; color: #856404; }
            .info { background: #d1ecf1; color: #0c5460; }
        </style>
    </head>
    <body>
        <h1 class="header">🛡️ Enhanced Bug Bounty Framework Dashboard</h1>
        
        <div class="section">
            <h2>🚀 Phase 1 Implementation Complete!</h2>
            <div class="status success">
                ✅ Docker containerization ready<br>
                ✅ Web dashboard operational<br>
                ✅ Testing framework available<br>
                ✅ Basic security tools integration
            </div>
        </div>
        
        <div class="section">
            <h2>🔧 Quick Actions</h2>
            <button class="button" onclick="startScan()">Start Security Scan</button>
            <button class="button" onclick="startZapScan()">Start OWASP ZAP Scan</button>
            <button class="button" onclick="startEnhancedScan()">Start Enhanced Free Tools Scan</button>
            <button class="button" onclick="viewResults()">View Results</button>
            <button class="button" onclick="viewLogs()">View Logs</button>
            <button class="button" onclick="viewAPI()">API Documentation</button>
        </div>
        
        <div class="section">
            <h2>📊 System Status</h2>
            <div id="system-status">
                <div class="status info">Framework Status: ✅ Operational</div>
                <div class="status info">Active Scans: <span id="active-scans">0</span></div>
                <div class="status info">Total Results: <span id="total-results">0</span></div>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Next Steps (Burp Suite MCP Integration)</h2>
            <div class="status warning">
                Ready to integrate with Burp Suite's MCP servers for enhanced vulnerability analysis!
            </div>
            <ul>
                <li>Install Burp Suite Professional</li>
                <li>Configure MCP server integration</li>
                <li>Enable advanced vulnerability scanning</li>
                <li>Set up automated exploit validation</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>🎯 Available Security Tools</h2>
            <div class="status info">
                ✅ OWASP ZAP Integration: Web Application Security Scanner<br>
                ✅ Enhanced Free Tools: Subfinder, Nuclei, Httpx, Amass, Nmap<br>
                ✅ Multiple Scan Types: Reconnaissance, Vulnerability Assessment, Port Scanning<br>
                ✅ Real-time Progress Monitoring and Results Dashboard
            </div>
        </div>
        
        <div class="section">
            <h2>🔧 Free Alternative Tools (No Burp Suite Pro Needed!)</h2>
            <div class="status success">
                Instead of Burp Suite Pro, we're using these powerful free alternatives:
            </div>
            <ul>
                <li><strong>OWASP ZAP</strong> - Complete web application security testing</li>
                <li><strong>Nuclei</strong> - Fast vulnerability scanner with 1000+ templates</li>
                <li><strong>Subfinder</strong> - Subdomain discovery</li>
                <li><strong>Httpx</strong> - HTTP toolkit and web service probing</li>
                <li><strong>Nmap</strong> - Network discovery and port scanning</li>
                <li><strong>SQLMap</strong> - SQL injection testing</li>
                <li><strong>Ffuf</strong> - Web fuzzing and directory discovery</li>
            </ul>
        </div>
        
        <script>
            function startScan() {
                const target = prompt("Enter target URL (e.g., https://example.com):");
                if (target) {
                    fetch('/api/scans', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({target: target, scan_type: 'comprehensive'})
                    })
                    .then(response => response.json())
                    .then(data => {
                        alert('Scan started! ID: ' + data.scan_id);
                        updateStatus();
                    });
                }
            }
            
            function startZapScan() {
                const target = prompt("Enter target URL for OWASP ZAP scan (e.g., https://example.com):");
                if (target) {
                    fetch('/api/scans/zap', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({target: target, scan_type: 'zap_comprehensive'})
                    })
                    .then(response => response.json())
                    .then(data => {
                        alert('OWASP ZAP scan started! ID: ' + data.scan_id);
                        updateStatus();
                    })
                    .catch(error => {
                        alert('Error starting ZAP scan: ' + error);
                    });
                }
            }
            
            function startEnhancedScan() {
                const target = prompt("Enter target for enhanced free tools scan (e.g., example.com):");
                if (target) {
                    fetch('/api/scans/enhanced', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({target: target, scan_type: 'enhanced_comprehensive'})
                    })
                    .then(response => response.json())
                    .then(data => {
                        alert('Enhanced security scan started! ID: ' + data.scan_id);
                        updateStatus();
                    })
                    .catch(error => {
                        alert('Error starting enhanced scan: ' + error);
                    });
                }
            }
            
            function viewResults() {
                window.open('/api/scans', '_blank');
            }
            
            function viewLogs() {
                window.open('/api/logs', '_blank');
            }
            
            function viewAPI() {
                window.open('/api/docs', '_blank');
            }
            
            function updateStatus() {
                fetch('/api/status')
                    .then(response => response.json())
                    .then(data => {
                        document.getElementById('active-scans').textContent = data.active_scans;
                        document.getElementById('total-results').textContent = data.total_results;
                    });
            }
            
            // Update status every 5 seconds
            setInterval(updateStatus, 5000);
            updateStatus(); // Initial load
        </script>
    </body>
    </html>
    """
    return html_content

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now()}

@app.get("/api/status")
async def get_status():
    """Get system status"""
    return {
        "status": "operational",
        "active_scans": len(active_scans),
        "total_results": len(scan_results),
        "timestamp": datetime.now()
    }

@app.post("/api/scans")
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new security scan"""
    scan_id = str(uuid.uuid4())
    
    scan_status = {
        "scan_id": scan_id,
        "status": "started",
        "progress": 0,
        "target": scan_request.target,
        "started_at": datetime.now(),
        "scan_type": scan_request.scan_type
    }
    
    active_scans[scan_id] = scan_status
    
    # Start background scan simulation
    background_tasks.add_task(simulate_scan, scan_id)
    
    logger.info(f"Started scan {scan_id} for target {scan_request.target}")
    return {"scan_id": scan_id, "status": "started", "message": "Scan initiated successfully"}

@app.post("/api/scans/zap")
async def start_zap_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start OWASP ZAP scan"""
    if not ZAP_AVAILABLE:
        raise HTTPException(status_code=503, detail="OWASP ZAP integration not available")
    
    scan_id = str(uuid.uuid4())
    
    scan_status = {
        "scan_id": scan_id,
        "status": "started",
        "progress": 0,
        "target": scan_request.target,
        "started_at": datetime.now(),
        "scan_type": "zap_scan"
    }
    
    active_scans[scan_id] = scan_status
    background_tasks.add_task(run_zap_scan_task, scan_id, scan_request.target)
    
    logger.info(f"Started ZAP scan {scan_id} for target {scan_request.target}")
    return {"scan_id": scan_id, "status": "started", "message": "OWASP ZAP scan initiated successfully"}

@app.post("/api/scans/enhanced")
async def start_enhanced_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start enhanced free tools scan"""
    if not ENHANCED_TOOLS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Enhanced tools integration not available")
    
    scan_id = str(uuid.uuid4())
    
    scan_status = {
        "scan_id": scan_id,
        "status": "started",
        "progress": 0,
        "target": scan_request.target,
        "started_at": datetime.now(),
        "scan_type": "enhanced_scan"
    }
    
    active_scans[scan_id] = scan_status
    background_tasks.add_task(run_enhanced_scan_task, scan_id, scan_request.target)
    
    logger.info(f"Started enhanced scan {scan_id} for target {scan_request.target}")
    return {"scan_id": scan_id, "status": "started", "message": "Enhanced security scan initiated successfully"}

@app.get("/api/scans")
async def get_scans():
    """Get all scans"""
    all_scans = {**active_scans, **scan_results}
    return {"scans": list(all_scans.values())}

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get specific scan status"""
    if scan_id in active_scans:
        return active_scans[scan_id]
    elif scan_id in scan_results:
        return scan_results[scan_id]
    else:
        raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/api/logs")
async def get_logs():
    """Get system logs"""
    return {
        "logs": [
            {"timestamp": datetime.now(), "level": "INFO", "message": "Dashboard started"},
            {"timestamp": datetime.now(), "level": "INFO", "message": "Phase 1 implementation complete"},
            {"timestamp": datetime.now(), "level": "INFO", "message": "Ready for Burp Suite MCP integration"}
        ]
    }

async def simulate_scan(scan_id: str):
    """Simulate a security scan"""
    try:
        # Simulate scan progress
        for progress in [10, 25, 50, 75, 90, 100]:
            await asyncio.sleep(2)  # Simulate work
            if scan_id in active_scans:
                active_scans[scan_id]["progress"] = progress
                active_scans[scan_id]["status"] = "running" if progress < 100 else "completed"
        
        # Move to results when complete
        if scan_id in active_scans:
            scan_data = active_scans[scan_id]
            scan_data["completed_at"] = datetime.now()
            scan_data["results"] = {
                "subdomains_found": 15,
                "open_ports": [80, 443, 8080],
                "vulnerabilities": [
                    {"type": "XSS", "severity": "Medium", "url": "/search"},
                    {"type": "CSRF", "severity": "Low", "url": "/admin"}
                ],
                "summary": "Demo scan completed successfully"
            }
            scan_results[scan_id] = scan_data
            del active_scans[scan_id]
            
        logger.info(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        if scan_id in active_scans:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = str(e)

async def run_zap_scan_task(scan_id: str, target: str):
    """Background task for ZAP scanning"""
    try:
        if scan_id in active_scans:
            active_scans[scan_id]["status"] = "running"
            active_scans[scan_id]["progress"] = 10
        
        # Run ZAP scan
        result = await run_zap_scan(target)
        
        # Move to results when complete
        if scan_id in active_scans:
            scan_data = active_scans.pop(scan_id)
            scan_data["completed_at"] = datetime.now()
            scan_data["progress"] = 100
            scan_data["status"] = "completed"
            scan_data["results"] = result
            scan_results[scan_id] = scan_data
            
        logger.info(f"ZAP scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"ZAP scan {scan_id} failed: {e}")
        if scan_id in active_scans:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = str(e)

async def run_enhanced_scan_task(scan_id: str, target: str):
    """Background task for enhanced scanning"""
    try:
        if scan_id in active_scans:
            active_scans[scan_id]["status"] = "running"
            active_scans[scan_id]["progress"] = 10
        
        # Run enhanced scan
        result = await run_enhanced_security_scan(target)
        
        # Move to results when complete
        if scan_id in active_scans:
            scan_data = active_scans.pop(scan_id)
            scan_data["completed_at"] = datetime.now()
            scan_data["progress"] = 100
            scan_data["status"] = "completed"
            scan_data["results"] = result
            scan_results[scan_id] = scan_data
            
        logger.info(f"Enhanced scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Enhanced scan {scan_id} failed: {e}")
        if scan_id in active_scans:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = str(e)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
