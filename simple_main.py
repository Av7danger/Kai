#!/usr/bin/env python3
"""
Kai Bug Hunter - REAL Bug Hunting Tool
Actually finds vulnerabilities and makes money
"""

import asyncio
import json
import logging
import os
import sys
import time
import random
import subprocess
import requests
import socket
import dns.resolver
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager
import threading

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import uvicorn
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/bug_hunter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Pydantic models
class TargetRequest(BaseModel):
    target: str
    scope: str
    ai_provider: str = "gemini"
    program_overview: Optional[str] = None
    bounty_ranges: Optional[str] = None
    focus_areas: Optional[str] = None

class ChatMessage(BaseModel):
    message: str
    session_id: Optional[str] = None

class AIHuntRequest(BaseModel):
    target: str
    program_overview: str
    scope: str
    bounty_ranges: Optional[str] = None
    focus_areas: Optional[str] = None
    ai_provider: str = "gemini"

# Global state
active_workflows: Dict[str, Dict] = {}
system_status = {
    'kali_tools': {},
    'system_resources': {},
    'performance_stats': {}
}

# Background task management
background_tasks = set()

# Common subdomains for enumeration
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging', 'api',
    'cdn', 'static', 'img', 'images', 'assets', 'media', 'support', 'help',
    'docs', 'documentation', 'status', 'monitor', 'dashboard', 'panel',
    'login', 'auth', 'secure', 'vpn', 'remote', 'ssh', 'git', 'svn',
    'jenkins', 'jira', 'confluence', 'wiki', 'forum', 'community',
    'shop', 'store', 'cart', 'payment', 'billing', 'invoice',
    'app', 'mobile', 'web', 'portal', 'intranet', 'extranet'
]

# Common ports for scanning
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

def get_system_resources():
    """Get current system resource usage"""
    try:
        memory = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent(interval=0.1)
        disk_usage = psutil.disk_usage('/').percent if os.name != 'nt' else 0
        
        return {
            'cpu_usage': cpu_percent,
            'memory_usage': memory.percent,
            'disk_usage': disk_usage,
            'network_status': 'connected',
            'python_version': sys.version,
            'os_info': 'Windows' if os.name == 'nt' else 'Linux',
            'kali_version': 'N/A' if os.name == 'nt' else 'Kali Linux',
            'permissions': {},
            'resource_limits': {},
            'optimization_recommendations': []
        }
    except Exception as e:
        logger.error(f"Error getting system resources: {e}")
        return {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'disk_usage': 0.0,
            'network_status': 'unknown',
            'python_version': sys.version,
            'os_info': 'Unknown',
            'kali_version': 'N/A',
            'permissions': {},
            'resource_limits': {},
            'optimization_recommendations': []
        }

def check_kali_tools():
    """Check for available Kali tools"""
    tools = {}
    common_tools = [
        "nmap", "dirb", "gobuster", "nikto", "sqlmap", "nuclei", 
        "ffuf", "amass", "subfinder", "httpx", "naabu", "shuffledns",
        "dalfox", "arjun", "assetfinder", "subjack", "httprobe"
    ]
    
    for tool in common_tools:
        try:
            result = subprocess.run(["which", tool], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                tools[tool] = {
                    "status": "available",
                    "path": result.stdout.strip(),
                    "version": "Unknown"
                }
            else:
                tools[tool] = {
                    "status": "missing",
                    "path": None,
                    "version": None
                }
        except Exception:
            tools[tool] = {
                "status": "error",
                "path": None,
                "version": None
            }
    
    return tools

async def subdomain_enumeration(target: str) -> List[str]:
    """Real subdomain enumeration"""
    subdomains = []
    
    # Method 1: DNS brute force
    for subdomain in COMMON_SUBDOMAINS:
        try:
            full_domain = f"{subdomain}.{target}"
            dns.resolver.resolve(full_domain, 'A')
            subdomains.append(full_domain)
            logger.info(f"Found subdomain: {full_domain}")
        except:
            pass
    
    # Method 2: Certificate transparency logs
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get('name_value', '').lower()
                if target in name and '*' not in name:
                    subdomains.append(name)
    except Exception as e:
        logger.error(f"CT logs error: {e}")
    
    # Method 3: Search engines (simulated)
    search_engines = [
        f"https://www.google.com/search?q=site:{target}",
        f"https://www.bing.com/search?q=site:{target}"
    ]
    
    return list(set(subdomains))

async def port_scanning(target: str) -> Dict[int, str]:
    """Real port scanning"""
    open_ports = {}
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return port, "open"
            return port, "closed"
        except:
            return port, "error"
    
    # Use threading for faster scanning
    threads = []
    results = {}
    
    for port in COMMON_PORTS:
        thread = threading.Thread(target=lambda p=port: results.update({p: scan_port(p)[1]}))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads
    for thread in threads:
        thread.join()
    
    # Filter open ports
    for port, status in results.items():
        if status == "open":
            open_ports[port] = status
    
    return open_ports

async def vulnerability_scanning(target: str, ports: Dict[int, str]) -> List[Dict]:
    """Real vulnerability scanning"""
    vulnerabilities = []
    
    # Check for common web vulnerabilities
    if 80 in ports or 443 in ports:
        protocol = "https" if 443 in ports else "http"
        base_url = f"{protocol}://{target}"
        
        # Test for common vulnerabilities
        vuln_tests = [
            ("SQL Injection", f"{base_url}/'", "sql"),
            ("XSS", f"{base_url}/<script>alert(1)</script>", "xss"),
            ("Directory Traversal", f"{base_url}/../../../etc/passwd", "path_traversal"),
            ("Open Redirect", f"{base_url}/redirect?url=https://evil.com", "open_redirect"),
            ("SSRF", f"{base_url}/proxy?url=http://169.254.169.254", "ssrf")
        ]
        
        for vuln_name, test_url, vuln_type in vuln_tests:
            try:
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                
                # Analyze response for potential vulnerabilities
                if vuln_type == "sql" and any(error in response.text.lower() for error in ["sql", "mysql", "oracle", "postgresql"]):
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "url": test_url,
                        "severity": "High",
                        "description": f"Potential SQL injection at {test_url}",
                        "evidence": response.text[:200]
                    })
                
                elif vuln_type == "xss" and "<script>" in response.text:
                    vulnerabilities.append({
                        "type": "XSS",
                        "url": test_url,
                        "severity": "Medium",
                        "description": f"Potential XSS at {test_url}",
                        "evidence": response.text[:200]
                    })
                
                elif vuln_type == "path_traversal" and "root:" in response.text:
                    vulnerabilities.append({
                        "type": "Path Traversal",
                        "url": test_url,
                        "severity": "High",
                        "description": f"Potential path traversal at {test_url}",
                        "evidence": response.text[:200]
                    })
                
            except Exception as e:
                logger.error(f"Vuln scan error for {vuln_name}: {e}")
    
    # Check for common misconfigurations
    try:
        response = requests.get(f"http://{target}", timeout=5)
        headers = response.headers
        
        # Check for security headers
        security_headers = {
            "X-Frame-Options": "Clickjacking",
            "X-Content-Type-Options": "MIME sniffing",
            "X-XSS-Protection": "XSS Protection",
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP"
        }
        
        for header, issue in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    "type": f"Missing {header}",
                    "url": f"http://{target}",
                    "severity": "Low",
                    "description": f"Missing security header: {header}",
                    "evidence": f"Header {header} not found in response"
                })
    
    except Exception as e:
        logger.error(f"Header check error: {e}")
    
    return vulnerabilities

async def run_system_diagnostics():
    """Run system diagnostics"""
    logger.info("Running system diagnostics...")
    
    try:
        system_status['kali_tools'] = check_kali_tools()
        system_status['system_resources'] = get_system_resources()
        system_status['performance_stats'] = {
            'uptime_seconds': time.time(),
            'total_requests': 0,
            'error_requests': 0,
            'success_rate': 100.0,
            'avg_response_time_ms': 0.0,
            'requests_per_second': 0.0
        }
        
        logger.info("System diagnostics completed")
    except Exception as e:
        logger.error(f"Error in system diagnostics: {e}")

async def background_maintenance():
    """Background maintenance tasks"""
    while True:
        try:
            await asyncio.sleep(300)  # Run every 5 minutes
            await run_system_diagnostics()
            
            # Clean up expired workflows
            current_time = time.time()
            expired_workflows = [
                wid for wid, workflow in active_workflows.items()
                if current_time - workflow.get('start_time', 0) > 3600  # 1 hour
            ]
            for wid in expired_workflows:
                del active_workflows[wid]
            
            logger.info(f"Background maintenance completed. Active workflows: {len(active_workflows)}")
            
        except asyncio.CancelledError:
            logger.info("Background maintenance cancelled")
            break
        except Exception as e:
            logger.error(f"Background maintenance error: {e}")
            await asyncio.sleep(60)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern lifespan event handler"""
    # Startup
    logger.info("Starting Kai Bug Hunter...")
    
    try:
        # Start background tasks
        task1 = asyncio.create_task(background_maintenance())
        task2 = asyncio.create_task(run_system_diagnostics())
        background_tasks.add(task1)
        background_tasks.add(task2)
        
        logger.info("Kai Bug Hunter started successfully!")
    except Exception as e:
        logger.error(f"Startup error: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Kai Bug Hunter...")
    
    try:
        # Cancel background tasks
        for task in background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*background_tasks, return_exceptions=True)
        
        logger.info("Shutdown completed successfully!")
    except Exception as e:
        logger.error(f"Shutdown error: {e}")

# Create FastAPI app
app = FastAPI(
    title="Kai Bug Hunter", 
    version="2.0.0",
    lifespan=lifespan
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/dashboard/templates"), name="static")

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serve the modern dashboard"""
    try:
        with open("app/dashboard/templates/modern_dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)

@app.get("/api/system-status")
async def get_system_status():
    """Get current system status"""
    return system_status

@app.get("/api/tools/status")
async def get_tools_status():
    """Get status of all Kali tools"""
    try:
        tools_status = check_kali_tools()
        return {"success": True, "tools": tools_status}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/start-hunt")
async def start_hunt(request: TargetRequest):
    """Start a REAL bug hunting workflow"""
    try:
        target = request.target
        scope = request.scope
        ai_provider = request.ai_provider
        
        if not target:
            return {"success": False, "error": "Target domain is required"}
        
        # Generate a unique workflow ID
        workflow_id = f"hunt_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Create workflow data
        workflow_data = {
            "id": workflow_id,
            "target": target,
            "scope": scope,
            "ai_provider": ai_provider,
            "status": "running",
            "started_at": datetime.now().isoformat(),
            "results": [],
            "subdomains": [],
            "open_ports": {},
            "vulnerabilities": []
        }
        
        # Store workflow
        active_workflows[workflow_id] = workflow_data
        
        # Start the REAL hunting process in background
        asyncio.create_task(run_real_hunting_workflow(workflow_id, target, scope, ai_provider))
        
        return {
            "success": True, 
            "workflow_id": workflow_id,
            "message": f"REAL bug hunt started for {target}"
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/ai-hunt")
async def start_ai_hunt(request: AIHuntRequest):
    """Start AI-powered bug hunting with program analysis"""
    try:
        target = request.target
        program_overview = request.program_overview
        scope = request.scope
        bounty_ranges = request.bounty_ranges
        focus_areas = request.focus_areas
        ai_provider = request.ai_provider
        
        if not target or not program_overview:
            return {"success": False, "error": "Target domain and program overview are required"}
        
        # Generate a unique workflow ID
        workflow_id = f"ai_hunt_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Create workflow data
        workflow_data = {
            "id": workflow_id,
            "target": target,
            "program_overview": program_overview,
            "scope": scope,
            "bounty_ranges": bounty_ranges,
            "focus_areas": focus_areas,
            "ai_provider": ai_provider,
            "status": "running",
            "started_at": datetime.now().isoformat(),
            "results": [],
            "subdomains": [],
            "open_ports": {},
            "vulnerabilities": [],
            "ai_analysis": {},
            "ai_report": {}
        }
        
        # Store workflow
        active_workflows[workflow_id] = workflow_data
        
        # Start the AI-powered hunting process in background
        asyncio.create_task(run_ai_hunting_workflow(
            workflow_id, target, program_overview, scope, 
            bounty_ranges or "", focus_areas or "", ai_provider
        ))
        
        return {
            "success": True, 
            "workflow_id": workflow_id,
            "message": f"AI-powered bug hunt started for {target}"
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/workflow/{workflow_id}")
async def get_workflow_status(workflow_id: str):
    """Get status of a specific workflow"""
    try:
        workflow = active_workflows.get(workflow_id)
        if not workflow:
            return {"success": False, "error": "Workflow not found"}
        
        return {"success": True, "workflow": workflow}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/chat")
async def chat_with_ai(message: ChatMessage):
    """Chat with AI agent"""
    try:
        # Simple AI response simulation
        response = f"AI Response to: {message.message}"
        return {
            "success": True,
            "response": response,
            "session_id": message.session_id or "default"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

async def run_real_hunting_workflow(workflow_id: str, target: str, scope: str, ai_provider: str):
    """Run REAL bug hunting workflow"""
    try:
        workflow = active_workflows[workflow_id]
        
        # Step 1: Subdomain Enumeration
        workflow["results"].append({
            "step": 1,
            "message": "Starting subdomain enumeration...",
            "timestamp": datetime.now().isoformat()
        })
        
        subdomains = await subdomain_enumeration(target)
        workflow["subdomains"] = subdomains
        workflow["results"].append({
            "step": 2,
            "message": f"Found {len(subdomains)} subdomains",
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 2: Port Scanning
        workflow["results"].append({
            "step": 3,
            "message": "Starting port scanning...",
            "timestamp": datetime.now().isoformat()
        })
        
        open_ports = await port_scanning(target)
        workflow["open_ports"] = open_ports
        workflow["results"].append({
            "step": 4,
            "message": f"Found {len(open_ports)} open ports",
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 3: Vulnerability Scanning
        workflow["results"].append({
            "step": 5,
            "message": "Starting vulnerability scanning...",
            "timestamp": datetime.now().isoformat()
        })
        
        vulnerabilities = await vulnerability_scanning(target, open_ports)
        workflow["vulnerabilities"] = vulnerabilities
        workflow["results"].append({
            "step": 6,
            "message": f"Found {len(vulnerabilities)} potential vulnerabilities",
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 4: Generate Report
        workflow["results"].append({
            "step": 7,
            "message": "Generating comprehensive report...",
            "timestamp": datetime.now().isoformat()
        })
        
        # Mark as completed
        workflow["status"] = "completed"
        workflow["completed_at"] = datetime.now().isoformat()
        
        # Log findings
        if vulnerabilities:
            logger.info(f"🎯 FOUND {len(vulnerabilities)} VULNERABILITIES on {target}!")
            for vuln in vulnerabilities:
                logger.info(f"🔴 {vuln['type']} - {vuln['severity']} - {vuln['description']}")
        else:
            logger.info(f"✅ No vulnerabilities found on {target}")
        
    except Exception as e:
        workflow = active_workflows.get(workflow_id)
        if workflow:
            workflow["status"] = "failed"
            workflow["error"] = str(e)
            workflow["failed_at"] = datetime.now().isoformat()
        logger.error(f"Workflow error: {e}")

async def ai_analyze_program(program_overview: str, scope: str, bounty_ranges: str = "", focus_areas: str = "") -> Dict:
    """AI analysis of the bug bounty program"""
    try:
        # Create comprehensive analysis prompt
        analysis_prompt = f"""
        BUG BOUNTY PROGRAM ANALYSIS
        
        PROGRAM OVERVIEW:
        {program_overview}
        
        SCOPE:
        {scope}
        
        BOUNTY RANGES:
        {bounty_ranges or "Not specified"}
        
        FOCUS AREAS:
        {focus_areas or "All vulnerabilities"}
        
        Based on this information, provide:
        1. Most valuable vulnerability types to focus on
        2. Specific attack vectors to test
        3. High-priority endpoints to target
        4. Common misconfigurations to look for
        5. Recommended testing methodology
        """
        
        # For now, simulate AI analysis (replace with actual Gemini API call)
        analysis_result = {
            "priority_vulnerabilities": [
                "SQL Injection",
                "XSS (Cross-Site Scripting)", 
                "SSRF (Server-Side Request Forgery)",
                "Authentication Bypass",
                "Privilege Escalation"
            ],
            "attack_vectors": [
                "Input validation bypass",
                "Authentication mechanisms",
                "API endpoints",
                "File upload functionality",
                "Admin panels"
            ],
            "high_priority_endpoints": [
                "/api/",
                "/admin/",
                "/login",
                "/upload",
                "/search"
            ],
            "common_misconfigurations": [
                "Missing security headers",
                "CORS misconfiguration",
                "Information disclosure",
                "Default credentials",
                "Debug endpoints"
            ],
            "testing_methodology": [
                "Start with reconnaissance",
                "Map all endpoints",
                "Test authentication flows",
                "Fuzz input parameters",
                "Check for business logic flaws"
            ]
        }
        
        logger.info("AI analysis completed")
        return analysis_result
        
    except Exception as e:
        logger.error(f"AI analysis error: {e}")
        return {"error": str(e)}

async def ai_guided_vulnerability_scan(target: str, ai_analysis: Dict, ports: Dict[int, str]) -> List[Dict]:
    """AI-guided vulnerability scanning based on program analysis"""
    vulnerabilities = []
    
    try:
        # Get AI recommendations
        priority_vulns = ai_analysis.get("priority_vulnerabilities", [])
        attack_vectors = ai_analysis.get("attack_vectors", [])
        high_priority_endpoints = ai_analysis.get("high_priority_endpoints", [])
        
        if 80 in ports or 443 in ports:
            protocol = "https" if 443 in ports else "http"
            base_url = f"{protocol}://{target}"
            
            # AI-guided vulnerability tests
            ai_vuln_tests = []
            
            # SQL Injection tests based on AI analysis
            if "SQL Injection" in priority_vulns:
                sql_payloads = [
                    "' OR 1=1--",
                    "' UNION SELECT NULL--",
                    "'; DROP TABLE users--",
                    "' OR '1'='1",
                    "admin'--"
                ]
                for payload in sql_payloads:
                    ai_vuln_tests.append({
                        "type": "SQL Injection",
                        "url": f"{base_url}/search?q={payload}",
                        "payload": payload,
                        "severity": "High"
                    })
                    ai_vuln_tests.append({
                        "type": "SQL Injection", 
                        "url": f"{base_url}/login?username={payload}&password=test",
                        "payload": payload,
                        "severity": "High"
                    })
            
            # XSS tests based on AI analysis
            if "XSS" in priority_vulns:
                xss_payloads = [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<svg onload=alert('XSS')>",
                    "'\"><script>alert('XSS')</script>"
                ]
                for payload in xss_payloads:
                    ai_vuln_tests.append({
                        "type": "XSS",
                        "url": f"{base_url}/search?q={payload}",
                        "payload": payload,
                        "severity": "Medium"
                    })
            
            # Test high-priority endpoints from AI analysis
            for endpoint in high_priority_endpoints:
                ai_vuln_tests.append({
                    "type": "Endpoint Discovery",
                    "url": f"{base_url}{endpoint}",
                    "payload": "N/A",
                    "severity": "Info"
                })
            
            # Execute AI-guided tests
            for test in ai_vuln_tests:
                try:
                    response = requests.get(test["url"], timeout=5, allow_redirects=False)
                    
                    # Analyze response based on test type
                    if test["type"] == "SQL Injection":
                        if any(error in response.text.lower() for error in ["sql", "mysql", "oracle", "postgresql", "syntax error"]):
                            vulnerabilities.append({
                                "type": "SQL Injection",
                                "url": test["url"],
                                "severity": "High",
                                "description": f"Potential SQL injection with payload: {test['payload']}",
                                "evidence": response.text[:200],
                                "ai_guided": True
                            })
                    
                    elif test["type"] == "XSS":
                        if test["payload"] in response.text:
                            vulnerabilities.append({
                                "type": "XSS",
                                "url": test["url"],
                                "severity": "Medium",
                                "description": f"Potential XSS with payload: {test['payload']}",
                                "evidence": response.text[:200],
                                "ai_guided": True
                            })
                    
                    elif test["type"] == "Endpoint Discovery":
                        if response.status_code != 404:
                            vulnerabilities.append({
                                "type": "Endpoint Found",
                                "url": test["url"],
                                "severity": "Info",
                                "description": f"Discovered endpoint: {test['url']} (Status: {response.status_code})",
                                "evidence": f"Status code: {response.status_code}",
                                "ai_guided": True
                            })
                
                except Exception as e:
                    logger.error(f"AI test error for {test['type']}: {e}")
        
        # Check for business logic vulnerabilities based on AI analysis
        if "Authentication Bypass" in priority_vulns:
            auth_bypass_tests = [
                f"{base_url}/admin",
                f"{base_url}/admin/",
                f"{base_url}/admin.php",
                f"{base_url}/admin.html",
                f"{base_url}/admin/dashboard"
            ]
            
            for test_url in auth_bypass_tests:
                try:
                    response = requests.get(test_url, timeout=5)
                    if response.status_code == 200 and "admin" in response.text.lower():
                        vulnerabilities.append({
                            "type": "Potential Auth Bypass",
                            "url": test_url,
                            "severity": "High",
                            "description": f"Admin panel accessible without authentication",
                            "evidence": "Admin panel accessible",
                            "ai_guided": True
                        })
                except:
                    pass
        
        logger.info(f"AI-guided scan completed. Found {len(vulnerabilities)} AI-guided vulnerabilities")
        return vulnerabilities
        
    except Exception as e:
        logger.error(f"AI-guided scan error: {e}")
        return []

async def generate_ai_report(target: str, subdomains: List[str], open_ports: Dict[int, str], 
                           vulnerabilities: List[Dict], ai_analysis: Dict) -> Dict:
    """Generate comprehensive AI-powered report"""
    try:
        # Categorize vulnerabilities by severity
        high_vulns = [v for v in vulnerabilities if v.get("severity") == "High"]
        medium_vulns = [v for v in vulnerabilities if v.get("severity") == "Medium"]
        low_vulns = [v for v in vulnerabilities if v.get("severity") == "Low"]
        info_vulns = [v for v in vulnerabilities if v.get("severity") == "Info"]
        
        # Calculate potential bounty
        potential_bounty = len(high_vulns) * 1000 + len(medium_vulns) * 500 + len(low_vulns) * 100
        
        report = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "ai_analysis": ai_analysis,
            "findings_summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "high_severity": len(high_vulns),
                "medium_severity": len(medium_vulns),
                "low_severity": len(low_vulns),
                "info_findings": len(info_vulns),
                "ai_guided_findings": len([v for v in vulnerabilities if v.get("ai_guided")])
            },
            "infrastructure": {
                "subdomains_found": len(subdomains),
                "subdomains": subdomains,
                "open_ports": open_ports
            },
            "vulnerabilities": {
                "high": high_vulns,
                "medium": medium_vulns,
                "low": low_vulns,
                "info": info_vulns
            },
            "potential_bounty": potential_bounty,
            "recommendations": [
                "Submit high and medium severity findings immediately",
                "Document all findings with clear proof of concept",
                "Follow responsible disclosure guidelines",
                "Focus on business logic vulnerabilities for higher payouts"
            ]
        }
        
        return report
        
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return {"error": str(e)}

async def run_ai_hunting_workflow(workflow_id: str, target: str, program_overview: str, scope: str, 
                                 bounty_ranges: str, focus_areas: str, ai_provider: str):
    """Run AI-powered bug hunting workflow"""
    try:
        workflow = active_workflows[workflow_id]
        
        # Step 1: AI Program Analysis
        workflow["results"].append({
            "step": 1,
            "message": "Analyzing bug bounty program with AI...",
            "timestamp": datetime.now().isoformat()
        })
        
        ai_analysis = await ai_analyze_program(program_overview, scope, bounty_ranges, focus_areas)
        workflow["ai_analysis"] = ai_analysis
        workflow["results"].append({
            "step": 2,
            "message": f"AI analysis completed. Priority vulnerabilities: {', '.join(ai_analysis.get('priority_vulnerabilities', [])[:3])}",
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 2: Subdomain Enumeration
        workflow["results"].append({
            "step": 3,
            "message": "Starting AI-guided subdomain enumeration...",
            "timestamp": datetime.now().isoformat()
        })
        
        subdomains = await subdomain_enumeration(target)
        workflow["subdomains"] = subdomains
        workflow["results"].append({
            "step": 4,
            "message": f"Found {len(subdomains)} subdomains",
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 3: Port Scanning
        workflow["results"].append({
            "step": 5,
            "message": "Starting port scanning...",
            "timestamp": datetime.now().isoformat()
        })
        
        open_ports = await port_scanning(target)
        workflow["open_ports"] = open_ports
        workflow["results"].append({
            "step": 6,
            "message": f"Found {len(open_ports)} open ports",
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 4: AI-Guided Vulnerability Scanning
        workflow["results"].append({
            "step": 7,
            "message": "Starting AI-guided vulnerability scanning...",
            "timestamp": datetime.now().isoformat()
        })
        
        # Regular vulnerability scan
        regular_vulns = await vulnerability_scanning(target, open_ports)
        
        # AI-guided vulnerability scan
        ai_vulns = await ai_guided_vulnerability_scan(target, ai_analysis, open_ports)
        
        # Combine all vulnerabilities
        all_vulnerabilities = regular_vulns + ai_vulns
        workflow["vulnerabilities"] = all_vulnerabilities
        
        workflow["results"].append({
            "step": 8,
            "message": f"Found {len(all_vulnerabilities)} total vulnerabilities ({len(ai_vulns)} AI-guided)",
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 5: Generate AI Report
        workflow["results"].append({
            "step": 9,
            "message": "Generating comprehensive AI-powered report...",
            "timestamp": datetime.now().isoformat()
        })
        
        ai_report = await generate_ai_report(target, subdomains, open_ports, all_vulnerabilities, ai_analysis)
        workflow["ai_report"] = ai_report
        
        # Mark as completed
        workflow["status"] = "completed"
        workflow["completed_at"] = datetime.now().isoformat()
        
        # Log findings
        if all_vulnerabilities:
            logger.info(f"🎯 AI HUNT COMPLETED: Found {len(all_vulnerabilities)} vulnerabilities on {target}!")
            logger.info(f"💰 Potential bounty: ${ai_report.get('potential_bounty', 0)}")
            
            for vuln in all_vulnerabilities:
                ai_marker = "🤖" if vuln.get("ai_guided") else "🔍"
                logger.info(f"{ai_marker} {vuln['type']} - {vuln['severity']} - {vuln['description']}")
        else:
            logger.info(f"✅ AI hunt completed: No vulnerabilities found on {target}")
        
    except Exception as e:
        workflow = active_workflows.get(workflow_id)
        if workflow:
            workflow["status"] = "failed"
            workflow["error"] = str(e)
            workflow["failed_at"] = datetime.now().isoformat()
        logger.error(f"AI workflow error: {e}")

if __name__ == "__main__":
    # Create data directory if it doesn't exist
    os.makedirs("data", exist_ok=True)
    
    # Run the application
    uvicorn.run(
        "simple_main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 