"""
OWASP ZAP Integration for Enhanced Bug Bounty Framework
Free and open-source web application security scanner integration
"""

import asyncio
import json
import logging
import time
import requests
import subprocess
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import os
from pathlib import Path

logger = logging.getLogger('zap_integration')

@dataclass
class ZAPScanResult:
    """ZAP scan result structure"""
    scan_id: str
    target: str
    alerts: List[Dict[str, Any]]
    status: str
    progress: int
    start_time: float
    end_time: Optional[float] = None

class OWASPZAPManager:
    """Manager for OWASP ZAP integration"""
    
    def __init__(self, zap_host: str = "localhost", zap_port: int = 8080):
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.zap_url = f"http://{zap_host}:{zap_port}"
        self.api_key = None
        self.session = requests.Session()
        self.active_scans = {}
        
    async def start_zap_daemon(self, headless: bool = True):
        """Start ZAP daemon"""
        try:
            # Check if ZAP is already running
            if await self.is_zap_running():
                logger.info("ZAP is already running")
                return True
            
            logger.info("Starting OWASP ZAP daemon...")
            
            # Try common ZAP installation paths
            zap_paths = [
                "zap.sh",  # Linux/macOS
                "zap.bat",  # Windows
                "/usr/share/zaproxy/zap.sh",  # Ubuntu
                "C:\\Program Files\\OWASP\\Zed Attack Proxy\\zap.bat",  # Windows default
                "C:\\Program Files (x86)\\OWASP\\Zed Attack Proxy\\zap.bat"
            ]
            
            zap_cmd = None
            for path in zap_paths:
                if os.path.exists(path):
                    zap_cmd = path
                    break
            
            if not zap_cmd:
                # Try docker approach
                logger.info("ZAP not found locally, trying Docker...")
                return await self.start_zap_docker()
            
            # Start ZAP
            cmd = [zap_cmd, "-daemon", "-port", str(self.zap_port)]
            if headless:
                cmd.append("-config")
                cmd.append("api.disablekey=true")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            
            # Wait for ZAP to start
            for _ in range(30):  # Wait up to 30 seconds
                if await self.is_zap_running():
                    logger.info("ZAP started successfully")
                    return True
                await asyncio.sleep(1)
            
            logger.error("Failed to start ZAP daemon")
            return False
            
        except Exception as e:
            logger.error(f"Error starting ZAP: {e}")
            return False
    
    async def start_zap_docker(self):
        """Start ZAP using Docker"""
        try:
            logger.info("Starting ZAP with Docker...")
            
            cmd = [
                "docker", "run", "-d",
                "--name", "owasp-zap",
                "-p", f"{self.zap_port}:8080",
                "owasp/zap2docker-stable",
                "zap.sh", "-daemon",
                "-host", "0.0.0.0",
                "-port", "8080",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true",
                "-config", "api.disablekey=true"
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0:
                # Wait for container to be ready
                for _ in range(60):  # Wait up to 60 seconds for Docker
                    if await self.is_zap_running():
                        logger.info("ZAP Docker container started successfully")
                        return True
                    await asyncio.sleep(1)
            
            logger.error("Failed to start ZAP Docker container")
            return False
            
        except Exception as e:
            logger.error(f"Error starting ZAP with Docker: {e}")
            return False
    
    async def is_zap_running(self) -> bool:
        """Check if ZAP is running"""
        try:
            response = self.session.get(f"{self.zap_url}/JSON/core/view/version/", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    async def spider_scan(self, target: str, max_children: int = 10) -> str:
        """Start spider scan"""
        try:
            # Add target to context
            await self.add_target_to_context(target)
            
            # Start spider
            response = self.session.get(
                f"{self.zap_url}/JSON/spider/action/scan/",
                params={
                    "url": target,
                    "maxChildren": max_children,
                    "recurse": "true"
                }
            )
            
            if response.status_code == 200:
                scan_id = response.json().get("scan")
                logger.info(f"Spider scan started with ID: {scan_id}")
                return scan_id
            else:
                logger.error(f"Failed to start spider scan: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error starting spider scan: {e}")
            return None
    
    async def active_scan(self, target: str) -> str:
        """Start active vulnerability scan"""
        try:
            # Start active scan
            response = self.session.get(
                f"{self.zap_url}/JSON/ascan/action/scan/",
                params={
                    "url": target,
                    "recurse": "true",
                    "inScopeOnly": "false"
                }
            )
            
            if response.status_code == 200:
                scan_id = response.json().get("scan")
                logger.info(f"Active scan started with ID: {scan_id}")
                return scan_id
            else:
                logger.error(f"Failed to start active scan: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error starting active scan: {e}")
            return None
    
    async def get_spider_progress(self, scan_id: str) -> int:
        """Get spider scan progress"""
        try:
            response = self.session.get(
                f"{self.zap_url}/JSON/spider/view/status/",
                params={"scanId": scan_id}
            )
            
            if response.status_code == 200:
                return int(response.json().get("status", "0"))
            return 0
            
        except Exception as e:
            logger.error(f"Error getting spider progress: {e}")
            return 0
    
    async def get_active_scan_progress(self, scan_id: str) -> int:
        """Get active scan progress"""
        try:
            response = self.session.get(
                f"{self.zap_url}/JSON/ascan/view/status/",
                params={"scanId": scan_id}
            )
            
            if response.status_code == 200:
                return int(response.json().get("status", "0"))
            return 0
            
        except Exception as e:
            logger.error(f"Error getting active scan progress: {e}")
            return 0
    
    async def get_alerts(self, baseurl: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get scan alerts/vulnerabilities"""
        try:
            params = {}
            if baseurl:
                params["baseurl"] = baseurl
            
            response = self.session.get(
                f"{self.zap_url}/JSON/core/view/alerts/",
                params=params
            )
            
            if response.status_code == 200:
                return response.json().get("alerts", [])
            return []
            
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []
    
    async def add_target_to_context(self, target: str):
        """Add target to ZAP context"""
        try:
            # Create new context
            response = self.session.get(
                f"{self.zap_url}/JSON/context/action/newContext/",
                params={"contextName": f"Context_{int(time.time())}"}
            )
            
            if response.status_code == 200:
                context_id = response.json().get("contextId")
                
                # Include URL in context
                self.session.get(
                    f"{self.zap_url}/JSON/context/action/includeInContext/",
                    params={
                        "contextName": f"Context_{context_id}",
                        "regex": f"{target}.*"
                    }
                )
                
        except Exception as e:
            logger.error(f"Error adding target to context: {e}")
    
    async def comprehensive_scan(self, target: str) -> ZAPScanResult:
        """Run comprehensive scan (spider + active scan)"""
        scan_id = f"zap_{int(time.time())}"
        
        try:
            logger.info(f"Starting comprehensive ZAP scan for {target}")
            
            # Ensure ZAP is running
            if not await self.is_zap_running():
                if not await self.start_zap_daemon():
                    raise Exception("Failed to start ZAP")
            
            scan_result = ZAPScanResult(
                scan_id=scan_id,
                target=target,
                alerts=[],
                status="running",
                progress=0,
                start_time=time.time()
            )
            
            self.active_scans[scan_id] = scan_result
            
            # Step 1: Spider scan
            logger.info("Starting spider scan...")
            spider_id = await self.spider_scan(target)
            
            if spider_id:
                # Monitor spider progress
                while True:
                    progress = await self.get_spider_progress(spider_id)
                    scan_result.progress = min(progress // 4, 25)  # 0-25% for spider
                    
                    if progress >= 100:
                        logger.info("Spider scan completed")
                        break
                    
                    await asyncio.sleep(2)
            
            # Step 2: Active scan
            logger.info("Starting active vulnerability scan...")
            active_id = await self.active_scan(target)
            
            if active_id:
                # Monitor active scan progress
                while True:
                    progress = await self.get_active_scan_progress(active_id)
                    scan_result.progress = 25 + (progress * 75 // 100)  # 25-100% for active scan
                    
                    if progress >= 100:
                        logger.info("Active scan completed")
                        break
                    
                    await asyncio.sleep(5)
            
            # Get results
            alerts = await self.get_alerts(target)
            scan_result.alerts = alerts
            scan_result.status = "completed"
            scan_result.progress = 100
            scan_result.end_time = time.time()
            
            logger.info(f"ZAP scan completed. Found {len(alerts)} alerts")
            return scan_result
            
        except Exception as e:
            logger.error(f"Error in comprehensive scan: {e}")
            scan_result.status = "failed"
            return scan_result
    
    async def stop_zap(self):
        """Stop ZAP daemon"""
        try:
            response = self.session.get(f"{self.zap_url}/JSON/core/action/shutdown/")
            if response.status_code == 200:
                logger.info("ZAP stopped successfully")
            
            # Also try to stop Docker container
            subprocess.run(["docker", "stop", "owasp-zap"], capture_output=True)
            subprocess.run(["docker", "rm", "owasp-zap"], capture_output=True)
            
        except Exception as e:
            logger.error(f"Error stopping ZAP: {e}")

# Global ZAP manager instance
zap_manager = OWASPZAPManager()

async def run_zap_scan(target: str) -> Dict[str, Any]:
    """High-level function to run ZAP scan"""
    try:
        result = await zap_manager.comprehensive_scan(target)
        
        return {
            "scan_id": result.scan_id,
            "target": result.target,
            "status": result.status,
            "progress": result.progress,
            "vulnerabilities": len(result.alerts),
            "alerts": result.alerts[:10],  # Return top 10 alerts
            "duration": result.end_time - result.start_time if result.end_time else None
        }
        
    except Exception as e:
        logger.error(f"ZAP scan failed: {e}")
        return {
            "scan_id": f"zap_failed_{int(time.time())}",
            "target": target,
            "status": "failed",
            "progress": 0,
            "error": str(e)
        }

if __name__ == "__main__":
    # Demo usage
    async def demo():
        target = "http://testphp.vulnweb.com/"  # Safe test target
        print(f"Running ZAP scan on {target}")
        
        result = await run_zap_scan(target)
        print(f"Scan results: {json.dumps(result, indent=2)}")
    
    asyncio.run(demo())
