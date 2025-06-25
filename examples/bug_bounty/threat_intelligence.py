"""
Threat Intelligence Integration Module
Real-time threat intelligence feeds for enhanced bug bounty hunting
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging
import hashlib

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    print("⚠️ aiohttp not available. Install with: pip install aiohttp")

@dataclass
class ThreatIntelligence:
    """Threat intelligence data structure"""
    cve_id: str
    severity: str
    score: float
    description: str
    affected_products: List[str]
    exploit_available: bool
    published_date: str
    last_modified: str
    references: List[str]
    tags: List[str]

@dataclass
class ExploitInfo:
    """Exploit information structure"""
    exploit_id: str
    cve_id: Optional[str]
    title: str
    platform: str
    exploit_type: str
    date_published: str
    verified: bool
    source_url: str
    tags: List[str]

class ThreatIntelligenceEngine:
    """Advanced threat intelligence integration engine"""
    
    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        self.api_keys = api_keys or {}
        self.logger = logging.getLogger('threat_intel')
        
        # Cache for threat intelligence data
        self.cve_cache = {}
        self.exploit_cache = {}
        self.threat_cache_ttl = 3600  # 1 hour
        
        # API endpoints
        self.endpoints = {
            "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "vulners": "https://vulners.com/api/v3/search/lucene/",
            "exploit_db": "https://www.exploit-db.com/api/v1/search",
            "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "github_advisories": "https://api.github.com/advisories"
        }
        
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for threat intelligence features")
            
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'CAI-BugBounty-ThreatIntel/1.0'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def get_threat_intelligence_for_target(self, target_info: Dict) -> Dict:
        """Get comprehensive threat intelligence for a target"""
        threat_intel = {
            "target": target_info.get("value", ""),
            "technology_threats": [],
            "recent_cves": [],
            "active_exploits": [],
            "threat_score": 0.0,
            "recommendations": []
        }
        
        try:
            # Extract technology information
            technologies = self._extract_technologies(target_info)
            
            # Get CVEs for detected technologies
            for tech in technologies:
                cves = await self._get_cves_for_technology(tech)
                threat_intel["recent_cves"].extend(cves)
            
            # Get exploit information
            exploits = await self._get_active_exploits(technologies)
            threat_intel["active_exploits"] = exploits
            
            # Calculate threat score
            threat_intel["threat_score"] = self._calculate_threat_score(
                threat_intel["recent_cves"], 
                threat_intel["active_exploits"]
            )
            
            # Generate recommendations
            threat_intel["recommendations"] = self._generate_threat_recommendations(
                threat_intel
            )
            
            self.logger.info(f"📊 Threat intelligence gathered for {target_info.get('value', '')}")
            
        except Exception as e:
            self.logger.error(f"Error gathering threat intelligence: {e}")
        
        return threat_intel
    
    async def _get_cves_for_technology(self, technology: str) -> List[ThreatIntelligence]:
        """Get recent CVEs for a specific technology"""
        cves = []
        
        try:
            # Check cache first
            cache_key = f"cve_{technology}"
            if cache_key in self.cve_cache:
                cache_time, cached_data = self.cve_cache[cache_key]
                if datetime.now().timestamp() - cache_time < self.threat_cache_ttl:
                    return cached_data
            
            # Query NVD for recent CVEs
            nvd_cves = await self._query_nvd_cves(technology)
            cves.extend(nvd_cves)
            
            # Query Vulners for additional intelligence
            if self.api_keys.get("vulners"):
                vulners_cves = await self._query_vulners(technology)
                cves.extend(vulners_cves)
            
            # Cache the results
            self.cve_cache[cache_key] = (datetime.now().timestamp(), cves)
            
        except Exception as e:
            self.logger.error(f"Error getting CVEs for {technology}: {e}")
        
        return cves
    
    async def _query_nvd_cves(self, technology: str) -> List[ThreatIntelligence]:
        """Query NIST NVD for CVEs"""
        cves = []
        
        try:
            # Calculate date range (last 90 days)
            end_date = datetime.now()
            start_date = end_date - timedelta(days=90)
            
            params = {
                "keywordSearch": technology,
                "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 20
            }
            
            async with self.session.get(self.endpoints["nvd"], params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for cve_item in data.get("vulnerabilities", []):
                        cve_data = cve_item.get("cve", {})
                        
                        # Extract CVSS score
                        cvss_score = 0.0
                        cvss_data = cve_data.get("metrics", {})
                        if "cvssMetricV31" in cvss_data:
                            cvss_score = cvss_data["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        elif "cvssMetricV30" in cvss_data:
                            cvss_score = cvss_data["cvssMetricV30"][0]["cvssData"]["baseScore"]
                        
                        # Create threat intelligence object
                        threat_intel = ThreatIntelligence(
                            cve_id=cve_data.get("id", ""),
                            severity=self._score_to_severity(cvss_score),
                            score=cvss_score,
                            description=cve_data.get("descriptions", [{}])[0].get("value", ""),
                            affected_products=self._extract_affected_products(cve_data),
                            exploit_available=False,  # Will be checked separately
                            published_date=cve_data.get("published", ""),
                            last_modified=cve_data.get("lastModified", ""),
                            references=[ref.get("url", "") for ref in cve_data.get("references", [])],
                            tags=cve_data.get("configurations", [])
                        )
                        
                        cves.append(threat_intel)
                
        except Exception as e:
            self.logger.error(f"Error querying NVD: {e}")
        
        return cves
    
    async def _query_vulners(self, technology: str) -> List[ThreatIntelligence]:
        """Query Vulners API for threat intelligence"""
        cves = []
        
        try:
            if not self.api_keys.get("vulners"):
                return cves
            
            headers = {"Content-Type": "application/json"}
            payload = {
                "query": f"type:cve AND {technology}",
                "sort": "published",
                "size": 20,
                "apikey": self.api_keys["vulners"]
            }
            
            async with self.session.post(
                self.endpoints["vulners"], 
                json=payload, 
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for item in data.get("data", {}).get("search", []):
                        cve_data = item.get("_source", {})
                        
                        threat_intel = ThreatIntelligence(
                            cve_id=cve_data.get("id", ""),
                            severity=cve_data.get("cvss", {}).get("severity", "UNKNOWN"),
                            score=float(cve_data.get("cvss", {}).get("score", 0.0)),
                            description=cve_data.get("description", ""),
                            affected_products=[cve_data.get("title", "")],
                            exploit_available=cve_data.get("exploit", False),
                            published_date=cve_data.get("published", ""),
                            last_modified=cve_data.get("modified", ""),
                            references=cve_data.get("references", []),
                            tags=cve_data.get("bulletinFamily", [])
                        )
                        
                        cves.append(threat_intel)
                
        except Exception as e:
            self.logger.error(f"Error querying Vulners: {e}")
        
        return cves
    
    async def _get_active_exploits(self, technologies: List[str]) -> List[ExploitInfo]:
        """Get active exploits for technologies"""
        exploits = []
        
        try:
            # Query exploit-db
            for tech in technologies:
                tech_exploits = await self._query_exploit_db(tech)
                exploits.extend(tech_exploits)
            
            # Query GitHub security advisories
            github_exploits = await self._query_github_advisories(technologies)
            exploits.extend(github_exploits)
            
            # Check CISA Known Exploited Vulnerabilities
            kev_exploits = await self._query_cisa_kev(technologies)
            exploits.extend(kev_exploits)
            
        except Exception as e:
            self.logger.error(f"Error getting active exploits: {e}")
        
        return exploits
    
    async def _query_exploit_db(self, technology: str) -> List[ExploitInfo]:
        """Query Exploit-DB for recent exploits"""
        exploits = []
        
        try:
            params = {
                "cve": "",
                "author": "",
                "platform": "",
                "type": "",
                "port": "",
                "term": technology
            }
            
            async with self.session.get(self.endpoints["exploit_db"], params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for exploit_data in data.get("data", []):
                        exploit_info = ExploitInfo(
                            exploit_id=str(exploit_data.get("id", "")),
                            cve_id=exploit_data.get("codes", {}).get("cve", [None])[0],
                            title=exploit_data.get("title", ""),
                            platform=exploit_data.get("platform", ""),
                            exploit_type=exploit_data.get("type", ""),
                            date_published=exploit_data.get("date_published", ""),
                            verified=exploit_data.get("verified", False),
                            source_url=f"https://www.exploit-db.com/exploits/{exploit_data.get('id', '')}",
                            tags=exploit_data.get("tags", [])
                        )
                        
                        exploits.append(exploit_info)
                
        except Exception as e:
            self.logger.error(f"Error querying Exploit-DB: {e}")
        
        return exploits
    
    async def _query_github_advisories(self, technologies: List[str]) -> List[ExploitInfo]:
        """Query GitHub Security Advisories"""
        exploits = []
        
        try:
            for tech in technologies:
                params = {
                    "type": "reviewed",
                    "affects": tech,
                    "sort": "published",
                    "direction": "desc",
                    "per_page": 10
                }
                
                async with self.session.get(
                    self.endpoints["github_advisories"], 
                    params=params
                ) as response:
                    if response.status == 200:
                        advisories = await response.json()
                        
                        for advisory in advisories:
                            if advisory.get("cvss", {}).get("score", 0) > 7.0:  # High severity
                                exploit_info = ExploitInfo(
                                    exploit_id=advisory.get("ghsa_id", ""),
                                    cve_id=advisory.get("cve_id"),
                                    title=advisory.get("summary", ""),
                                    platform="Multiple",
                                    exploit_type="Advisory",
                                    date_published=advisory.get("published_at", ""),
                                    verified=True,
                                    source_url=advisory.get("html_url", ""),
                                    tags=advisory.get("cwe_ids", [])
                                )
                                
                                exploits.append(exploit_info)
                    
        except Exception as e:
            self.logger.error(f"Error querying GitHub advisories: {e}")
        
        return exploits
    
    async def _query_cisa_kev(self, technologies: List[str]) -> List[ExploitInfo]:
        """Query CISA Known Exploited Vulnerabilities"""
        exploits = []
        
        try:
            async with self.session.get(self.endpoints["cisa_kev"]) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for vuln in data.get("vulnerabilities", []):
                        # Check if any technology matches
                        if any(tech.lower() in vuln.get("product", "").lower() 
                               for tech in technologies):
                            
                            exploit_info = ExploitInfo(
                                exploit_id=vuln.get("cveID", ""),
                                cve_id=vuln.get("cveID"),
                                title=vuln.get("vulnerabilityName", ""),
                                platform=vuln.get("product", ""),
                                exploit_type="KEV",
                                date_published=vuln.get("dateAdded", ""),
                                verified=True,
                                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                                tags=["CISA", "KEV", "Active Exploitation"]
                            )
                            
                            exploits.append(exploit_info)
                    
        except Exception as e:
            self.logger.error(f"Error querying CISA KEV: {e}")
        
        return exploits
    
    def _extract_technologies(self, target_info: Dict) -> List[str]:
        """Extract technology information from target data"""
        technologies = []
        
        # Extract from various sources
        tech_sources = [
            target_info.get("technology", ""),
            target_info.get("server", ""),
            target_info.get("framework", ""),
            target_info.get("cms", ""),
            str(target_info.get("headers", {}))
        ]
        
        # Common technology patterns
        tech_patterns = {
            "apache": ["apache", "httpd"],
            "nginx": ["nginx"],
            "php": ["php"],
            "wordpress": ["wordpress", "wp-"],
            "drupal": ["drupal"],
            "joomla": ["joomla"],
            "laravel": ["laravel"],
            "react": ["react"],
            "angular": ["angular"],
            "vue": ["vue.js", "vuejs"],
            "node": ["node.js", "nodejs"],
            "express": ["express"],
            "django": ["django"],
            "flask": ["flask"],
            "spring": ["spring"],
            "tomcat": ["tomcat"],
            "iis": ["iis", "microsoft-iis"]
        }
        
        for source in tech_sources:
            source_lower = source.lower()
            for tech, patterns in tech_patterns.items():
                if any(pattern in source_lower for pattern in patterns):
                    if tech not in technologies:
                        technologies.append(tech)
        
        return technologies
    
    def _extract_affected_products(self, cve_data: Dict) -> List[str]:
        """Extract affected products from CVE data"""
        products = []
        
        try:
            configs = cve_data.get("configurations", [])
            for config in configs:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_matches = node.get("cpeMatch", [])
                    for match in cpe_matches:
                        cpe = match.get("criteria", "")
                        if cpe:
                            # Extract product name from CPE
                            parts = cpe.split(":")
                            if len(parts) > 4:
                                products.append(parts[4])
        except Exception:
            pass
        
        return list(set(products))
    
    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        else:
            return "UNKNOWN"
    
    def _calculate_threat_score(self, cves: List[ThreatIntelligence], 
                               exploits: List[ExploitInfo]) -> float:
        """Calculate overall threat score for target"""
        score = 0.0
        
        # Score based on CVE severity
        for cve in cves:
            if cve.severity == "CRITICAL":
                score += 10.0
            elif cve.severity == "HIGH":
                score += 7.0
            elif cve.severity == "MEDIUM":
                score += 4.0
            elif cve.severity == "LOW":
                score += 2.0
        
        # Bonus for available exploits
        for exploit in exploits:
            if exploit.verified:
                score += 5.0
            else:
                score += 2.0
        
        # Normalize score (0-100)
        max_possible = len(cves) * 10 + len(exploits) * 5
        if max_possible > 0:
            score = min(100.0, (score / max_possible) * 100)
        
        return score
    
    def _generate_threat_recommendations(self, threat_intel: Dict) -> List[str]:
        """Generate threat-based testing recommendations"""
        recommendations = []
        
        threat_score = threat_intel.get("threat_score", 0.0)
        cves = threat_intel.get("recent_cves", [])
        exploits = threat_intel.get("active_exploits", [])
        
        if threat_score > 80:
            recommendations.append("🚨 HIGH THREAT TARGET - Prioritize immediate testing")
        elif threat_score > 60:
            recommendations.append("⚠️ Elevated threat level - Focus on recent CVEs")
        
        # CVE-specific recommendations
        critical_cves = [cve for cve in cves if cve.severity == "CRITICAL"]
        if critical_cves:
            recommendations.append(f"🔴 Test for {len(critical_cves)} critical CVEs immediately")
        
        # Exploit-specific recommendations
        verified_exploits = [exp for exp in exploits if exp.verified]
        if verified_exploits:
            recommendations.append(f"💥 {len(verified_exploits)} verified exploits available - test ASAP")
        
        # Technology-specific recommendations
        if any("wordpress" in cve.description.lower() for cve in cves):
            recommendations.append("🔍 Focus on WordPress-specific vulnerabilities")
        
        if any("sql" in cve.description.lower() for cve in cves):
            recommendations.append("💉 Prioritize SQL injection testing")
        
        if not recommendations:
            recommendations.append("✅ Low threat profile - proceed with standard testing")
        
        return recommendations

# Integration with existing workflow
async def enhance_reconnaissance_with_threat_intel(target_info: Dict, 
                                                 api_keys: Optional[Dict[str, str]] = None) -> Dict:
    """Enhance reconnaissance with threat intelligence"""
    
    async with ThreatIntelligenceEngine(api_keys) as threat_engine:
        threat_intel = await threat_engine.get_threat_intelligence_for_target(target_info)
        
        # Merge with existing target info
        enhanced_target = {
            **target_info,
            "threat_intelligence": threat_intel,
            "priority_score": threat_intel.get("threat_score", 0.0),
            "testing_recommendations": threat_intel.get("recommendations", [])
        }
        
        return enhanced_target

# Example usage
async def example_threat_intelligence():
    """Example of threat intelligence integration"""
    
    # Example target information
    target_info = {
        "value": "example.com",
        "technology": "apache",
        "server": "Apache/2.4.41",
        "framework": "php",
        "cms": "wordpress"
    }
    
    # API keys (optional but recommended)
    api_keys = {
        "vulners": "your_vulners_api_key"  # Get from vulners.com
    }
    
    # Get threat intelligence
    enhanced_target = await enhance_reconnaissance_with_threat_intel(target_info, api_keys)
    
    print("🔍 Threat Intelligence Analysis:")
    print(f"Target: {enhanced_target['value']}")
    print(f"Threat Score: {enhanced_target['threat_intelligence']['threat_score']:.1f}/100")
    print(f"Recent CVEs: {len(enhanced_target['threat_intelligence']['recent_cves'])}")
    print(f"Active Exploits: {len(enhanced_target['threat_intelligence']['active_exploits'])}")
    print("\n📋 Recommendations:")
    for rec in enhanced_target['testing_recommendations']:
        print(f"  • {rec}")

if __name__ == "__main__":
    asyncio.run(example_threat_intelligence())
