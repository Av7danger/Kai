"""
Bug Bounty Hunting Workflow with Gemini AI
Complete workflow for systematic bug bounty hunting
"""

import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv
from gemini_bug_bounty_agent import BugBountyAgent, quick_recon, vulnerability_scan
from advanced_tools import (
    advanced_subdomain_enum,
    web_technology_detection,
    smart_parameter_discovery,
    intelligent_directory_discovery,
    api_endpoint_discovery
)

load_dotenv()

class BugBountyWorkflow:
    """Complete bug bounty hunting workflow"""
    
    def __init__(self, target: str, scope: Optional[List[str]] = None):
        self.target = target
        self.scope = scope or [target]
        self.session_id = f"bb_{int(time.time())}"
        self.results_dir = Path(f"./bug_bounty_results/{self.session_id}")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize agents
        self.hunter = BugBountyAgent(self.scope)
        
        # Results storage
        self.findings = {
            "target": target,
            "scope": self.scope,
            "start_time": datetime.now().isoformat(),
            "phases": {},
            "vulnerabilities": [],
            "recommendations": []
        }
    
    async def run_complete_workflow(self) -> Dict:
        """Execute complete bug bounty workflow"""
        print(f"🎯 Starting Bug Bounty Hunt on: {self.target}")
        print(f"📁 Results will be saved to: {self.results_dir}")
        
        try:
            # Phase 1: Reconnaissance
            await self._phase_1_reconnaissance()
            
            # Phase 2: Asset Discovery
            await self._phase_2_asset_discovery()
            
            # Phase 3: Vulnerability Assessment
            await self._phase_3_vulnerability_assessment()
            
            # Phase 4: Deep Analysis
            await self._phase_4_deep_analysis()
            
            # Phase 5: Reporting
            await self._phase_5_reporting()
            
        except Exception as e:
            print(f"❌ Error in workflow: {str(e)}")
            self.findings["error"] = str(e)
        
        finally:
            self.findings["end_time"] = datetime.now().isoformat()
            await self._save_results()
        
        return self.findings
    
    async def _phase_1_reconnaissance(self):
        """Phase 1: Initial reconnaissance and scope expansion"""
        print("\n🔍 Phase 1: Reconnaissance")
        
        phase_results = {"subdomains": [], "technologies": {}, "initial_assessment": ""}
        
        # Subdomain enumeration
        print("  📡 Enumerating subdomains...")
        subdomain_result = await self.hunter.agent.run(f"Use advanced subdomain enumeration on {self.target} with passive techniques enabled")
        
        # Parse results (assuming the agent returns structured data)
        try:
            # Try to extract subdomain information from agent response
            import re
            subdomain_pattern = r'([a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]*\.)+[a-zA-Z]{2,}'
            found_subdomains = re.findall(subdomain_pattern, subdomain_result.final_output)
            phase_results["subdomains"] = list(set(found_subdomains))
        except Exception:
            phase_results["subdomains"] = []
        
        # Expand scope with discovered subdomains
        new_targets = [sub for sub in phase_results["subdomains"] 
                      if sub not in self.scope and not sub.startswith('*')]
        self.scope.extend(new_targets[:50])  # Limit to top 50 subdomains
        
        # Technology detection on main target
        print("  🔧 Detecting technologies...")
        if self.target.startswith('http'):
            tech_url = self.target
        else:
            tech_url = f"https://{self.target}"
        
        tech_result = await self.hunter.agent.run(f"Analyze the web technologies and security headers for {tech_url}")
        phase_results["technologies"] = {"analysis": tech_result.final_output}
        
        # Initial security assessment with Gemini
        print("  🤖 Running initial assessment with Gemini...")
        assessment_prompt = f"""
        Analyze the initial reconnaissance results for {self.target}:
        
        Discovered subdomains: {len(phase_results['subdomains'])}
        Technology stack: {phase_results['technologies'].get('technologies', {})}
        Security implications: {phase_results['technologies'].get('security_implications', [])}
        
        Provide:
        1. Initial risk assessment
        2. Priority targets for further investigation
        3. Recommended attack vectors based on technology stack
        4. Scope refinement suggestions
        """
        
        assessment_result = await self.hunter.agent.run(assessment_prompt)
        phase_results["initial_assessment"] = assessment_result.final_output
        
        self.findings["phases"]["reconnaissance"] = phase_results
        print(f"  ✅ Found {len(phase_results['subdomains'])} subdomains")
    
    async def _phase_2_asset_discovery(self):
        """Phase 2: Comprehensive asset discovery"""
        print("\n🗺️  Phase 2: Asset Discovery")
        
        phase_results = {"live_hosts": [], "services": [], "web_apps": []}
        
        # Port scanning on key targets
        print("  🔍 Scanning for live services...")
        key_targets = self.scope[:20]  # Scan top 20 targets
        
        for target in key_targets:
            try:
                # Quick port scan
                scan_prompt = f"""
                Perform a quick port scan on {target} to identify:
                1. Open ports and services
                2. Web applications
                3. Potential entry points
                
                Use nmap for efficient scanning and focus on common ports.
                """
                
                scan_result = await self.hunter.agent.run(scan_prompt)
                
                phase_results["services"].append({
                    "target": target,
                    "scan_results": scan_result.final_output
                })
                
                # Check if it's a web application
                for protocol in ['https', 'http']:
                    web_url = f"{protocol}://{target}"
                    try:
                        import requests
                        response = requests.get(web_url, timeout=5, verify=False)
                        if response.status_code == 200:
                            phase_results["web_apps"].append(web_url)
                            break
                    except Exception:
                        continue
                        
            except Exception as e:
                print(f"    ⚠️  Error scanning {target}: {str(e)}")
        
        # API endpoint discovery
        print("  🔌 Discovering API endpoints...")
        for web_app in phase_results["web_apps"][:10]:  # Top 10 web apps
            try:
                api_result = await self.hunter.agent.run(f"Discover API endpoints and analyze security for {web_app}")
                
                # Store the API analysis results
                phase_results["live_hosts"].append({
                    "url": web_app,
                    "api_analysis": api_result.final_output,
                    "security_issues": []
                })
            except Exception as e:
                print(f"    ⚠️  Error discovering APIs on {web_app}: {str(e)}")
        
        self.findings["phases"]["asset_discovery"] = phase_results
        print(f"  ✅ Discovered {len(phase_results['web_apps'])} web applications")
    
    async def _phase_3_vulnerability_assessment(self):
        """Phase 3: Automated vulnerability assessment"""
        print("\n🛡️  Phase 3: Vulnerability Assessment")
        
        phase_results = {"nuclei_findings": [], "directory_scans": [], "parameter_analysis": []}
        
        web_apps = self.findings["phases"]["asset_discovery"]["web_apps"]
        
        for web_app in web_apps[:5]:  # Top 5 web applications
            print(f"  🔍 Assessing {web_app}")
            
            try:
                # Nuclei scan
                nuclei_prompt = f"""
                Run a Nuclei scan on {web_app} focusing on:
                1. Common vulnerabilities (CVEs)
                2. Misconfigurations
                3. Information disclosure
                4. Technology-specific issues
                
                Use appropriate templates and provide detailed findings.
                """
                
                nuclei_result = await self.hunter.agent.run(nuclei_prompt)
                phase_results["nuclei_findings"].append({
                    "target": web_app,
                    "findings": nuclei_result.final_output
                })
                
                # Directory discovery
                print(f"    📁 Directory discovery on {web_app}")
                dir_result = await self.hunter.agent.run(f"Perform intelligent directory and file discovery on {web_app} with comprehensive wordlist")
                
                # Parameter discovery
                print(f"    🔗 Parameter analysis on {web_app}")
                param_result = await self.hunter.agent.run(f"Discover parameters and analyze for injection vulnerabilities on {web_app}")
                
                phase_results["directory_scans"].append({
                    "target": web_app,
                    "results": dir_result.final_output
                })
                
                phase_results["parameter_analysis"].append({
                    "target": web_app,
                    "results": param_result.final_output
                })
                
                # Check for potential vulnerabilities mentioned in results
                if "injection" in param_result.final_output.lower() or "vulnerable" in param_result.final_output.lower():
                    self.findings["vulnerabilities"].append({
                        "type": "potential_injection",
                        "target": web_app,
                        "details": param_result.final_output[:500],
                        "severity": "high"
                    })
                
                if "admin" in dir_result.final_output.lower() or "backup" in dir_result.final_output.lower():
                    self.findings["vulnerabilities"].append({
                        "type": "sensitive_exposure",
                        "target": web_app,
                        "details": dir_result.final_output[:500],
                        "severity": "medium"
                    })
                
            except Exception as e:
                print(f"    ⚠️  Error assessing {web_app}: {str(e)}")
        
        self.findings["phases"]["vulnerability_assessment"] = phase_results
        print(f"  ✅ Completed assessment of {len(web_apps)} applications")
    
    async def _phase_4_deep_analysis(self):
        """Phase 4: Deep analysis with Gemini AI"""
        print("\n🧠 Phase 4: Deep Analysis with Gemini")
        
        # Compile all findings for Gemini analysis
        all_findings = {
            "reconnaissance": self.findings["phases"].get("reconnaissance", {}),
            "assets": self.findings["phases"].get("asset_discovery", {}),
            "vulnerabilities": self.findings["phases"].get("vulnerability_assessment", {}),
            "identified_vulns": self.findings["vulnerabilities"]
        }
        
        analysis_prompt = f"""
        Perform deep security analysis on the complete assessment of {self.target}:
        
        FINDINGS SUMMARY:
        {json.dumps(all_findings, indent=2)[:5000]}...
        
        Provide comprehensive analysis including:
        
        1. CRITICAL VULNERABILITIES:
           - Identify highest impact security issues
           - Provide exploitation scenarios
           - Assess business risk
        
        2. ATTACK CHAINS:
           - Map potential attack paths
           - Identify privilege escalation opportunities
           - Suggest chaining techniques
        
        3. BUSINESS LOGIC FLAWS:
           - Analyze application workflow
           - Identify logic vulnerabilities
           - Suggest testing approaches
        
        4. PRIORITIZED RECOMMENDATIONS:
           - Risk-based vulnerability prioritization
           - Remediation guidance
           - Testing methodology improvements
        
        5. RESPONSIBLE DISCLOSURE STRATEGY:
           - Suggest disclosure timeline
           - Recommend communication approach
           - Identify key stakeholders
        
        Focus on actionable insights that would be valuable for bug bounty submission.
        """
        
        print("  🤖 Running comprehensive analysis...")
        analysis_result = await self.hunter.agent.run(analysis_prompt)
        
        self.findings["deep_analysis"] = analysis_result.final_output
        
        # Extract specific recommendations
        recommendations_prompt = f"""
        Based on the analysis, provide specific actionable recommendations for:
        1. Immediate high-priority vulnerabilities to investigate
        2. Manual testing techniques to apply
        3. Tools and payloads to use
        4. Areas requiring deeper investigation
        
        Format as a prioritized action plan.
        """
        
        recommendations_result = await self.hunter.agent.run(recommendations_prompt)
        self.findings["recommendations"] = recommendations_result.final_output
        
        print("  ✅ Deep analysis completed")
    
    async def _phase_5_reporting(self):
        """Phase 5: Generate comprehensive report"""
        print("\n📊 Phase 5: Report Generation")
        
        # Generate executive summary
        summary_prompt = f"""
        Create an executive summary for the bug bounty assessment of {self.target}:
        
        Include:
        - Scope and methodology
        - Key findings summary
        - Critical vulnerabilities identified
        - Overall security posture
        - Recommendations priority
        
        Target audience: Security team and bug bounty platform
        """
        
        summary_result = await self.hunter.agent.run(summary_prompt)
        self.findings["executive_summary"] = summary_result.final_output
        
        # Generate detailed technical report
        technical_prompt = f"""
        Generate a detailed technical report including:
        
        1. Methodology and tools used
        2. Complete findings with evidence
        3. Step-by-step reproduction steps
        4. Risk assessment and impact analysis
        5. Detailed remediation guidance
        
        Format for bug bounty submission with clear proof-of-concept.
        """
        
        technical_result = await self.hunter.agent.run(technical_prompt)
        self.findings["technical_report"] = technical_result.final_output
        
        print("  ✅ Reports generated")
    
    async def _save_results(self):
        """Save all results to files"""
        # Save main findings
        with open(self.results_dir / "findings.json", "w") as f:
            json.dump(self.findings, f, indent=2)
        
        # Save individual reports
        if "executive_summary" in self.findings:
            with open(self.results_dir / "executive_summary.md", "w") as f:
                f.write(self.findings["executive_summary"])
        
        if "technical_report" in self.findings:
            with open(self.results_dir / "technical_report.md", "w") as f:
                f.write(self.findings["technical_report"])
        
        if "deep_analysis" in self.findings:
            with open(self.results_dir / "deep_analysis.md", "w") as f:
                f.write(self.findings["deep_analysis"])
        
        print(f"  💾 Results saved to {self.results_dir}")

# Quick workflow functions
async def quick_bug_bounty_scan(target: str) -> Dict:
    """Quick bug bounty scan for initial assessment"""
    workflow = BugBountyWorkflow(target)
    
    print(f"🚀 Quick Bug Bounty Scan: {target}")
    
    # Run reconnaissance and basic assessment
    await workflow._phase_1_reconnaissance()
    await workflow._phase_2_asset_discovery()
    
    # Quick vulnerability check
    findings_summary = {
        "target": target,
        "subdomains_found": len(workflow.findings["phases"]["reconnaissance"]["subdomains"]),
        "web_apps_found": len(workflow.findings["phases"]["asset_discovery"]["web_apps"]),
        "vulnerabilities": workflow.findings["vulnerabilities"],
        "recommendations": "Run full workflow for comprehensive assessment"
    }
    
    return findings_summary

async def focused_vulnerability_hunt(target: str, vuln_type: str) -> Dict:
    """Focused hunt for specific vulnerability types"""
    hunter = BugBountyAgent([target])
    
    vuln_prompts = {
        "xss": f"""
        Focus on Cross-Site Scripting (XSS) vulnerabilities in {target}:
        1. Identify all input points and parameters
        2. Test for reflected, stored, and DOM-based XSS
        3. Use advanced payloads for filter bypass
        4. Check for CSP bypasses
        5. Provide detailed exploitation steps
        """,
        
        "sqli": f"""
        Focus on SQL Injection vulnerabilities in {target}:
        1. Identify database-driven functionality
        2. Test all parameters for SQL injection
        3. Use time-based and error-based techniques
        4. Attempt to extract database information
        5. Provide detailed exploitation steps
        """,
        
        "ssrf": f"""
        Focus on Server-Side Request Forgery (SSRF) in {target}:
        1. Identify URL parameters and file upload functionality
        2. Test for internal network access
        3. Check for cloud metadata access
        4. Test various protocols and payloads
        5. Provide detailed exploitation steps
        """,
        
        "idor": f"""
        Focus on Insecure Direct Object References (IDOR) in {target}:
        1. Map all user-controlled identifiers
        2. Test horizontal and vertical privilege escalation
        3. Check API endpoints for authorization bypasses
        4. Test numeric and UUID-based identifiers
        5. Provide detailed exploitation steps
        """
    }
    
    if vuln_type not in vuln_prompts:
        return {"error": f"Unsupported vulnerability type: {vuln_type}"}
    
    result = await hunter.agent.run(vuln_prompts[vuln_type])
    
    return {
        "target": target,
        "vulnerability_type": vuln_type,
        "findings": result.final_output
    }

# Main execution
async def main():
    """Example usage of the bug bounty workflow"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python bug_bounty_workflow.py <target> [scan_type]")
        print("Scan types: full, quick, xss, sqli, ssrf, idor")
        return
    
    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "full"
    
    if scan_type == "full":
        workflow = BugBountyWorkflow(target)
        results = await workflow.run_complete_workflow()
        print(f"\n🎉 Complete workflow finished!")
        print(f"📊 Vulnerabilities found: {len(results['vulnerabilities'])}")
        
    elif scan_type == "quick":
        results = await quick_bug_bounty_scan(target)
        print(f"\n🎉 Quick scan completed!")
        print(f"📊 Results: {json.dumps(results, indent=2)}")
        
    elif scan_type in ["xss", "sqli", "ssrf", "idor"]:
        results = await focused_vulnerability_hunt(target, scan_type)
        print(f"\n🎉 Focused {scan_type.upper()} hunt completed!")
        print(f"📊 Findings: {results['findings']}")
        
    else:
        print(f"❌ Unknown scan type: {scan_type}")

if __name__ == "__main__":
    asyncio.run(main())
