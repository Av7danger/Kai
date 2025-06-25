"""
Enhanced Bug Bounty Agent with Google Gemini Integration
Optimized for bug bounty hunting with comprehensive toolset
"""

import asyncio
import os
from dotenv import load_dotenv
from typing import List, Optional

from agents import Agent, Runner
from cai.sdk.agents import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

# Import bug bounty specific tools
from cai.tools.reconnaissance.nmap import nmap
from cai.tools.reconnaissance.subfinder import subfinder
from cai.tools.reconnaissance.assetfinder import assetfinder
from cai.tools.reconnaissance.amass import amass
from cai.tools.reconnaissance.gau import gau
from cai.tools.reconnaissance.waybackurls import waybackurls
from cai.tools.reconnaissance.paramspider import paramspider
from cai.tools.reconnaissance.shodan import shodan_search, shodan_host_info
from cai.tools.reconnaissance.curl import curl_request
from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from cai.tools.reconnaissance.exec_code import execute_code

from cai.tools.vulnerability.nuclei import nuclei_scan
from cai.tools.vulnerability.sqlmap import sqlmap_scan
from cai.tools.vulnerability.ffuf import ffuf_directory_scan
from cai.tools.vulnerability.dalfox import dalfox_xss_scan

from cai.tools.web.search_web import make_google_search, query_perplexity
from cai.tools.web.headers import analyze_headers

load_dotenv()

class BugBountyAgent:
    """Enhanced Bug Bounty Agent with Gemini integration and comprehensive toolset"""
    
    def __init__(self, target_scope: Optional[List[str]] = None):
        self.target_scope = target_scope or []
        self.findings = []
        
        # Configure tools based on available API keys
        self.tools = self._configure_tools()
        
        # Create agent with Gemini model
        self.agent = self._create_agent()
    
    def _configure_tools(self) -> List:
        """Configure available tools based on environment and API keys"""
        tools = [
            # Core reconnaissance tools
            nmap,
            subfinder,
            assetfinder,
            curl_request,
            generic_linux_command,
            execute_code,
            analyze_headers,
            
            # URL discovery tools
            gau,
            waybackurls,
            paramspider,
            
            # Vulnerability scanners
            nuclei_scan,
            ffuf_directory_scan,
        ]
        
        # Add tools based on available API keys
        if os.getenv('SHODAN_API_KEY'):
            tools.extend([shodan_search, shodan_host_info])
        
        if os.getenv('GOOGLE_SEARCH_API_KEY') and os.getenv('GOOGLE_SEARCH_CX'):
            tools.append(make_google_search)
        
        if os.getenv('PERPLEXITY_API_KEY'):
            tools.append(query_perplexity)
            
        # Advanced vulnerability scanners (require tool installation)
        try:
            tools.extend([sqlmap_scan, dalfox_xss_scan])
        except ImportError:
            print("Advanced vulnerability tools not available. Install sqlmap and dalfox for full functionality.")
        
        return tools
    
    def _create_agent(self) -> Agent:
        """Create bug bounty agent with Gemini model configuration"""
        
        # Gemini model configuration through LiteLLM
        model_config = {
            "model": "gemini/gemini-1.5-pro-latest",  # Use latest Gemini Pro model
            "api_key": os.getenv('GOOGLE_API_KEY'),
            "temperature": 0.3,  # Lower temperature for more focused security testing
            "max_tokens": 8192,
        }
        
        # If Gemini API key not available, fall back to OpenAI
        if not os.getenv('GOOGLE_API_KEY'):
            print("Warning: GOOGLE_API_KEY not found. Falling back to OpenAI model.")
            model_config = {
                "model": os.getenv('CAI_MODEL', 'gpt-4o'),
                "api_key": os.getenv('OPENAI_API_KEY'),
                "temperature": 0.3,
                "max_tokens": 8192,
            }
        
        instructions = self._get_bug_bounty_instructions()
        
        return Agent(
            name="Advanced Bug Bounty Hunter",
            instructions=instructions,
            tools=self.tools,
            model=OpenAIChatCompletionsModel(**model_config)
        )
    
    def _get_bug_bounty_instructions(self) -> str:
        """Get comprehensive bug bounty hunting instructions"""
        scope_info = f"Target scope: {', '.join(self.target_scope)}" if self.target_scope else "Scope to be defined by user"
        
        return f"""# Advanced Bug Bounty Hunter with Gemini Intelligence

You are an elite bug bounty hunter with expertise in web application security, infrastructure testing, and responsible disclosure. You use Google's Gemini AI capabilities for enhanced vulnerability analysis and pattern recognition.

{scope_info}

## Core Methodology

### Phase 1: Reconnaissance & Asset Discovery
1. **Subdomain Enumeration**
   - Use subfinder, assetfinder, and amass for comprehensive subdomain discovery
   - Cross-reference findings with Shodan for exposed services
   - Use waybackurls and gau for historical URL discovery

2. **Service Discovery**
   - Perform nmap scans to identify open ports and services
   - Analyze HTTP headers for technology stack information
   - Identify potential attack surfaces

3. **URL & Parameter Discovery**
   - Use paramspider to find parameters in archived URLs
   - Crawl applications to map all endpoints
   - Identify API endpoints and documentation

### Phase 2: Vulnerability Assessment
1. **Automated Scanning**
   - Run Nuclei with appropriate templates for quick wins
   - Use ffuf for directory and file discovery
   - Perform targeted scans based on technology stack

2. **Manual Testing Focus Areas**
   - Authentication and authorization flaws
   - Business logic vulnerabilities
   - API security issues
   - Input validation problems
   - Configuration issues

3. **Advanced Testing**
   - SQL injection testing with sqlmap
   - XSS testing with dalfox
   - Custom payload development
   - Race condition testing

### Phase 3: Analysis & Reporting
1. **Impact Assessment**
   - Evaluate business impact of findings
   - Provide clear proof-of-concept
   - Suggest remediation steps

2. **Documentation**
   - Create detailed vulnerability reports
   - Include steps to reproduce
   - Provide remediation guidance

## Key Principles
- Always stay within defined scope
- Prioritize high-impact vulnerabilities
- Use stealth techniques to avoid detection
- Focus on quality over quantity
- Maintain ethical hacking standards
- Document everything systematically

## Gemini Advantages
- Enhanced pattern recognition in responses
- Better understanding of complex attack chains
- Improved false positive reduction
- Advanced correlation of findings

Remember: The goal is to find real security issues that matter to organizations while maintaining the highest ethical standards."""

    async def hunt(self, target: str, scope: Optional[List[str]] = None) -> dict:
        """
        Execute comprehensive bug bounty hunt on target
        
        Args:
            target: Primary target (domain, IP, etc.)
            scope: Additional scope items
            
        Returns:
            Dictionary with findings and recommendations
        """
        if scope:
            self.target_scope.extend(scope)
        if target not in self.target_scope:
            self.target_scope.append(target)
        
        hunt_prompt = f"""
        Execute a comprehensive bug bounty assessment on the target: {target}
        
        Scope: {', '.join(self.target_scope)}
        
        Follow the phased approach:
        1. Start with reconnaissance and asset discovery
        2. Perform vulnerability assessment
        3. Analyze findings and provide detailed report
        
        Focus on finding real, exploitable vulnerabilities with business impact.
        Stay within scope and maintain ethical standards throughout the assessment.
        """
        
        result = await Runner.run(self.agent, hunt_prompt)
        return {
            "target": target,
            "scope": self.target_scope,
            "findings": result.final_output,
            "tools_used": [tool.__name__ for tool in self.tools]
        }

# Example usage and quick start functions
async def quick_recon(domain: str) -> dict:
    """Quick reconnaissance scan of a domain"""
    hunter = BugBountyAgent([domain])
    
    recon_prompt = f"""
    Perform quick reconnaissance on {domain}:
    1. Enumerate subdomains using subfinder and assetfinder
    2. Check for exposed services with basic nmap scan
    3. Gather URLs from wayback machine and gau
    4. Run basic nuclei scan for quick wins
    5. Summarize findings and suggest next steps
    """
    
    result = await Runner.run(hunter.agent, recon_prompt)
    return {"domain": domain, "recon_results": result.final_output}

async def vulnerability_scan(target: str, scan_type: str = "web") -> dict:
    """Focused vulnerability scanning"""
    hunter = BugBountyAgent([target])
    
    if scan_type == "web":
        scan_prompt = f"""
        Perform web application vulnerability scan on {target}:
        1. Analyze HTTP headers and technology stack
        2. Run nuclei with web application templates
        3. Perform directory discovery with ffuf
        4. Test for common web vulnerabilities
        5. Provide detailed findings with exploitation steps
        """
    elif scan_type == "network":
        scan_prompt = f"""
        Perform network vulnerability scan on {target}:
        1. Comprehensive nmap scan with service detection
        2. Check for common misconfigurations
        3. Identify potential entry points
        4. Run relevant nuclei templates for network services
        5. Provide attack vectors and recommendations
        """
    else:
        scan_prompt = f"""
        Perform comprehensive security assessment on {target}:
        1. Combined web and network reconnaissance
        2. Multi-vector vulnerability testing
        3. Business logic assessment
        4. Configuration review
        5. Detailed security report with remediation
        """
    
    result = await Runner.run(hunter.agent, scan_prompt)
    return {"target": target, "scan_type": scan_type, "results": result.final_output}

# Main execution example
async def main():
    """Example usage of the enhanced bug bounty agent"""
    
    # Example 1: Quick recon
    print("=== Quick Reconnaissance Example ===")
    recon_result = await quick_recon("example.com")
    print(recon_result["recon_results"])
    
    # Example 2: Full bug bounty hunt
    print("\n=== Full Bug Bounty Hunt Example ===")
    hunter = BugBountyAgent()
    hunt_result = await hunter.hunt("example.com", ["*.example.com", "api.example.com"])
    print(hunt_result["findings"])
    
    # Example 3: Focused web app scan
    print("\n=== Web Application Scan Example ===")
    web_scan_result = await vulnerability_scan("https://example.com", "web")
    print(web_scan_result["results"])

if __name__ == "__main__":
    asyncio.run(main())
