"""
Advanced Bug Bounty Tools
Enhanced versions of security testing tools optimized for bug bounty hunting
"""

import os
import json
import subprocess
import tempfile
import requests
import asyncio
from typing import List, Dict, Optional
from urllib.parse import urlparse, urljoin
import dns.resolver
from cai.sdk.agents import function_tool
from cai.tools.common import run_command


@function_tool
def advanced_subdomain_enum(domain: str, use_passive: bool = True, use_active: bool = False) -> str:
    """
    Advanced subdomain enumeration using multiple tools and techniques
    
    Args:
        domain: Target domain for subdomain enumeration
        use_passive: Use passive enumeration techniques (safer)
        use_active: Use active enumeration techniques (may be detected)
    
    Returns:
        Comprehensive list of discovered subdomains with sources
    """
    subdomains = set()
    results = {"domain": domain, "subdomains": [], "sources": {}}
    
    if use_passive:
        # Subfinder
        try:
            subfinder_output = run_command(f"subfinder -d {domain} -silent")
            subfinder_subs = [s.strip() for s in subfinder_output.split('\n') if s.strip()]
            subdomains.update(subfinder_subs)
            results["sources"]["subfinder"] = len(subfinder_subs)
        except Exception as e:
            results["sources"]["subfinder"] = f"Error: {str(e)}"
        
        # Assetfinder
        try:
            assetfinder_output = run_command(f"assetfinder {domain}")
            assetfinder_subs = [s.strip() for s in assetfinder_output.split('\n') if s.strip()]
            subdomains.update(assetfinder_subs)
            results["sources"]["assetfinder"] = len(assetfinder_subs)
        except Exception as e:
            results["sources"]["assetfinder"] = f"Error: {str(e)}"
        
        # Certificate Transparency
        try:
            ct_subs = get_crt_sh_subdomains(domain)
            subdomains.update(ct_subs)
            results["sources"]["certificate_transparency"] = len(ct_subs)
        except Exception as e:
            results["sources"]["certificate_transparency"] = f"Error: {str(e)}"
    
    if use_active:
        # DNS bruteforcing with common subdomains
        try:
            dns_subs = dns_bruteforce(domain)
            subdomains.update(dns_subs)
            results["sources"]["dns_bruteforce"] = len(dns_subs)
        except Exception as e:
            results["sources"]["dns_bruteforce"] = f"Error: {str(e)}"
    
    results["subdomains"] = sorted(list(subdomains))
    results["total_found"] = len(subdomains)
    
    return json.dumps(results, indent=2)


@function_tool
def web_technology_detection(url: str) -> str:
    """
    Detect web technologies, frameworks, and potential vulnerabilities
    
    Args:
        url: Target URL to analyze
        
    Returns:
        Detailed technology stack information and security implications
    """
    results = {"url": url, "technologies": {}, "security_implications": []}
    
    try:
        # Basic header analysis
        response = requests.get(url, timeout=10, verify=False)
        headers = dict(response.headers)
        
        # Server detection
        if 'Server' in headers:
            server = headers['Server']
            results["technologies"]["server"] = server
            
            # Check for version disclosure
            if any(version in server.lower() for version in ['apache/2.2', 'nginx/1.1', 'iis/6.0']):
                results["security_implications"].append("Outdated server version detected - potential security vulnerabilities")
        
        # Framework detection
        framework_headers = {
            'X-Powered-By': 'backend_framework',
            'X-AspNet-Version': 'aspnet_version',
            'X-Generator': 'cms_generator'
        }
        
        for header, tech_type in framework_headers.items():
            if header in headers:
                results["technologies"][tech_type] = headers[header]
        
        # Security headers analysis
        security_headers = {
            'X-Frame-Options': 'clickjacking_protection',
            'X-Content-Type-Options': 'mime_sniffing_protection',
            'X-XSS-Protection': 'xss_protection',
            'Strict-Transport-Security': 'hsts',
            'Content-Security-Policy': 'csp'
        }
        
        missing_headers = []
        for header, description in security_headers.items():
            if header in headers:
                results["technologies"][description] = headers[header]
            else:
                missing_headers.append(description)
        
        if missing_headers:
            results["security_implications"].append(f"Missing security headers: {', '.join(missing_headers)}")
        
        # Content analysis for additional tech detection
        content = response.text[:10000]  # First 10KB
        
        # CMS detection
        cms_signatures = {
            'wp-content': 'WordPress',
            'drupal': 'Drupal',
            'joomla': 'Joomla',
            '/typo3/': 'TYPO3'
        }
        
        for signature, cms in cms_signatures.items():
            if signature in content.lower():
                results["technologies"]["cms"] = cms
                break
        
        # JavaScript framework detection
        js_frameworks = {
            'react': 'React',
            'angular': 'Angular',
            'vue': 'Vue.js',
            'jquery': 'jQuery'
        }
        
        detected_js = []
        for framework, name in js_frameworks.items():
            if framework in content.lower():
                detected_js.append(name)
        
        if detected_js:
            results["technologies"]["javascript_frameworks"] = detected_js
        
    except Exception as e:
        results["error"] = str(e)
    
    return json.dumps(results, indent=2)


@function_tool
def smart_parameter_discovery(url: str, wordlist_type: str = "comprehensive") -> str:
    """
    Intelligent parameter discovery using multiple techniques
    
    Args:
        url: Target URL for parameter discovery
        wordlist_type: Type of wordlist (basic, comprehensive, api_focused)
        
    Returns:
        Discovered parameters with potential injection points
    """
    results = {"url": url, "parameters": [], "injection_points": []}
    
    try:
        # Use paramspider for historical parameters
        domain = urlparse(url).netloc
        paramspider_output = run_command(f"paramspider -d {domain} --level high")
        
        # Parse wayback URLs for parameters
        wayback_output = run_command(f"echo {domain} | waybackurls")
        
        # Extract parameters from URLs
        parameters = set()
        for line in wayback_output.split('\n'):
            if '?' in line:
                url_params = line.split('?')[1].split('&')
                for param in url_params:
                    if '=' in param:
                        param_name = param.split('=')[0]
                        if param_name:
                            parameters.add(param_name)
        
        # Common parameter fuzzing
        common_params = get_common_parameters(wordlist_type)
        
        # Test for parameter existence
        base_response = requests.get(url, timeout=10)
        
        for param in list(parameters) + common_params:
            try:
                test_url = f"{url}?{param}=test"
                test_response = requests.get(test_url, timeout=5)
                
                # Check for different response indicating parameter acceptance
                if (test_response.status_code != base_response.status_code or 
                    len(test_response.content) != len(base_response.content)):
                    
                    results["parameters"].append({
                        "name": param,
                        "discovered_via": "response_difference",
                        "potential_injection": analyze_parameter_for_injection(param)
                    })
                    
            except Exception:
                continue
        
        # Error-based parameter discovery
        error_params = ["'", '"', "<script>", "{{7*7}}", "${7*7}"]
        for param in parameters:
            for payload in error_params:
                try:
                    test_url = f"{url}?{param}={payload}"
                    test_response = requests.get(test_url, timeout=5)
                    
                    # Look for error messages indicating vulnerability
                    error_indicators = ["sql", "mysql", "oracle", "syntax error", "exception", "warning"]
                    if any(indicator in test_response.text.lower() for indicator in error_indicators):
                        results["injection_points"].append({
                            "parameter": param,
                            "payload": payload,
                            "vulnerability_type": "potential_injection",
                            "response_snippet": test_response.text[:500]
                        })
                        
                except Exception:
                    continue
    
    except Exception as e:
        results["error"] = str(e)
    
    return json.dumps(results, indent=2)


@function_tool
def intelligent_directory_discovery(url: str, scan_level: str = "comprehensive") -> str:
    """
    Intelligent directory and file discovery with adaptive wordlists
    
    Args:
        url: Target URL for directory discovery
        scan_level: Scan intensity (basic, comprehensive, exhaustive)
        
    Returns:
        Discovered directories and files with access analysis
    """
    results = {"url": url, "discovered": [], "interesting_findings": []}
    
    try:
        # Technology-specific wordlists
        tech_stack = detect_technology_stack(url)
        wordlist = generate_adaptive_wordlist(tech_stack, scan_level)
        
        # Use ffuf for discovery
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(wordlist))
            wordlist_path = f.name
        
        try:
            ffuf_output = run_command(
                f"ffuf -u {url}/FUZZ -w {wordlist_path} -mc 200,204,301,302,403 -o /tmp/ffuf_results.json -of json"
            )
            
            # Parse results
            with open('/tmp/ffuf_results.json', 'r') as f:
                ffuf_data = json.load(f)
                
            for result in ffuf_data.get('results', []):
                finding = {
                    "path": result['input']['FUZZ'],
                    "status_code": result['status'],
                    "length": result['length'],
                    "words": result['words']
                }
                
                # Analyze findings for security implications
                if result['status'] == 403:
                    finding["note"] = "Forbidden - may contain sensitive content"
                elif result['status'] in [301, 302]:
                    finding["note"] = "Redirect - check destination"
                elif any(sensitive in result['input']['FUZZ'].lower() for sensitive in 
                        ['admin', 'config', 'backup', 'db', 'sql', 'log']):
                    finding["note"] = "Potentially sensitive directory/file"
                    results["interesting_findings"].append(finding)
                
                results["discovered"].append(finding)
        
        finally:
            os.unlink(wordlist_path)
            if os.path.exists('/tmp/ffuf_results.json'):
                os.unlink('/tmp/ffuf_results.json')
    
    except Exception as e:
        results["error"] = str(e)
    
    return json.dumps(results, indent=2)


@function_tool
def api_endpoint_discovery(base_url: str, api_type: str = "rest") -> str:
    """
    Discover API endpoints and analyze their security
    
    Args:
        base_url: Base URL of the application
        api_type: Type of API (rest, graphql, soap)
        
    Returns:
        Discovered API endpoints with security analysis
    """
    results = {"base_url": base_url, "endpoints": [], "security_issues": []}
    
    try:
        # Common API paths
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/restapi', '/webapi',
            '/graphql', '/graphiql',
            '/swagger', '/swagger-ui', '/api-docs',
            '/docs', '/documentation'
        ]
        
        if api_type == "graphql":
            api_paths.extend(['/graphql', '/graphiql', '/playground'])
        elif api_type == "soap":
            api_paths.extend(['/soap', '/wsdl', '/services'])
        
        for path in api_paths:
            try:
                test_url = urljoin(base_url, path)
                response = requests.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    endpoint_info = {
                        "path": path,
                        "status": response.status_code,
                        "content_type": response.headers.get('Content-Type', ''),
                        "size": len(response.content)
                    }
                    
                    # Analyze response for API characteristics
                    content = response.text.lower()
                    
                    if 'swagger' in content or 'openapi' in content:
                        endpoint_info["type"] = "swagger_documentation"
                        results["security_issues"].append("API documentation exposed - may reveal sensitive endpoints")
                    
                    elif 'graphql' in content or '"data":' in content:
                        endpoint_info["type"] = "graphql_endpoint"
                        # Test for introspection
                        introspection_query = {"query": "query IntrospectionQuery { __schema { queryType { name } } }"}
                        intro_response = requests.post(test_url, json=introspection_query)
                        if intro_response.status_code == 200 and 'queryType' in intro_response.text:
                            results["security_issues"].append("GraphQL introspection enabled - schema can be enumerated")
                    
                    elif any(indicator in content for indicator in ['{"', '[{', 'json']):
                        endpoint_info["type"] = "json_api"
                    
                    results["endpoints"].append(endpoint_info)
                
                elif response.status_code == 403:
                    results["endpoints"].append({
                        "path": path,
                        "status": response.status_code,
                        "note": "Forbidden - API exists but access denied"
                    })
            
            except Exception:
                continue
        
        # Test for common API vulnerabilities
        if results["endpoints"]:
            test_common_api_vulnerabilities(base_url, results)
    
    except Exception as e:
        results["error"] = str(e)
    
    return json.dumps(results, indent=2)


# Helper functions
def get_crt_sh_subdomains(domain: str) -> List[str]:
    """Get subdomains from certificate transparency logs"""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        data = response.json()
        
        subdomains = set()
        for cert in data:
            name_value = cert.get('name_value', '')
            for subdomain in name_value.split('\n'):
                subdomain = subdomain.strip()
                if subdomain and not subdomain.startswith('*'):
                    subdomains.add(subdomain)
        
        return list(subdomains)
    except Exception:
        return []


def dns_bruteforce(domain: str, wordlist_size: int = 1000) -> List[str]:
    """Perform DNS bruteforcing for subdomain discovery"""
    common_subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'test', 'staging',
        'dev', 'admin', 'api', 'mobile', 'm', 'blog', 'shop', 'cdn', 'img', 'static'
    ]
    
    found_subdomains = []
    
    for subdomain in common_subdomains[:wordlist_size]:
        try:
            full_domain = f"{subdomain}.{domain}"
            dns.resolver.resolve(full_domain, 'A')
            found_subdomains.append(full_domain)
        except Exception:
            continue
    
    return found_subdomains


def get_common_parameters(wordlist_type: str) -> List[str]:
    """Get parameter wordlist based on type"""
    basic_params = ['id', 'user', 'admin', 'page', 'action', 'cmd', 'search', 'q', 'query']
    
    if wordlist_type == "basic":
        return basic_params
    
    comprehensive_params = basic_params + [
        'debug', 'test', 'username', 'password', 'email', 'file', 'path', 'url',
        'redirect', 'return', 'callback', 'jsonp', 'format', 'type', 'mode',
        'limit', 'offset', 'sort', 'order', 'filter', 'category', 'tag'
    ]
    
    if wordlist_type == "api_focused":
        return comprehensive_params + [
            'api_key', 'token', 'access_token', 'refresh_token', 'client_id',
            'client_secret', 'scope', 'grant_type', 'response_type'
        ]
    
    return comprehensive_params


def analyze_parameter_for_injection(param_name: str) -> List[str]:
    """Analyze parameter name for potential injection types"""
    injection_types = []
    
    if any(keyword in param_name.lower() for keyword in ['id', 'user', 'admin', 'page']):
        injection_types.append('sql_injection')
    
    if any(keyword in param_name.lower() for keyword in ['cmd', 'command', 'exec']):
        injection_types.append('command_injection')
    
    if any(keyword in param_name.lower() for keyword in ['file', 'path', 'dir']):
        injection_types.append('path_traversal')
    
    if any(keyword in param_name.lower() for keyword in ['url', 'redirect', 'link']):
        injection_types.append('ssrf')
    
    return injection_types


def detect_technology_stack(url: str) -> Dict[str, str]:
    """Detect technology stack for adaptive wordlist generation"""
    try:
        response = requests.get(url, timeout=10)
        headers = dict(response.headers)
        content = response.text[:5000]
        
        tech_stack = {}
        
        # Server detection
        if 'Server' in headers:
            server = headers['Server'].lower()
            if 'apache' in server:
                tech_stack['server'] = 'apache'
            elif 'nginx' in server:
                tech_stack['server'] = 'nginx'
            elif 'iis' in server:
                tech_stack['server'] = 'iis'
        
        # Framework detection
        if 'wp-content' in content.lower():
            tech_stack['cms'] = 'wordpress'
        elif 'drupal' in content.lower():
            tech_stack['cms'] = 'drupal'
        elif 'joomla' in content.lower():
            tech_stack['cms'] = 'joomla'
        
        return tech_stack
    except Exception:
        return {}


def generate_adaptive_wordlist(tech_stack: Dict[str, str], scan_level: str) -> List[str]:
    """Generate adaptive wordlist based on detected technology"""
    base_wordlist = [
        'admin', 'administrator', 'backup', 'config', 'test', 'dev', 'staging',
        'api', 'uploads', 'images', 'css', 'js', 'assets', 'static'
    ]
    
    # Add technology-specific paths
    if tech_stack.get('cms') == 'wordpress':
        base_wordlist.extend([
            'wp-admin', 'wp-content', 'wp-includes', 'wp-config.php',
            'wp-login.php', 'xmlrpc.php', 'readme.html'
        ])
    elif tech_stack.get('cms') == 'drupal':
        base_wordlist.extend([
            'sites', 'modules', 'themes', 'core', 'install.php',
            'update.php', 'cron.php', 'user', 'node'
        ])
    
    if tech_stack.get('server') == 'apache':
        base_wordlist.extend(['.htaccess', '.htpasswd', 'server-status', 'server-info'])
    
    if scan_level == "exhaustive":
        # Add more comprehensive wordlist
        base_wordlist.extend([
            'logs', 'log', 'tmp', 'temp', 'cache', 'include', 'inc',
            'lib', 'library', 'src', 'source', 'vendor', 'node_modules'
        ])
    
    return list(set(base_wordlist))  # Remove duplicates


def test_common_api_vulnerabilities(base_url: str, results: Dict) -> None:
    """Test for common API vulnerabilities"""
    
    # Test for rate limiting
    try:
        api_endpoint = None
        for endpoint in results["endpoints"]:
            if endpoint["path"].startswith('/api'):
                api_endpoint = urljoin(base_url, endpoint["path"])
                break
        
        if api_endpoint:
            # Make multiple rapid requests
            responses = []
            for _ in range(10):
                try:
                    resp = requests.get(api_endpoint, timeout=2)
                    responses.append(resp.status_code)
                except Exception:
                    break
            
            # Check if all requests succeeded (no rate limiting)
            if all(status == 200 for status in responses):
                results["security_issues"].append("No rate limiting detected on API endpoints")
    
    except Exception:
        pass
