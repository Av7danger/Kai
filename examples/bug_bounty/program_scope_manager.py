# 🎯 ADVANCED PROGRAM SCOPE MANAGER
# Defines exactly what the AI model should focus on for maximum bounty earnings

import json
from typing import Dict, List, Any
from datetime import datetime

class ProgramScopeManager:
    """Manages program scope and AI model context for bug bounty hunting"""
    
    def __init__(self):
        self.scope_config = self._load_default_scope()
        self.active_programs = {}
        self.learning_data = {}
    
    def _load_default_scope(self) -> Dict[str, Any]:
        """Load default scope configuration"""
        return {
            "global_scope": {
                "focus_areas": [
                    "High-impact vulnerabilities with clear business impact",
                    "Critical security flaws in authentication/authorization",
                    "Data exposure and privacy violations", 
                    "API security vulnerabilities",
                    "Business logic flaws in core functionality"
                ],
                
                "exclusions": [
                    "Out-of-scope domains and subdomains",
                    "Physical security attacks",
                    "Social engineering attacks",
                    "Denial of service attacks",
                    "Rate limiting issues (unless critical)"
                ],
                
                "legal_boundaries": [
                    "Only test in-scope assets",
                    "Do not access other users' data",
                    "Do not perform destructive actions",
                    "Respect rate limits and system resources",
                    "Follow responsible disclosure practices"
                ]
            },
            
            "vulnerability_hierarchy": {
                "tier_1_critical": {
                    "types": ["RCE", "SQLi", "Auth Bypass", "Privilege Escalation"],
                    "min_payout": 5000,
                    "time_investment": "high",
                    "automation_level": "manual_validation_required"
                },
                "tier_2_high": {
                    "types": ["Stored XSS", "CSRF", "IDOR", "API Security"],
                    "min_payout": 1000,
                    "time_investment": "medium", 
                    "automation_level": "semi_automated"
                },
                "tier_3_medium": {
                    "types": ["Reflected XSS", "Info Disclosure", "Subdomain Takeover"],
                    "min_payout": 200,
                    "time_investment": "low",
                    "automation_level": "fully_automated"
                }
            }
        }
    
    def set_program_scope(self, program_name: str, scope_config: Dict[str, Any]):
        """Set scope for a specific bug bounty program"""
        
        validated_scope = {
            "program_name": program_name,
            "timestamp": datetime.now().isoformat(),
            
            # Target Information
            "in_scope_assets": scope_config.get("in_scope", []),
            "out_of_scope_assets": scope_config.get("out_of_scope", []),
            "asset_types": scope_config.get("asset_types", ["web", "mobile", "api"]),
            
            # Business Context
            "company_info": {
                "industry": scope_config.get("industry", "technology"),
                "size": scope_config.get("company_size", "medium"),
                "business_model": scope_config.get("business_model", "saas"),
                "key_business_functions": scope_config.get("key_functions", [])
            },
            
            # Payout Information
            "payout_structure": {
                "critical": scope_config.get("critical_payout", 5000),
                "high": scope_config.get("high_payout", 1000), 
                "medium": scope_config.get("medium_payout", 300),
                "low": scope_config.get("low_payout", 100),
                "currency": scope_config.get("currency", "USD"),
                "average_response_time": scope_config.get("response_time", "5_days")
            },
            
            # Testing Preferences
            "testing_focus": {
                "priority_areas": scope_config.get("priority_areas", [
                    "authentication", "authorization", "input_validation", 
                    "business_logic", "api_security"
                ]),
                "testing_depth": scope_config.get("testing_depth", "thorough"),
                "automation_preference": scope_config.get("automation", "balanced")
            },
            
            # AI Instructions
            "ai_context": {
                "testing_methodology": scope_config.get("methodology", "owasp_based"),
                "report_style": scope_config.get("report_style", "technical_detailed"),
                "risk_tolerance": scope_config.get("risk_tolerance", "medium"),
                "time_budget": scope_config.get("time_budget_hours", 8)
            }
        }
        
        self.active_programs[program_name] = validated_scope
        return validated_scope
    
    def get_ai_context_prompt(self, program_name: str = None) -> str:
        """Generate AI context prompt for the current scope"""
        
        if program_name and program_name in self.active_programs:
            scope = self.active_programs[program_name]
            
            prompt = f"""
🎯 BUG BOUNTY PROGRAM CONTEXT

Program: {scope['program_name']}
Industry: {scope['company_info']['industry']}
Business Model: {scope['company_info']['business_model']}

IN-SCOPE ASSETS:
{chr(10).join('• ' + asset for asset in scope['in_scope_assets'])}

OUT-OF-SCOPE (AVOID):
{chr(10).join('• ' + asset for asset in scope['out_of_scope_assets'])}

PAYOUT STRUCTURE:
• Critical: ${scope['payout_structure']['critical']}
• High: ${scope['payout_structure']['high']} 
• Medium: ${scope['payout_structure']['medium']}
• Low: ${scope['payout_structure']['low']}

PRIORITY TESTING AREAS:
{chr(10).join('• ' + area for area in scope['testing_focus']['priority_areas'])}

AI MISSION:
Focus on finding {scope['ai_context']['testing_depth']} vulnerabilities in the priority areas above. 
Use {scope['ai_context']['testing_methodology']} methodology.
Target minimum payout of ${scope['payout_structure']['medium']} per vulnerability.
Time budget: {scope['ai_context']['time_budget']} hours.

LEGAL BOUNDARIES:
• Only test in-scope assets listed above
• Do not access other users' data
• Follow responsible disclosure practices
• Respect system resources and rate limits
"""
        else:
            # Default global context
            prompt = """
🎯 GENERAL BUG BOUNTY CONTEXT

MISSION: Find high-impact security vulnerabilities for maximum bounty earnings

FOCUS AREAS:
• Authentication and authorization flaws
• Input validation vulnerabilities  
• Business logic security issues
• API security vulnerabilities
• Data exposure and privacy violations

PAYOUT TARGETS:
• Aim for Critical/High severity findings ($1000+ payouts)
• Document clear business impact
• Provide actionable remediation steps

METHODOLOGY:
• Use OWASP Top 10 as baseline
• Focus on manual testing for business logic
• Combine automated and manual approaches
• Prioritize time based on payout potential
"""
        
        return prompt
    
    def update_scope_from_results(self, program_name: str, results: Dict[str, Any]):
        """Update scope based on hunting results and feedback"""
        
        if program_name not in self.active_programs:
            return
        
        scope = self.active_programs[program_name]
        
        # Update based on successful findings
        if results.get("accepted_reports"):
            successful_areas = [r.get("vulnerability_type") for r in results["accepted_reports"]]
            scope["testing_focus"]["priority_areas"].extend(successful_areas)
        
        # Adjust time allocation based on ROI
        if results.get("time_spent") and results.get("total_payout"):
            roi = results["total_payout"] / results["time_spent"]
            if roi > 200:  # $200/hour
                scope["ai_context"]["time_budget"] += 2
            elif roi < 50:  # $50/hour  
                scope["ai_context"]["time_budget"] = max(4, scope["ai_context"]["time_budget"] - 2)
        
        # Store learning data
        self.learning_data[program_name] = {
            "last_updated": datetime.now().isoformat(),
            "results_summary": results,
            "scope_adjustments": "auto_updated_based_on_roi"
        }
    
    def get_scope_summary(self, program_name: str = None) -> str:
        """Get a summary of current scope configuration"""
        
        if program_name and program_name in self.active_programs:
            scope = self.active_programs[program_name]
            return f"""
📋 SCOPE SUMMARY: {scope['program_name']}

🎯 In-Scope: {len(scope['in_scope_assets'])} assets
🚫 Out-of-Scope: {len(scope['out_of_scope_assets'])} assets  
💰 Max Payout: ${scope['payout_structure']['critical']}
⏱️ Time Budget: {scope['ai_context']['time_budget']} hours
🔍 Priority Areas: {len(scope['testing_focus']['priority_areas'])} focus areas
"""
        else:
            return f"""
📋 GLOBAL SCOPE STATUS

🎯 Active Programs: {len(self.active_programs)}
📊 Learning Data: {len(self.learning_data)} programs tracked
🤖 AI Context: Default global hunting mode
"""

# Example usage
def create_example_scope():
    """Example of how to set up program scope"""
    
    scope_manager = ProgramScopeManager()
    
    # Example program scope
    example_scope = {
        "in_scope": [
            "*.example.com",
            "api.example.com", 
            "mobile.example.com",
            "admin.example.com"
        ],
        "out_of_scope": [
            "blog.example.com",
            "static.example.com",
            "legacy.example.com"
        ],
        "industry": "fintech",
        "company_size": "enterprise", 
        "business_model": "saas",
        "key_functions": ["payments", "user_accounts", "data_analytics"],
        "critical_payout": 10000,
        "high_payout": 2500,
        "medium_payout": 500,
        "priority_areas": [
            "payment_processing", "authentication", "api_security", 
            "data_privacy", "business_logic"
        ],
        "testing_depth": "thorough",
        "methodology": "owasp_plus_business_logic",
        "time_budget_hours": 12
    }
    
    # Set the scope
    validated_scope = scope_manager.set_program_scope("ExampleCorp", example_scope)
    
    # Get AI context
    ai_prompt = scope_manager.get_ai_context_prompt("ExampleCorp")
    
    print("✅ Example scope configured!")
    print(f"🤖 AI Context:\n{ai_prompt}")
    
    return scope_manager

if __name__ == "__main__":
    # Demo the scope manager
    create_example_scope()
