# 🚀 QUICK START CONFIGURATION
# Your personal bug bounty settings

# API Configuration
GEMINI_API_KEY = "AIzaSyDYKxald07-cc-BFHWFOwnFWU9BlW-LFpY"

# Personal Hunter Profile
HUNTER_PROFILE = {
    "experience_level": "intermediate",  # beginner, intermediate, advanced, expert
    "daily_hours": 8,                   # How many hours you want to hunt per day
    "monthly_target": 50000,            # Your monthly earnings goal ($)
    "risk_tolerance": "low",         # low, medium, high
    "specializations": [                # Your areas of expertise
        "web_app", 
        "api", 
        "mobile", 
        "business_logic"
    ]
}

# System Settings
SYSTEM_CONFIG = {
    "max_concurrent_targets": 5,        # How many targets to process at once
    "ai_confidence_threshold": 0.75,    # Minimum confidence for AI decisions
    "enable_human_escalation": True,    # Enable expert escalation
    "enable_compliance_checks": True,   # Enable legal compliance validation
    "enable_data_provenance": True,     # Enable audit trails
    "documentation_level": "forensic"   # basic, detailed, forensic
}

# Target Preferences
TARGET_PREFERENCES = {
    "min_payout": 1000,                 # Minimum bounty payout to consider
    "max_payout": 50000,                # Maximum bounty payout range
    "preferred_difficulty": "medium",    # easy, medium, hard, expert
    "avoid_high_competition": True,      # Skip extremely competitive programs
    "fast_payout_preference": True      # Prefer programs with fast payouts
}

# 🎯 PROGRAM SCOPE CONFIGURATION
# This tells the AI model exactly what to focus on for maximum profit

PROGRAM_SCOPE = {
    # Target Selection Criteria
    "target_types": [
        "web_applications",
        "mobile_apps", 
        "apis",
        "cloud_infrastructure",
        "iot_devices"
    ],
    
    # Vulnerability Focus Areas (prioritized by profit potential)
    "vulnerability_priorities": {
        "critical": [
            "remote_code_execution",
            "sql_injection", 
            "authentication_bypass",
            "privilege_escalation",
            "data_exposure"
        ],
        "high": [
            "xss_stored",
            "csrf",
            "idor",
            "business_logic_flaws",
            "api_security_issues"
        ],
        "medium": [
            "xss_reflected",
            "information_disclosure",
            "subdomain_takeover",
            "rate_limiting_bypass"
        ]
    },
    
    # Industries to Focus On (higher payouts)
    "target_industries": [
        "fintech",
        "healthcare", 
        "e_commerce",
        "social_media",
        "cloud_providers",
        "cryptocurrency"
    ],
    
    # Scope Boundaries
    "in_scope": [
        "*.target.com",
        "api.target.com",
        "mobile apps",
        "web applications",
        "documented endpoints"
    ],
    
    "out_of_scope": [
        "physical_attacks",
        "social_engineering",
        "dos_attacks",
        "brute_force",
        "spam"
    ]
}

# 🤖 AI MODEL CONTEXT AND INSTRUCTIONS
AI_CONTEXT = {
    # Core Mission
    "primary_objective": "Find high-impact vulnerabilities that maximize bounty payouts while staying within legal and ethical boundaries",
    
    # AI Personality and Approach
    "ai_personality": {
        "role": "Expert Bug Bounty Hunter",
        "style": "methodical, thorough, profit-focused",
        "expertise_areas": [
            "OWASP Top 10",
            "API Security",
            "Business Logic Testing", 
            "Modern Web Application Security",
            "Mobile Application Security"
        ]
    },
    
    # Decision Making Framework
    "decision_criteria": {
        "vulnerability_scoring": {
            "impact": 0.4,      # 40% weight on impact
            "exploitability": 0.3,  # 30% weight on how easy to exploit
            "payout_potential": 0.3  # 30% weight on likely payout
        },
        "time_allocation": {
            "recon": 0.2,       # 20% time on reconnaissance
            "testing": 0.6,     # 60% time on active testing
            "reporting": 0.2    # 20% time on documentation
        }
    },
    
    # Learning and Adaptation
    "learning_preferences": {
        "update_strategies_based_on": [
            "successful_submissions",
            "rejected_reports", 
            "payout_trends",
            "new_vulnerability_types"
        ],
        "benchmark_against": [
            "top_hackers_methodologies",
            "latest_security_research",
            "platform_specific_preferences"
        ]
    }
}

# 📊 SUCCESS METRICS AND KPIs
SUCCESS_METRICS = {
    "daily_targets": {
        "vulnerabilities_found": 3,
        "reports_submitted": 2,
        "earnings_goal": 1500
    },
    
    "weekly_targets": {
        "new_programs_researched": 5,
        "follow_up_reports": 3,
        "earnings_goal": 10000
    },
    
    "monthly_targets": {
        "total_earnings": 50000,
        "acceptance_rate": 0.8,    # 80% of reports accepted
        "average_payout": 2500
    }
}

# 🔍 METHODOLOGY AND WORKFLOW
HUNTING_METHODOLOGY = {
    # Reconnaissance Phase
    "recon_workflow": [
        "asset_discovery",
        "technology_stack_analysis", 
        "attack_surface_mapping",
        "previous_reports_analysis",
        "program_scope_validation"
    ],
    
    # Testing Phase  
    "testing_workflow": [
        "automated_vulnerability_scanning",
        "manual_security_testing",
        "business_logic_analysis",
        "api_security_testing",
        "privilege_escalation_testing"
    ],
    
    # Reporting Phase
    "reporting_workflow": [
        "impact_assessment",
        "proof_of_concept_development",
        "remediation_recommendations",
        "report_quality_validation",
        "submission_optimization"
    ]
}

# 🎯 PLATFORM-SPECIFIC CONFIGURATIONS
PLATFORM_CONFIGS = {
    "hackerone": {
        "preferred_report_style": "detailed_technical",
        "average_response_time": "3_days",
        "payout_reliability": "high",
        "competition_level": "high"
    },
    
    "bugcrowd": {
        "preferred_report_style": "business_impact_focused", 
        "average_response_time": "5_days",
        "payout_reliability": "medium_high",
        "competition_level": "medium"
    },
    
    "intigriti": {
        "preferred_report_style": "exploit_focused",
        "average_response_time": "7_days", 
        "payout_reliability": "medium",
        "competition_level": "low"
    }
}
