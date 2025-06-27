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
