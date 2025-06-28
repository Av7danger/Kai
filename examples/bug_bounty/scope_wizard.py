#!/usr/bin/env python3
"""
🎯 SCOPE CONFIGURATION WIZARD
Sets up program scope and AI model context for bug bounty hunting
"""

from program_scope_manager import ProgramScopeManager
import json

def setup_program_scope():
    """Interactive wizard to set up program scope"""
    
    print("🎯 BUG BOUNTY PROGRAM SCOPE WIZARD")
    print("=" * 50)
    
    scope_manager = ProgramScopeManager()
    
    # Get basic program info
    program_name = input("📝 Program name (e.g., 'ExampleCorp'): ").strip()
    if not program_name:
        program_name = "DefaultProgram"
    
    print(f"\n🏢 Setting up scope for: {program_name}")
    
    # Get scope assets
    print("\n📍 IN-SCOPE ASSETS:")
    print("Enter domains/assets (one per line, empty line to finish):")
    in_scope = []
    while True:
        asset = input("  • ").strip()
        if not asset:
            break
        in_scope.append(asset)
    
    print("\n🚫 OUT-OF-SCOPE ASSETS:")  
    print("Enter domains/assets to avoid (one per line, empty line to finish):")
    out_of_scope = []
    while True:
        asset = input("  • ").strip()
        if not asset:
            break
        out_of_scope.append(asset)
    
    # Get industry info
    print("\n🏭 COMPANY DETAILS:")
    industry_options = ["fintech", "healthcare", "e-commerce", "social_media", "saas", "other"]
    print("Industries:", ", ".join(industry_options))
    industry = input("Industry: ").strip() or "technology"
    
    # Get payout info
    print("\n💰 PAYOUT STRUCTURE:")
    critical_payout = input("Critical severity payout ($): ").strip()
    critical_payout = int(critical_payout) if critical_payout.isdigit() else 5000
    
    high_payout = input("High severity payout ($): ").strip()
    high_payout = int(high_payout) if high_payout.isdigit() else 1000
    
    medium_payout = input("Medium severity payout ($): ").strip()
    medium_payout = int(medium_payout) if medium_payout.isdigit() else 300
    
    # Get focus areas
    print("\n🔍 PRIORITY TESTING AREAS:")
    focus_options = [
        "authentication", "authorization", "input_validation", 
        "business_logic", "api_security", "data_privacy", 
        "payment_processing", "file_upload", "session_management"
    ]
    print("Available areas:", ", ".join(focus_options))
    print("Enter priority areas (comma-separated):")
    priority_input = input("Areas: ").strip()
    priority_areas = [area.strip() for area in priority_input.split(",") if area.strip()]
    if not priority_areas:
        priority_areas = ["authentication", "authorization", "input_validation"]
    
    # Get time budget
    time_budget = input("\n⏱️ Time budget for this program (hours): ").strip()
    time_budget = int(time_budget) if time_budget.isdigit() else 8
    
    # Create scope configuration
    scope_config = {
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "industry": industry,
        "company_size": "medium",  # Default
        "business_model": "saas",  # Default
        "critical_payout": critical_payout,
        "high_payout": high_payout,
        "medium_payout": medium_payout,
        "priority_areas": priority_areas,
        "testing_depth": "thorough",
        "methodology": "owasp_plus_business_logic",
        "time_budget_hours": time_budget,
        "report_style": "technical_detailed"
    }
    
    # Set the scope
    validated_scope = scope_manager.set_program_scope(program_name, scope_config)
    
    # Show summary
    print("\n" + "="*50)
    print("✅ SCOPE CONFIGURATION COMPLETE!")
    print("="*50)
    print(scope_manager.get_scope_summary(program_name))
    
    # Get AI context prompt
    ai_context = scope_manager.get_ai_context_prompt(program_name)
    
    # Save to file
    config_file = f"scope_{program_name.lower().replace(' ', '_')}.json"
    with open(config_file, 'w') as f:
        json.dump(validated_scope, f, indent=2)
    
    print(f"💾 Scope saved to: {config_file}")
    
    # Save AI context
    ai_file = f"ai_context_{program_name.lower().replace(' ', '_')}.txt"
    with open(ai_file, 'w') as f:
        f.write(ai_context)
    
    print(f"🤖 AI context saved to: {ai_file}")
    
    print(f"\n🚀 READY TO HUNT!")
    print(f"Use: python3 kali_bb_pro.py quick-hunt [target] --program {program_name}")
    
    return scope_manager, validated_scope

def load_existing_scope(program_name: str):
    """Load an existing scope configuration"""
    
    config_file = f"scope_{program_name.lower().replace(' ', '_')}.json"
    
    try:
        with open(config_file, 'r') as f:
            scope_data = json.load(f)
        
        scope_manager = ProgramScopeManager()
        scope_manager.active_programs[program_name] = scope_data
        
        print(f"✅ Loaded scope for: {program_name}")
        print(scope_manager.get_scope_summary(program_name))
        
        return scope_manager
        
    except FileNotFoundError:
        print(f"❌ No scope file found for: {program_name}")
        print(f"Expected file: {config_file}")
        return None

def quick_scope_setup(target: str):
    """Quick scope setup for a single target"""
    
    scope_manager = ProgramScopeManager()
    
    # Extract domain from target
    if target.startswith(('http://', 'https://')):
        domain = target.split('/')[2]
    else:
        domain = target
    
    program_name = f"QuickHunt_{domain.replace('.', '_')}"
    
    # Default quick scope
    quick_scope = {
        "in_scope": [f"*.{domain}", domain],
        "out_of_scope": [],
        "industry": "technology",
        "critical_payout": 2000,
        "high_payout": 500,
        "medium_payout": 100,
        "priority_areas": ["authentication", "input_validation", "business_logic"],
        "testing_depth": "standard",
        "time_budget_hours": 4
    }
    
    scope_manager.set_program_scope(program_name, quick_scope)
    
    print(f"🎯 Quick scope set up for: {target}")
    print(scope_manager.get_scope_summary(program_name))
    
    return scope_manager, program_name

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "load" and len(sys.argv) > 2:
            # Load existing scope
            load_existing_scope(sys.argv[2])
        elif sys.argv[1] == "quick" and len(sys.argv) > 2:
            # Quick setup for target
            quick_scope_setup(sys.argv[2])
        else:
            print("Usage:")
            print("  python3 scope_wizard.py                    # Interactive setup")
            print("  python3 scope_wizard.py load ProgramName   # Load existing")
            print("  python3 scope_wizard.py quick target.com   # Quick setup")
    else:
        # Interactive setup
        setup_program_scope()
