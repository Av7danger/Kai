#!/usr/bin/env python3
"""
🎯 GEMINI CONTEXT GENERATOR
Creates a complete context prompt for Gemini AI with target-specific information
"""

import sys
import json
from datetime import datetime

def generate_target_context(target, program_info=None):
    """Generate target-specific context to append to master context"""
    
    context = f"""

---
## 🎯 CURRENT TARGET ASSIGNMENT

**Target**: {target}
**Assignment Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Mission**: Begin autonomous bug bounty hunting on this target

### TARGET-SPECIFIC INSTRUCTIONS:

1. **Start immediately** with scope validation for: {target}
2. **Prioritize business-critical functionality** that would impact this company most
3. **Focus on high-payout vulnerabilities** that demonstrate clear business impact
4. **Document everything** for professional bug bounty report submission

"""

    if program_info:
        context += f"""
### PROGRAM-SPECIFIC INFORMATION:

**Program Name**: {program_info.get('name', 'Unknown')}
**Industry**: {program_info.get('industry', 'Technology')}

**In-Scope Assets**:
{chr(10).join('• ' + asset for asset in program_info.get('in_scope', [target]))}

**Out-of-Scope Assets**:
{chr(10).join('• ' + asset for asset in program_info.get('out_of_scope', ['None specified']))}

**Payout Structure**:
• Critical: ${program_info.get('critical_payout', 5000)}
• High: ${program_info.get('high_payout', 1000)}
• Medium: ${program_info.get('medium_payout', 300)}
• Low: ${program_info.get('low_payout', 100)}

**Priority Testing Areas**:
{chr(10).join('• ' + area for area in program_info.get('priority_areas', ['authentication', 'authorization', 'input_validation']))}

**Time Budget**: {program_info.get('time_budget', 4)} hours

"""

    # Add industry-specific focus
    industry_focus = {
        'fintech': [
            'Payment processing vulnerabilities',
            'Financial data exposure',
            'Transaction manipulation',
            'Account takeover scenarios',
            'Regulatory compliance violations'
        ],
        'healthcare': [
            'Patient data exposure (HIPAA)',
            'Medical record access controls', 
            'Healthcare API security',
            'Medical data manipulation'
        ],
        'ecommerce': [
            'Payment bypass scenarios',
            'Price manipulation',
            'Order processing flaws',
            'User account security'
        ],
        'saas': [
            'Multi-tenant data isolation',
            'Admin privilege escalation',
            'API security in business features',
            'Data export/import vulnerabilities'
        ]
    }
    
    industry = program_info.get('industry', '').lower() if program_info else ''
    if industry in industry_focus:
        context += f"""
### INDUSTRY-SPECIFIC FOCUS ({industry.upper()}):
{chr(10).join('• ' + focus for focus in industry_focus[industry])}

"""

    context += f"""
### IMMEDIATE ACTION ITEMS:

1. **Scope Validation**: Verify {target} is in-scope and identify all related assets
2. **Business Analysis**: Research what this company does and their critical business functions  
3. **Technology Stack**: Identify frameworks, servers, and technologies in use
4. **Attack Surface**: Map all accessible endpoints, forms, and functionality
5. **Prioritized Testing**: Start with authentication, payment flows, and sensitive data handling
6. **Document Findings**: Create professional reports for any vulnerabilities discovered

### SUCCESS CRITERIA FOR THIS SESSION:

✅ Find at least 1 vulnerability worth $300+
✅ Create reproducible proof-of-concept
✅ Document clear business impact
✅ Provide actionable remediation steps
✅ Complete testing within time budget

---

🚀 **BEGIN AUTONOMOUS BUG BOUNTY HUNTING ON {target.upper()} NOW!**

Use your expert knowledge, the methodology above, and the tools available to systematically test this target. Focus on high-impact vulnerabilities that would result in significant bug bounty payouts.

Remember: You are an expert security researcher. Be thorough, be methodical, and be profitable!
"""

    return context

def create_complete_prompt(target, program_file=None):
    """Create complete prompt by combining master context with target info"""
    
    # Read master context
    try:
        with open('gemini_master_context.txt', 'r', encoding='utf-8') as f:
            master_context = f.read()
    except FileNotFoundError:
        print("❌ gemini_master_context.txt not found!")
        print("Make sure this file exists in the current directory.")
        return None
    
    # Read program info if provided
    program_info = None
    if program_file:
        try:
            with open(program_file, 'r', encoding='utf-8') as f:
                program_info = json.load(f)
        except FileNotFoundError:
            print(f"⚠️ Program file {program_file} not found. Using default context.")
        except json.JSONDecodeError:
            print(f"⚠️ Invalid JSON in {program_file}. Using default context.")
    
    # Generate target-specific context
    target_context = generate_target_context(target, program_info)
    
    # Combine everything
    complete_prompt = master_context + target_context
    
    return complete_prompt

def save_prompt_to_file(prompt, target):
    """Save the complete prompt to a file"""
    filename = f"gemini_prompt_{target.replace('.', '_').replace('/', '_')}.txt"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(prompt)
        return filename
    except Exception as e:
        print(f"❌ Error saving prompt: {e}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 generate_context.py target.com")
        print("  python3 generate_context.py target.com program_scope.json")
        print("  python3 generate_context.py target.com --print")
        return
    
    target = sys.argv[1]
    program_file = None
    print_only = False
    
    if len(sys.argv) > 2:
        if sys.argv[2] == "--print":
            print_only = True
        else:
            program_file = sys.argv[2]
    
    # Generate complete prompt
    complete_prompt = create_complete_prompt(target, program_file)
    
    if not complete_prompt:
        return
    
    if print_only or "--print" in sys.argv:
        # Print to console
        print("=" * 80)
        print("🎯 COMPLETE GEMINI CONTEXT FOR BUG BOUNTY HUNTING")
        print("=" * 80)
        print(complete_prompt)
        print("=" * 80)
        print("📋 Copy the above text and paste it into Gemini AI")
    else:
        # Save to file
        filename = save_prompt_to_file(complete_prompt, target)
        if filename:
            print(f"✅ Complete Gemini context saved to: {filename}")
            print(f"📋 Copy the contents of {filename} and paste into Gemini AI")
            print(f"🎯 Gemini will then autonomously start testing: {target}")
        
        # Also print a summary
        print(f"\n📊 PROMPT SUMMARY:")
        print(f"Target: {target}")
        print(f"Program file: {program_file or 'Default context'}")
        print(f"Prompt length: {len(complete_prompt)} characters")
        print(f"\n🚀 Ready to feed to Gemini AI for autonomous bug bounty hunting!")

if __name__ == "__main__":
    main()
