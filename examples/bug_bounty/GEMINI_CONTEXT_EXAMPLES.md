# 🎯 GEMINI CONTEXT USAGE EXAMPLES

## EXAMPLE 1: Quick Target Testing
```bash
# Generate context for a specific target
python3 generate_context.py testphp.vulnweb.com --print

# This creates a complete prompt that you copy/paste to Gemini
# Gemini will then autonomously start testing the target
```

## EXAMPLE 2: With Program Scope
```bash
# First set up program scope
python3 scope_wizard.py quick example.com

# Then generate context with program info
python3 generate_context.py example.com scope_example_com.json

# This creates a targeted prompt with specific scope and payout info
```

## EXAMPLE 3: Complete Workflow
```bash
# 1. Set up detailed program scope
python3 scope_wizard.py
# (Follow interactive prompts)

# 2. Generate Gemini context
python3 generate_context.py target.com scope_myprogram.json

# 3. Copy the generated file content and paste into Gemini
# 4. Gemini starts autonomous bug bounty hunting!
```

## WHAT GEMINI GETS:

✅ **Complete Role Definition** - Expert bug bounty hunter identity
✅ **Vulnerability Priorities** - Focus on high-payout findings ($5000+ critical, $1000+ high)
✅ **Testing Methodology** - Structured approach (recon → testing → reporting)
✅ **Legal Boundaries** - Clear scope and compliance guidelines
✅ **Industry Context** - Specific focus areas for fintech, healthcare, etc.
✅ **Success Metrics** - Daily goals and quality indicators
✅ **Tools & Commands** - Specific security testing commands to use
✅ **Output Format** - Professional vulnerability report structure

## RESULT:
Gemini becomes an autonomous bug bounty hunter that:
- Validates scope before testing
- Focuses on high-impact vulnerabilities
- Uses proper testing methodology
- Creates professional reports
- Maximizes payout potential
- Stays legally compliant

## SAMPLE GENERATED PROMPT:
The generated file will be ~3000+ words containing:
1. Master context (role, methodology, priorities)
2. Target-specific instructions
3. Program scope and payout info
4. Industry-specific focus areas
5. Immediate action items
6. Success criteria

Just copy the entire generated file and paste it into Gemini - it will start hunting immediately!
