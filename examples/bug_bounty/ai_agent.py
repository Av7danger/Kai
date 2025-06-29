#!/usr/bin/env python3
"""
AI Agent for Autonomous Bug Hunting
Provides intelligent analysis, decision making, and result interpretation
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import aiohttp
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class AIProvider(Enum):
    """Supported AI providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"

class AnalysisType(Enum):
    """Types of AI analysis"""
    TARGET_ANALYSIS = "target_analysis"
    RESULT_ANALYSIS = "result_analysis"
    WORKFLOW_PLANNING = "workflow_planning"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"

@dataclass
class AIAnalysisResult:
    """Result of AI analysis"""
    analysis_type: AnalysisType
    confidence: float
    insights: List[str]
    recommendations: List[str]
    risk_level: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

@dataclass
class TargetAnalysis:
    """Target analysis result"""
    target_url: str
    scope: str
    attack_surface: List[str]
    potential_vulnerabilities: List[str]
    recommended_tools: List[str]
    risk_assessment: Dict[str, Any]
    complexity_score: float

class ChatSession(BaseModel):
    """Chat session model"""
    session_id: str
    messages: List[Dict[str, str]] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)
    last_activity: float = Field(default_factory=time.time)

class AIAgent:
    """Intelligent AI agent for autonomous bug hunting"""
    
    def __init__(self, 
                 default_provider: AIProvider = AIProvider.GEMINI,
                 api_keys: Optional[Dict[str, str]] = None,
                 max_retries: int = 3):
        """
        Initialize AI Agent
        
        Args:
            default_provider: Default AI provider to use
            api_keys: Dictionary of API keys for different providers
            max_retries: Maximum number of retries for API calls
        """
        self.default_provider = default_provider
        self.api_keys = api_keys or {}
        self.max_retries = max_retries
        self.sessions: Dict[str, ChatSession] = {}
        self.analysis_cache: Dict[str, AIAnalysisResult] = {}
        
        # Configure providers
        self._setup_providers()
    
    def _setup_providers(self) -> None:
        """Setup AI provider configurations"""
        self.providers = {
            AIProvider.OPENAI: {
                'base_url': 'https://api.openai.com/v1',
                'model': 'gpt-4',
                'max_tokens': 4000
            },
            AIProvider.ANTHROPIC: {
                'base_url': 'https://api.anthropic.com',
                'model': 'claude-3-sonnet-20240229',
                'max_tokens': 4000
            },
            AIProvider.GEMINI: {
                'base_url': 'https://generativelanguage.googleapis.com',
                'model': 'gemini-pro',
                'max_tokens': 4000
            }
        }
    
    async def analyze_target(self, target: str, scope: str) -> TargetAnalysis:
        """
        Analyze target for bug hunting
        
        Args:
            target: Target URL or domain
            scope: Scope of the bug bounty program
            
        Returns:
            TargetAnalysis object with comprehensive analysis
        """
        logger.info(f"Analyzing target: {target}")
        
        # Check cache first
        cache_key = f"target_analysis:{target}:{scope}"
        if cache_key in self.analysis_cache:
            cached_result = self.analysis_cache[cache_key]
            if time.time() - cached_result.timestamp < 3600:  # 1 hour cache
                logger.info("Using cached target analysis")
                return cached_result.data
        
        # Prepare analysis prompt
        prompt = self._build_target_analysis_prompt(target, scope)
        
        # Get AI response
        response = await self._get_ai_response(prompt, AIProvider.GEMINI)
        
        # Parse and structure the response
        analysis = self._parse_target_analysis(response, target, scope)
        
        # Cache the result
        result = AIAnalysisResult(
            analysis_type=AnalysisType.TARGET_ANALYSIS,
            confidence=0.85,
            insights=analysis.get('insights', []),
            recommendations=analysis.get('recommendations', []),
            risk_level=analysis.get('risk_level', 'medium'),
            data=analysis
        )
        self.analysis_cache[cache_key] = result
        
        return TargetAnalysis(**analysis)
    
    async def analyze_results(self, 
                            vuln_results: Dict[str, Any], 
                            recon_results: Dict[str, Any]) -> AIAnalysisResult:
        """
        Analyze vulnerability and reconnaissance results
        
        Args:
            vuln_results: Vulnerability scan results
            recon_results: Reconnaissance results
            
        Returns:
            AIAnalysisResult with comprehensive analysis
        """
        logger.info("Analyzing scan results")
        
        # Prepare analysis prompt
        prompt = self._build_result_analysis_prompt(vuln_results, recon_results)
        
        # Get AI response
        response = await self._get_ai_response(prompt, AIProvider.GEMINI)
        
        # Parse the response
        analysis = self._parse_result_analysis(response)
        
        return AIAnalysisResult(
            analysis_type=AnalysisType.RESULT_ANALYSIS,
            confidence=analysis.get('confidence', 0.8),
            insights=analysis.get('insights', []),
            recommendations=analysis.get('recommendations', []),
            risk_level=analysis.get('risk_level', 'medium'),
            data=analysis
        )
    
    async def plan_workflow(self, 
                          target: str, 
                          scope: str, 
                          available_tools: List[str]) -> Dict[str, Any]:
        """
        Plan optimal workflow for bug hunting
        
        Args:
            target: Target URL or domain
            scope: Scope of the bug bounty program
            available_tools: List of available tools
            
        Returns:
            Workflow plan with steps and tool assignments
        """
        logger.info(f"Planning workflow for {target}")
        
        # Prepare planning prompt
        prompt = self._build_workflow_planning_prompt(target, scope, available_tools)
        
        # Get AI response
        response = await self._get_ai_response(prompt, AIProvider.GEMINI)
        
        # Parse the response
        workflow_plan = self._parse_workflow_plan(response)
        
        return workflow_plan
    
    async def chat(self, message: str, session_id: Optional[str] = None) -> str:
        """
        Chat with AI about the system and workflows
        
        Args:
            message: User message
            session_id: Optional session ID for context
            
        Returns:
            AI response
        """
        # Get or create session
        if session_id is None:
            session_id = f"session_{int(time.time())}"
        
        if session_id not in self.sessions:
            self.sessions[session_id] = ChatSession(session_id=session_id)
        
        session = self.sessions[session_id]
        
        # Add user message to session
        session.messages.append({
            'role': 'user',
            'content': message,
            'timestamp': time.time()
        })
        
        # Prepare chat prompt with context
        prompt = self._build_chat_prompt(message, session)
        
        # Get AI response
        response = await self._get_ai_response(prompt, AIProvider.GEMINI)
        
        # Add AI response to session
        session.messages.append({
            'role': 'assistant',
            'content': response,
            'timestamp': time.time()
        })
        session.last_activity = time.time()
        
        return response
    
    async def _get_ai_response(self, 
                              prompt: str, 
                              provider: AIProvider = None) -> str:
        """
        Get response from AI provider
        
        Args:
            prompt: Input prompt
            provider: AI provider to use
            
        Returns:
            AI response text
        """
        provider = provider or self.default_provider
        
        for attempt in range(self.max_retries):
            try:
                if provider == AIProvider.GEMINI:
                    return await self._call_gemini_api(prompt)
                elif provider == AIProvider.OPENAI:
                    return await self._call_openai_api(prompt)
                elif provider == AIProvider.ANTHROPIC:
                    return await self._call_anthropic_api(prompt)
                else:
                    raise ValueError(f"Unsupported provider: {provider}")
                    
            except Exception as e:
                logger.error(f"AI API call failed (attempt {attempt + 1}): {e}")
                if attempt == self.max_retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
    
    async def _call_gemini_api(self, prompt: str) -> str:
        """Call Gemini API"""
        # Simulated Gemini API call
        await asyncio.sleep(0.5)  # Simulate API delay
        
        # Return structured response based on prompt type
        if "target analysis" in prompt.lower():
            return self._generate_target_analysis_response()
        elif "result analysis" in prompt.lower():
            return self._generate_result_analysis_response()
        elif "workflow planning" in prompt.lower():
            return self._generate_workflow_planning_response()
        else:
            return self._generate_chat_response(prompt)
    
    async def _call_openai_api(self, prompt: str) -> str:
        """Call OpenAI API"""
        # Simulated OpenAI API call
        await asyncio.sleep(0.5)
        return f"OpenAI response to: {prompt[:100]}..."
    
    async def _call_anthropic_api(self, prompt: str) -> str:
        """Call Anthropic API"""
        # Simulated Anthropic API call
        await asyncio.sleep(0.5)
        return f"Anthropic response to: {prompt[:100]}..."
    
    def _build_target_analysis_prompt(self, target: str, scope: str) -> str:
        """Build prompt for target analysis"""
        return f"""
        Analyze the following target for bug hunting:
        
        Target: {target}
        Scope: {scope}
        
        Provide a comprehensive analysis including:
        1. Attack surface identification
        2. Potential vulnerability types
        3. Recommended tools and techniques
        4. Risk assessment
        5. Complexity score (1-10)
        
        Format the response as JSON with the following structure:
        {{
            "target_url": "{target}",
            "scope": "{scope}",
            "attack_surface": ["list", "of", "attack", "vectors"],
            "potential_vulnerabilities": ["list", "of", "vulnerability", "types"],
            "recommended_tools": ["list", "of", "tools"],
            "risk_assessment": {{
                "overall_risk": "low|medium|high",
                "factors": ["risk", "factors"]
            }},
            "complexity_score": 7.5,
            "insights": ["key", "insights"],
            "recommendations": ["recommendations"]
        }}
        """
    
    def _build_result_analysis_prompt(self, 
                                    vuln_results: Dict[str, Any], 
                                    recon_results: Dict[str, Any]) -> str:
        """Build prompt for result analysis"""
        return f"""
        Analyze the following bug hunting results:
        
        Vulnerability Results: {json.dumps(vuln_results, indent=2)}
        Reconnaissance Results: {json.dumps(recon_results, indent=2)}
        
        Provide analysis including:
        1. Key findings and insights
        2. Risk assessment
        3. Recommendations for further investigation
        4. Confidence level
        
        Format as JSON with structure:
        {{
            "confidence": 0.85,
            "insights": ["insights"],
            "recommendations": ["recommendations"],
            "risk_level": "low|medium|high",
            "key_findings": ["findings"]
        }}
        """
    
    def _build_workflow_planning_prompt(self, 
                                      target: str, 
                                      scope: str, 
                                      available_tools: List[str]) -> str:
        """Build prompt for workflow planning"""
        return f"""
        Plan an optimal bug hunting workflow:
        
        Target: {target}
        Scope: {scope}
        Available Tools: {', '.join(available_tools)}
        
        Create a detailed workflow plan with:
        1. Sequential steps
        2. Tool assignments
        3. Expected outcomes
        4. Success criteria
        
        Format as JSON with structure:
        {{
            "workflow_steps": [
                {{
                    "step": 1,
                    "name": "Reconnaissance",
                    "tools": ["tool1", "tool2"],
                    "description": "description",
                    "expected_outcome": "outcome"
                }}
            ],
            "estimated_duration": "30 minutes",
            "success_criteria": ["criteria"]
        }}
        """
    
    def _build_chat_prompt(self, message: str, session: ChatSession) -> str:
        """Build chat prompt with context"""
        context = f"""
        You are an AI assistant for a Kali Linux bug hunting system.
        
        Previous conversation context:
        {json.dumps(session.messages[-5:], indent=2)}
        
        Current message: {message}
        
        Provide helpful, technical responses about bug hunting, security tools, and the system.
        """
        return context
    
    def _parse_target_analysis(self, response: str, target: str, scope: str) -> Dict[str, Any]:
        """Parse target analysis response"""
        try:
            # Try to extract JSON from response
            if '{' in response and '}' in response:
                start = response.find('{')
                end = response.rfind('}') + 1
                json_str = response[start:end]
                return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Fallback to structured response
        return {
            "target_url": target,
            "scope": scope,
            "attack_surface": ["web", "api", "infrastructure"],
            "potential_vulnerabilities": ["xss", "sqli", "rce"],
            "recommended_tools": ["nmap", "nuclei", "sqlmap"],
            "risk_assessment": {
                "overall_risk": "medium",
                "factors": ["public target", "complex scope"]
            },
            "complexity_score": 7.0,
            "insights": ["Target appears to be a web application", "Multiple attack vectors identified"],
            "recommendations": ["Start with reconnaissance", "Focus on common web vulnerabilities"]
        }
    
    def _parse_result_analysis(self, response: str) -> Dict[str, Any]:
        """Parse result analysis response"""
        try:
            if '{' in response and '}' in response:
                start = response.find('{')
                end = response.rfind('}') + 1
                json_str = response[start:end]
                return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            pass
        
        return {
            "confidence": 0.8,
            "insights": ["Analysis completed successfully"],
            "recommendations": ["Review findings", "Generate report"],
            "risk_level": "medium",
            "key_findings": ["No critical vulnerabilities found"]
        }
    
    def _parse_workflow_plan(self, response: str) -> Dict[str, Any]:
        """Parse workflow planning response"""
        try:
            if '{' in response and '}' in response:
                start = response.find('{')
                end = response.rfind('}') + 1
                json_str = response[start:end]
                return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            pass
        
        return {
            "workflow_steps": [
                {
                    "step": 1,
                    "name": "Reconnaissance",
                    "tools": ["nmap", "subfinder"],
                    "description": "Gather information about target",
                    "expected_outcome": "Target enumeration complete"
                }
            ],
            "estimated_duration": "30 minutes",
            "success_criteria": ["Target fully enumerated", "Vulnerabilities identified"]
        }
    
    def _generate_target_analysis_response(self) -> str:
        """Generate simulated target analysis response"""
        return json.dumps({
            "target_url": "https://example.com",
            "scope": "*.example.com",
            "attack_surface": ["web", "api", "infrastructure", "subdomains"],
            "potential_vulnerabilities": ["xss", "sqli", "rce", "ssrf", "xxe"],
            "recommended_tools": ["nmap", "nuclei", "sqlmap", "ffuf", "subfinder"],
            "risk_assessment": {
                "overall_risk": "medium",
                "factors": ["public target", "complex scope", "multiple subdomains"]
            },
            "complexity_score": 7.5,
            "insights": [
                "Target is a large web application with multiple subdomains",
                "API endpoints present potential attack vectors",
                "Infrastructure components may have misconfigurations"
            ],
            "recommendations": [
                "Start with subdomain enumeration",
                "Focus on API security testing",
                "Check for common web vulnerabilities"
            ]
        }, indent=2)
    
    def _generate_result_analysis_response(self) -> str:
        """Generate simulated result analysis response"""
        return json.dumps({
            "confidence": 0.85,
            "insights": [
                "Reconnaissance phase completed successfully",
                "Multiple subdomains discovered",
                "Several potential vulnerabilities identified"
            ],
            "recommendations": [
                "Investigate XSS findings further",
                "Test SQL injection vectors",
                "Generate comprehensive report"
            ],
            "risk_level": "medium",
            "key_findings": [
                "3 potential XSS vulnerabilities",
                "1 SQL injection vector",
                "2 subdomains with security misconfigurations"
            ]
        }, indent=2)
    
    def _generate_workflow_planning_response(self) -> str:
        """Generate simulated workflow planning response"""
        return json.dumps({
            "workflow_steps": [
                {
                    "step": 1,
                    "name": "Subdomain Enumeration",
                    "tools": ["subfinder", "amass"],
                    "description": "Discover all subdomains of the target",
                    "expected_outcome": "Complete subdomain list"
                },
                {
                    "step": 2,
                    "name": "Port Scanning",
                    "tools": ["nmap", "masscan"],
                    "description": "Scan discovered hosts for open ports",
                    "expected_outcome": "Port mapping of all hosts"
                },
                {
                    "step": 3,
                    "name": "Vulnerability Scanning",
                    "tools": ["nuclei", "nikto"],
                    "description": "Scan for common vulnerabilities",
                    "expected_outcome": "Vulnerability report"
                }
            ],
            "estimated_duration": "45 minutes",
            "success_criteria": [
                "All subdomains enumerated",
                "All hosts scanned",
                "Vulnerabilities identified and documented"
            ]
        }, indent=2)
    
    def _generate_chat_response(self, prompt: str) -> str:
        """Generate chat response"""
        return f"I'm your AI assistant for the Kali Bug Hunter system. I can help you with bug hunting strategies, tool usage, and analyzing results. How can I assist you today?"

if __name__ == "__main__":
    # Test the AI agent
    async def test_ai_agent():
        agent = AIAgent()
        
        # Test target analysis
        print("Testing target analysis...")
        analysis = await agent.analyze_target("https://example.com", "*.example.com")
        print(f"Analysis: {analysis}")
        
        # Test chat
        print("\nTesting chat...")
        response = await agent.chat("What tools should I use for web application testing?")
        print(f"Chat response: {response}")
    
    asyncio.run(test_ai_agent()) 