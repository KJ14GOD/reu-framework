from langchain_openai import ChatOpenAI
from langchain.agents import initialize_agent, AgentType
import os

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Debug: Print the API key being used
print(f"DEBUG: Using API key: {os.environ.get('OPENAI_API_KEY', 'NOT SET')[:20]}...")

# Set LangSmith keys
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_API_KEY"] = "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"

# DeepSeek API configuration
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"

class ReActAgent:
    def __init__(self, model_name="gpt-4o", use_deepseek=False):
        """
        Initialize ReAct Agent with either OpenAI or DeepSeek model
        
        Args:
            model_name: Model name (default: "gpt-4o")
            use_deepseek: If True, use DeepSeek API instead of OpenAI
        """
        self.use_deepseek = use_deepseek
        
        if use_deepseek:
            if not DEEPSEEK_API_KEY:
                raise ValueError("DEEPSEEK_API_KEY environment variable is required for DeepSeek models")
            
            # Use DeepSeek API
            self.llm = ChatOpenAI(
                model=model_name,
                temperature=0,
                openai_api_key=DEEPSEEK_API_KEY,
                openai_api_base=DEEPSEEK_BASE_URL
            )
            print(f"Using DeepSeek model: {model_name}")
        else:
            # Use OpenAI API
            self.llm = ChatOpenAI(model=model_name, temperature=0)
            print(f"Using OpenAI model: {model_name}")
        
        self.tools = []
        self.agent = None

    def set_tools(self, tools_list):
        """Set the tools for this agent and reinitialize the agent."""
        self.tools = tools_list
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent_type=AgentType.CHAT_ZERO_SHOT_REACT_DESCRIPTION,
            verbose=True,
            handle_parsing_errors=True,
            max_iterations=25,
            max_execution_time=120
        )

    def predict(self, function_name):
        if not self.agent:
            raise ValueError("Tools must be set before calling predict. Use set_tools() first.")
            
        prompt = f"""You are an EXPERT vulnerability hunter analyzing function '{function_name}' for security flaws.

**🎯 MISSION: Detect security vulnerabilities through comprehensive code analysis**

**STEP 1: GET THE FUNCTION CODE**
Use get_function_body tool to examine the actual source code.

**STEP 2: COMPREHENSIVE VULNERABILITY DETECTION**

**A. HIGH PRIORITY VULNERABILITY PATTERNS (Score 8-10/10)**

**Input Validation & Sanitization Issues:**
- Missing validation of user input parameters
- Insufficient bounds checking on arrays/buffers
- Missing null pointer checks before dereference
- Inadequate character filtering (missing backslash, control character checks)
- URL validation bypasses and redirect vulnerabilities

**Memory Safety Issues:**
- Buffer overflow vulnerabilities (strcpy, strcat, sprintf without bounds)
- Use-after-free patterns
- Double free vulnerabilities
- Memory leaks in error paths
- Uninitialized memory access

**Control Flow Vulnerabilities:**
- Recursion without depth limits
- Infinite loops or excessive iteration
- Missing break statements in switch cases
- Improper error handling that continues execution

**B. MEDIUM PRIORITY VULNERABILITY PATTERNS (Score 5-8/10)**

**Integer Issues:**
- Integer overflow/underflow in arithmetic operations
- Signed/unsigned integer confusion
- Size calculations that can wrap
- Array indexing without bounds validation

**Format String Vulnerabilities:**
- User input directly in format strings
- `printf(user_input)` instead of `printf("%s", user_input)`

**Race Conditions:**
- Unsynchronized access to shared resources
- Time-of-check vs time-of-use issues

**Injection Vulnerabilities:**
- SQL injection patterns
- Command injection risks
- Path traversal vulnerabilities

**STEP 3: COMPREHENSIVE ANALYSIS APPROACH**

1. **Examine input validation and sanitization** (highest priority)
2. **Check memory safety and bounds checking**
3. **Analyze control flow and error handling**
4. **Look for injection and format string vulnerabilities**
5. **Assess overall security posture**

**VULNERABILITY SCORING GUIDE:**
- **9-10/10:** Clear vulnerability with exploitation potential
- **7-8/10:** Security weakness with potential impact
- **5-6/10:** Missing security controls or weak validation
- **3-4/10:** Minor security concerns
- **1-2/10:** Very minor issues, mostly secure
- **0/10:** No vulnerabilities, proper security controls

**CRITICAL: Be thorough but precise. Flag vulnerabilities with concrete evidence.**

**REQUIRED OUTPUT:**
**VULNERABILITY SCORE: X/10**
**DECISION: @@vulnerable@@ or @@not vulnerable@@**
**ANALYSIS: [Specific vulnerability pattern found OR security assessment]**

**Examples:**
- "Missing backslash check in URL validation - Score 8/10 VULNERABLE"
- "Buffer overflow: `strcpy(dest, src)` without bounds checking - Score 7/10 VULNERABLE"
- "Missing null check on parameter `ptr` before dereference - Score 6/10 VULNERABLE"
- "Proper bounds checking with `strncpy` and null termination - Score 0/10 NOT VULNERABLE"
- "Integer overflow possible in `size * count` calculation - Score 6/10 VULNERABLE"

**REMEMBER: Be PRECISE. Don't guess. Only flag as vulnerable with concrete evidence.**"""
        
        response = self.agent.invoke(prompt)
        return response

     