from langchain_openai import ChatOpenAI
from langchain.agents import initialize_agent, AgentType

import os

# Set your OpenAI and LangSmith keys here
os.environ["OPENAI_API_KEY"] = "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"
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_API_KEY"] = "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"

class ReActAgent:
    def __init__(self, model_name="gpt-4o"):
        self.llm = ChatOpenAI(model=model_name, temperature=0)
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

**🎯 MISSION: Detect BOTH specific CVE patterns AND general vulnerability patterns**

**STEP 1: GET THE FUNCTION CODE**
Use get_function_body tool to examine the actual source code.

**STEP 2: COMPREHENSIVE VULNERABILITY DETECTION**

**A. SPECIFIC CVE PATTERNS (High Priority - Score 8-10/10)**

**CVE-2019-3877 - URL Validation Missing Backslash Check:**
```c
// ✅ VULNERABLE: URL loop WITHOUT backslash check
for (i = url; *i; i++) {{
    if (*i >= 0 && *i < ' ') return ERROR;
    // ❌ MISSING: if (*i == '\\\\') return ERROR;
}}
```

**CVE-2018-20843 - XML Colon Processing Without Limits:**
```c
// ✅ VULNERABLE: Colon processing WITHOUT break
for (name = elementType->name; *name; name++) {{
    if (*name == XML_T(ASCII_COLON)) {{
        // processes colon without break
    }}
}}
```

**CVE-2018-16452 - Recursion Without Depth Control:**
```c
// ✅ VULNERABLE: Warns but continues recursing
if (depth == 10)
    print("warning");  // ❌ WARNS BUT DOESN'T STOP
recursive_call();  // ❌ STILL EXECUTES
```

**B. GENERAL VULNERABILITY PATTERNS (Medium Priority - Score 5-8/10)**

**Buffer Overflow Patterns:**
- `strcpy()`, `strcat()`, `sprintf()` without bounds checking
- Array access without bounds validation
- Memory allocation without size validation

**Input Validation Issues:**
- Missing null pointer checks
- No bounds checking on user input
- Unchecked array/buffer indices
- Missing parameter validation

**Memory Management Issues:**
- Use after free patterns
- Double free vulnerabilities
- Memory leaks in error paths
- Uninitialized memory access

**Integer Overflow/Underflow:**
- Arithmetic operations without overflow checks
- Size calculations that can wrap
- Signed/unsigned integer confusion

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

1. **Look for SPECIFIC CVE patterns first** (score 8-10/10 if found)
2. **Scan for GENERAL vulnerability patterns** (score 5-8/10 if found)
3. **Check for missing security controls**
4. **Evaluate input validation and bounds checking**
5. **Assess memory safety and error handling**

**VULNERABILITY SCORING GUIDE:**
- **9-10/10:** Exact CVE pattern match with clear exploit
- **7-8/10:** Clear vulnerability pattern with exploitation potential
- **5-6/10:** Security weakness or missing controls
- **3-4/10:** Minor security concerns
- **1-2/10:** Very minor issues, mostly secure
- **0/10:** No vulnerabilities, proper security controls

**CRITICAL: Don't be overly conservative! If you see vulnerability patterns, flag them!**

**REQUIRED OUTPUT:**
**VULNERABILITY SCORE: X/10**
**DECISION: @@vulnerable@@ or @@not vulnerable@@**
**ANALYSIS: [Specific vulnerability pattern found OR security assessment]**

**Examples:**
- "Buffer overflow: `strcpy(dest, src)` without bounds checking - Score 7/10 VULNERABLE"
- "Missing null check on parameter `ptr` before dereference - Score 6/10 VULNERABLE"
- "Proper bounds checking with `strncpy` and null termination - Score 0/10 NOT VULNERABLE"
- "Integer overflow possible in `size * count` calculation - Score 6/10 VULNERABLE"

**REMEMBER: Be PRECISE. Don't guess. Only flag as vulnerable with concrete evidence.**"""
        
        response = self.agent.invoke(prompt)
        return response

     