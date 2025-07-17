import os
from langchain_openai import ChatOpenAI

os.environ["OPENAI_API_KEY"] = "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"

class ReflexionAgent:
    def __init__(self, model_name="gpt-4o"):
        self.llm = ChatOpenAI(model=model_name, temperature=0)
        self.tools = [] # Store tools, but ReflexionAgent doesn't use initialize_agent directly

    def set_tools(self, tools_list):
        self.tools = tools_list

    def reflect_on_analysis(self, function_name, function_code, react_output, expected_vulnerability_status=None):
        """
        Analyzes the ReAct agent's vulnerability assessment and provides critical reflection.
        This version of the agent now receives the function's code to perform a more grounded analysis.
        
        Args:
            function_name: Name of the function being analyzed
            function_code: The actual source code of the function
            react_output: The ReAct agent's analysis output
            expected_vulnerability_status: Optional hint about whether this is expected to be vulnerable (for debugging)
        """
        # Extract the actual output text from the ReAct response
        if isinstance(react_output, dict) and "output" in react_output:
            analysis_text = react_output["output"]
        else:
            analysis_text = str(react_output)

        print(f"\n[REFLEXION AGENT ANALYSIS]")
        print(f"Analyzing ReAct agent's assessment of function: {function_name}")
        print(f"{'='*60}")
        
        prompt = f"""You are a COMPREHENSIVE security verification expert reviewing function '{function_name}'.

**🎯 MISSION: Verify ReAct's analysis for BOTH specific CVEs AND general vulnerabilities**

**ReAct's Analysis:**
{analysis_text}

**Function Code to Verify:**
```c
{function_code}
```

**YOUR TASK: COMPREHENSIVE SECURITY VERIFICATION**

**STEP 1: EXAMINE THE CODE INDEPENDENTLY**
Ignore ReAct's opinion - analyze the code with fresh expert eyes.

**STEP 2: VERIFY SPECIFIC CVE PATTERNS**

**CVE-2019-3877 - URL Validation Missing Backslash Check:**
✅ **IS VULNERABLE** = URL loop WITHOUT `if (*i == '\\\\') return ERROR;`
❌ **NOT VULNERABLE** = URL loop WITH `if (*i == '\\\\') return ERROR;`

**CVE-2018-20843 - XML Colon Processing Without Limits:**
✅ **IS VULNERABLE** = Colon processing WITHOUT `break;` after first match
❌ **NOT VULNERABLE** = Colon processing WITH `break;` after first match

**CVE-2018-16452 - Recursion Without Depth Control:**
✅ **IS VULNERABLE** = Warning printed but recursion continues
❌ **NOT VULNERABLE** = Returns/stops when depth limit reached

**STEP 3: VERIFY GENERAL VULNERABILITY PATTERNS**

**Buffer Overflow Issues:**
- ✅ VULNERABLE: `strcpy()`, `strcat()`, `sprintf()` without bounds
- ✅ VULNERABLE: Array access without bounds validation
- ✅ VULNERABLE: Memory allocation without size checks

**Input Validation Issues:**
- ✅ VULNERABLE: Missing null pointer checks before use
- ✅ VULNERABLE: No bounds checking on user input
- ✅ VULNERABLE: Unchecked array/buffer indices
- ✅ VULNERABLE: Missing parameter validation

**Memory Management Issues:**
- ✅ VULNERABLE: Use after free patterns
- ✅ VULNERABLE: Double free vulnerabilities
- ✅ VULNERABLE: Uninitialized memory access

**Integer Issues:**
- ✅ VULNERABLE: Arithmetic without overflow checks
- ✅ VULNERABLE: Size calculations that can wrap
- ✅ VULNERABLE: Signed/unsigned confusion

**Other Common Patterns:**
- ✅ VULNERABLE: Format string issues
- ✅ VULNERABLE: Race conditions
- ✅ VULNERABLE: Injection vulnerabilities

**STEP 4: CHALLENGE REACT'S ASSESSMENT**

**If ReAct said NOT_VULNERABLE but you found issues:**
- Quote specific vulnerable code patterns
- Explain the security risk
- Score 5-9/10 VULNERABLE

**If ReAct said VULNERABLE but code looks secure:**
- Point to specific security controls present
- Explain why it's actually safe
- Score 0-3/10 NOT VULNERABLE

**If ReAct missed severity level:**
- Adjust scoring based on actual risk
- Provide better severity assessment

**STEP 5: COMPREHENSIVE SCORING**

- **9-10/10:** Exact CVE match or severe vulnerability
- **7-8/10:** Clear vulnerability with exploitation potential
- **5-6/10:** Security weakness or missing controls
- **3-4/10:** Minor security concerns
- **1-2/10:** Very minor issues, mostly secure
- **0/10:** No vulnerabilities, proper controls present

**REQUIRED OUTPUT:**

**VULNERABILITY SCORE: X/10**
  - Exploitability: X/4 (based on actual code analysis)
  - Impact: X/4 (based on realistic damage)
  - Complexity: X/2 (based on actual difficulty)

**DECISION: @@vulnerable@@ or @@not vulnerable@@**

**CRITICAL ANALYSIS:**
- **Code evidence:** [Quote specific vulnerable/secure code patterns]
- **Vulnerability pattern:** [Specific vulnerability type found or security controls present]
- **ReAct assessment:** ✅ CORRECT or ❌ INCORRECT - [specific reason]

**Examples:**
- "Code uses `strcpy(dest, src)` without bounds checking - buffer overflow risk, ReAct MISSED"
- "Code has `if (!ptr) return ERROR;` before use - null check present, ReAct CORRECT"
- "Code missing input validation on array index - out of bounds risk, ReAct INCORRECT"
- "Function properly validates all inputs and uses safe string functions - ReAct CORRECT"

**CRITICAL: Don't be overly conservative! If you see real vulnerability patterns, challenge ReAct!**"""
        
        print("Sending analysis to Reflexion agent...")
        print(f"{'='*60}")
        
        response = self.llm.invoke(prompt)
        reflexion_text = response.content.strip()
        
        print("REFLEXION AGENT OUTPUT:")
        print(f"{'='*60}")
        print(reflexion_text)
        print(f"{'='*60}")
        
        return {
            "function_name": function_name,
            "original_analysis": analysis_text,
            "reflexion_output": reflexion_text,
            "assessment": self._extract_assessment(reflexion_text),
            "confidence": self._extract_confidence(reflexion_text)
        }

    def _extract_assessment(self, reflexion_text):
        """Extract the CORRECT/INCORRECT assessment from reflexion output"""
        if "CORRECT" in reflexion_text.upper():
            return "CORRECT"
        elif "INCORRECT" in reflexion_text.upper():
            return "INCORRECT" 
        elif "PARTIALLY_CORRECT" in reflexion_text.upper():
            return "PARTIALLY_CORRECT"
        return "UNKNOWN"

    def _extract_confidence(self, reflexion_text):
        """Extract the confidence level from reflexion output"""
        if "HIGH" in reflexion_text.upper():
            return "HIGH"
        elif "MEDIUM" in reflexion_text.upper():
            return "MEDIUM"
        elif "LOW" in reflexion_text.upper():
            return "LOW"
        return "UNKNOWN"