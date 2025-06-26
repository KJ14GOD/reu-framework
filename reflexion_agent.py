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
        
        prompt = f"""You are a senior security expert conducting an independent code review and then critically evaluating another analyst's findings. You must be OBJECTIVE and BASE YOUR ASSESSMENT ONLY ON THE ACTUAL CODE PROVIDED.

FUNCTION ANALYZED: {function_name}

FUNCTION CODE:
```
{function_code}
```

REACT AGENT'S ANALYSIS TO REVIEW:
{analysis_text}

**CRITICAL INSTRUCTIONS:**
- You must first analyze the code INDEPENDENTLY without being influenced by the ReAct analysis
- Then objectively compare your findings with the ReAct agent's analysis
- Be PRECISE about what constitutes a vulnerability vs. what is secure code
- Pay SPECIAL ATTENTION to parsing functions - they often contain subtle but critical vulnerabilities
- Look carefully at string manipulation, delimiter handling, and format parsing
- Don't declare something vulnerable just because it "could theoretically be problematic"
- Don't declare something secure just because obvious flaws aren't immediately visible

**PART 1: YOUR INDEPENDENT SECURITY ANALYSIS**

Analyze the function code above for actual security vulnerabilities. Look for:

**Input Validation Issues:**
- Missing validation of dangerous characters (backslashes, null bytes, etc.)
- Improper parsing that could be bypassed
- Injection attack opportunities

**Parsing & Format Vulnerabilities:**
- Incorrect string parsing (memchr vs strrchr for finding delimiters)
- Wrong delimiter handling in structured data (URLs, addresses, ports)
- Format string vulnerabilities or incorrect format parsing
- Protocol parsing errors that can be exploited
- Example: Using memchr() to find first colon instead of strrchr() for last colon in "host:port" parsing
- Example: Allowing injection through malformed input like "host:fake:real" being parsed incorrectly

**Logic/Business Vulnerabilities:**
- Authentication/authorization bypass opportunities  
- Validation bypass methods
- Incorrect state handling

**Resource Exhaustion:**
- Algorithmic complexity attacks (e.g., O(n²) behavior with many special characters)
- Stack exhaustion from unbounded recursion
- Memory exhaustion possibilities

**Memory Safety:**
- Buffer overflows/underflows
- Use-after-free/double-free
- Null pointer dereferences

**Other Security Issues:**
- Race conditions
- Integer overflows
- Protocol/format parsing errors

**PART 2: CRITICAL EVALUATION OF REACT ANALYSIS**

Now compare the ReAct agent's conclusion and reasoning with your independent analysis:

1. **Classification Accuracy:** Did the ReAct agent correctly classify this as @@vulnerable@@ or @@not vulnerable@@?
2. **Reasoning Quality:** Is the ReAct agent's technical reasoning sound and supported by the code?
3. **Completeness:** Did the ReAct agent identify the actual vulnerabilities (if any) or miss important issues?
4. **False Positives/Negatives:** Did the ReAct agent identify non-existent vulnerabilities or miss real ones?

**PROVIDE YOUR ASSESSMENT:**

**REFLEXION ASSESSMENT**: [CORRECT/INCORRECT/PARTIALLY_CORRECT]

**RATIONALE FOR ASSESSMENT**:
[Based on your independent analysis, explain whether the ReAct agent was right or wrong. Be specific about:
- What your independent analysis concluded about the vulnerability status
- Whether the ReAct agent's classification matches your findings
- Any vulnerabilities the ReAct agent missed or incorrectly identified
- Whether the ReAct agent's reasoning was technically sound]

**YOUR INDEPENDENT CONCLUSION**:
Based solely on the code provided, this function should be classified as: [@@vulnerable@@ or @@not vulnerable@@]
Because: [Your reasoning based on the code]

**CONFIDENCE IN YOUR ASSESSMENT**: [HIGH/MEDIUM/LOW]

Remember: Base your judgment on concrete evidence in the code, not theoretical possibilities or assumptions about external context.
"""
        
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
        """Extract the CORRECT/INCORRECT/PARTIALLY_CORRECT assessment from reflexion output"""
        if "REFLEXION ASSESSMENT" in reflexion_text:
            lines = reflexion_text.split('\n')
            for line in lines:
                if "REFLEXION ASSESSMENT" in line:
                    if "CORRECT" in line:
                        return "CORRECT"
                    elif "INCORRECT" in line:
                        return "INCORRECT"
                    elif "PARTIALLY_CORRECT" in line:
                        return "PARTIALLY_CORRECT"
        return "UNKNOWN"

    def _extract_confidence(self, reflexion_text):
        """Extract the confidence level from reflexion output"""
        if "CONFIDENCE IN YOUR ASSESSMENT" in reflexion_text:
            lines = reflexion_text.split('\n')
            for line in lines:
                if "CONFIDENCE IN YOUR ASSESSMENT" in line:
                    if "HIGH" in line:
                        return "HIGH"
                    elif "MEDIUM" in line:
                        return "MEDIUM"
                    elif "LOW" in line:
                        return "LOW"
        return "UNKNOWN"