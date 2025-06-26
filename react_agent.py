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
            handle_parsing_errors=True
        )

    def predict(self, function_name):
        if not self.agent:
            raise ValueError("Tools must be set before calling predict. Use set_tools() first.")
            
        prompt = f"""You are an expert security researcher analyzing the function '{function_name}' for vulnerabilities. You must be BALANCED and ACCURATE - not everything is vulnerable, and not everything is safe.

You must follow this exact plan:
1. **Get Function Body:** Use the `get_function_body` tool to retrieve the source code of the function '{function_name}'.
2. **Get Callers:** Use the `get_callers` tool to find out which other functions call '{function_name}'.
3. **Get Callees:** Use the `get_callees` tool to find out which functions are called from within '{function_name}'.
4. **Balanced Security Analysis:** Perform a thorough but realistic vulnerability analysis.

**CRITICAL: BE PRECISE - Only mark as vulnerable if there's CONCRETE evidence of exploitable flaws:**

**Look for ACTUAL vulnerabilities:**
- **Input Validation Issues:** Missing validation that can be exploited (not just theoretical concerns)
- **Parsing Vulnerabilities:** Incorrect parsing logic (using memchr vs strrchr, wrong delimiters, etc.)
- **Logic Flaws:** Authentication/authorization bypasses with clear attack paths
- **Resource Exhaustion:** Algorithmic complexity attacks with concrete DoS potential
- **Memory Safety:** Buffer overflows, use-after-free with clear exploitation paths
- **Injection Attacks:** SQL, command, or code injection with direct attack vectors
- **Protocol/Format Issues:** Incorrect handling of structured data (URLs, addresses, formats)

**But ALSO look for PROPER security measures:**
- **Good Input Validation:** Proper bounds checking, sanitization, validation
- **Safe Memory Management:** Proper allocation, bounds checking, safe string handling
- **Defensive Programming:** Error handling, null checks, proper state management
- **Secure Coding Practices:** Use of safe functions, proper validation patterns

**IMPORTANT ANALYSIS GUIDELINES:**
- **Only mark as vulnerable if you find CONCRETE, EXPLOITABLE flaws**
- **Pay special attention to parsing functions - they often have subtle vulnerabilities**
- **Check string parsing logic carefully: memchr vs strrchr, first vs last delimiter, etc.**
- **Look for functions that parse structured input (URLs, addresses, formats) - common vulnerability area**
- **If the function has proper validation and security checks, mark it as NOT vulnerable**
- **Don't assume vulnerabilities exist just because the code "could theoretically be problematic"**
- **Look for actual security controls and defensive measures**
- **Consider: Can an attacker actually exploit this function in a realistic scenario?**

**DECISION CRITERIA:**
- **@@vulnerable@@**: You found specific, exploitable security flaws with clear attack vectors
- **@@not vulnerable@@**: The function has proper security controls, validation, or no exploitable flaws

**Final Answer:** Your answer MUST start with '@@vulnerable@@' or '@@not vulnerable@@', followed by a detailed explanation including:
1. What the function does and its security context
2. What security measures (if any) are present
3. What vulnerabilities you found (if any) with specific exploitation scenarios
4. Why you concluded vulnerable or not vulnerable

Be precise and evidence-based - avoid false positives!
"""
        response = self.agent.invoke(prompt)
        return response

     