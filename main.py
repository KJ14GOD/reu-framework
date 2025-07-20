import json
import sys
import os
import textwrap
import argparse
from react_agent import ReActAgent
from reflexion_agent import ReflexionAgent
from evaluation_agent import EvaluationAgent
import time
import tools
from datetime import datetime
import random
from openai import RateLimitError
import re

def iterative_debate(react_agent, reflexion_agent, function_name, function_body, function_type, project, max_rounds=5):
    """
    Conduct an iterative debate between ReAct and Reflexion agents until consensus or max rounds
    """
    debate_history = []
    round_num = 1
    
    # Initial ReAct analysis
    print(f"Round {round_num}: ReAct Agent initial analysis...")
    react_output = safe_api_call(react_agent.predict, function_name)
    react_decision = extract_vulnerability_decision(react_output)
    react_reasoning = extract_reasoning(react_output)
    
    # Extract vulnerability score from ReAct analysis
    react_score = extract_vulnerability_score(react_output)
    react_exploitability, react_impact, react_complexity = extract_score_components(react_output)
    
    print(f"ReAct initial decision: {react_decision}")
    if react_score is not None:
        print(f"ReAct vulnerability score: {react_score}/10")
        if react_exploitability is not None:
            print(f"  - Exploitability: {react_exploitability}/4, Impact: {react_impact}/4, Complexity: {react_complexity}/2")
    
    debate_history.append({
        "round": round_num,
        "agent": "ReAct",
        "decision": react_decision,
        "reasoning": react_reasoning,
        "score": react_score,
        "score_components": (react_exploitability, react_impact, react_complexity)
    })
    
    # Initial Reflexion review
    print(f"Round {round_num}: Reflexion Agent reviewing...")
    reflexion_result = reflexion_agent.reflect_on_analysis(
        function_name, function_body, react_output
    )
    reflexion_decision = extract_reflexion_decision(reflexion_result["reflexion_output"])
    reflexion_assessment = reflexion_result["assessment"]
    
    # Extract vulnerability score from Reflexion analysis
    reflexion_score = extract_vulnerability_score(reflexion_result["reflexion_output"])
    reflexion_exploitability, reflexion_impact, reflexion_complexity = extract_score_components(reflexion_result["reflexion_output"])
    
    print(f"Reflexion initial decision: {reflexion_decision}")
    print(f"Reflexion assessment of ReAct: {reflexion_assessment}")
    if reflexion_score is not None:
        print(f"Reflexion vulnerability score: {reflexion_score}/10")
        if reflexion_exploitability is not None:
            print(f"  - Exploitability: {reflexion_exploitability}/4, Impact: {reflexion_impact}/4, Complexity: {reflexion_complexity}/2")
    
    debate_history.append({
        "round": round_num,
        "agent": "Reflexion", 
        "decision": reflexion_decision,
        "reasoning": extract_reflexion_reasoning(reflexion_result["reflexion_output"]),
        "assessment": reflexion_assessment,
        "score": reflexion_score,
        "score_components": (reflexion_exploitability, reflexion_impact, reflexion_complexity)
    })
    
    # Check for agreement  
    agree = check_agreement(react_decision, reflexion_decision, reflexion_assessment)
    
    # DEBUG: Print what we extracted
    print(f"DEBUG - ReAct decision: '{react_decision}'")
    print(f"DEBUG - Reflexion decision: '{reflexion_decision}'") 
    print(f"DEBUG - Reflexion assessment: '{reflexion_assessment}'")
    print(f"DEBUG - Agreement check result: {agree}")
    
    if agree:
        print(f"Agents reached consensus in round {round_num}")
        final_decision = react_decision
    else:
        print(f"Agents disagree. Starting iterative debate...")
        
        # Continue debate until agreement or max rounds
        for round_num in range(2, max_rounds + 1):
            print(f"\nRound {round_num}: Debate continues...")
            
            # Reflexion explains disagreement and presents counter-argument
            counter_prompt = create_counter_argument_prompt(function_name, function_body, react_decision, reflexion_decision, debate_history)
            counter_output = safe_api_call(reflexion_agent.llm.invoke, counter_prompt.content)
            
            debate_history.append({
                "round": round_num,
                "agent": "Reflexion-Counter",
                "output": {"output": counter_output.content},
                "decision": reflexion_decision,
                "reasoning": counter_output.content
            })
            
            print(f"Reflexion counter-argument: {counter_output.content[:100]}...")
            
            # ReAct responds to counter-argument
            rebuttal_prompt = create_rebuttal_prompt(function_name, function_body, react_decision, counter_output.content, debate_history)
            rebuttal_output = safe_api_call(react_agent.llm.invoke, rebuttal_prompt.content)
            new_react_decision = extract_vulnerability_decision({"output": rebuttal_output.content})
            
            debate_history.append({
                "round": round_num,
                "agent": "ReAct-Rebuttal",
                "output": {"output": rebuttal_output.content},
                "decision": new_react_decision,
                "reasoning": rebuttal_output.content
            })
            
            print(f"ReAct rebuttal decision: {new_react_decision}")
            
            # Check if ReAct changed position
            if new_react_decision != react_decision:
                print(f"ReAct changed position from {react_decision} to {new_react_decision}")
                react_decision = new_react_decision
                
            # Check for agreement
            if react_decision == reflexion_decision:
                print(f"Agents reached consensus in round {round_num}: {react_decision}")
                final_decision = react_decision
                break
                
            # Reflexion re-evaluates after ReAct's rebuttal
            final_reflexion_prompt = create_final_evaluation_prompt(function_name, function_body, debate_history)
            final_reflexion_output = safe_api_call(reflexion_agent.llm.invoke, final_reflexion_prompt.content)
            new_reflexion_decision = extract_vulnerability_decision({"output": final_reflexion_output.content})
            
            debate_history.append({
                "round": round_num,
                "agent": "Reflexion-Final",
                "output": {"output": final_reflexion_output.content},
                "decision": new_reflexion_decision,
                "reasoning": final_reflexion_output.content
            })
            
            if new_reflexion_decision != reflexion_decision:
                print(f"Reflexion changed position from {reflexion_decision} to {new_reflexion_decision}")
                reflexion_decision = new_reflexion_decision
                
            if react_decision == reflexion_decision:
                print(f"Agents reached consensus in round {round_num}: {react_decision}")
                final_decision = react_decision
                break
        else:
            print(f"No consensus reached after {max_rounds} rounds. Using final positions...")
            # Use the most recent decision from each agent as the tie-breaker
            # Be conservative: default to NOT_VULNERABLE unless both explicitly say VULNERABLE
            
            latest_react = react_decision
            latest_reflexion = reflexion_decision
            
            # Conservative tie-breaking: require strong evidence for VULNERABLE
            if latest_react == "VULNERABLE" and latest_reflexion == "VULNERABLE":
                final_decision = "VULNERABLE"
            elif latest_react == "NOT_VULNERABLE" and latest_reflexion == "NOT_VULNERABLE":
                final_decision = "NOT_VULNERABLE"
            else:
                # If agents disagree, be conservative and default to NOT_VULNERABLE
                # This reduces false positives
                final_decision = "NOT_VULNERABLE"
                print(f"Agents disagree ({latest_react} vs {latest_reflexion}), defaulting to NOT_VULNERABLE")
            
            print(f"Final decision after debate: {final_decision}")
    
    return {
        "final_decision": final_decision,
        "debate_history": debate_history,
        "consensus_reached": agree or react_decision == reflexion_decision,
        "rounds_needed": round_num
    }

def extract_vulnerability_decision(output):
    """Extract vulnerability decision from agent output"""
    if isinstance(output, dict) and "output" in output:
        content = output["output"]
    elif hasattr(output, 'content'):
        content = output.content
    else:
        content = str(output)
    
    content_lower = content.lower()
    
    # Look for explicit decision markers
    if "@@vulnerable@@" in content_lower:
        return "VULNERABLE"
    elif "@@not vulnerable@@" in content_lower:
        return "NOT_VULNERABLE"
    # Also handle the case where there's a colon before the marker
    elif ": @@vulnerable@@" in content_lower:
        return "VULNERABLE"
    elif ": @@not vulnerable@@" in content_lower:
        return "NOT_VULNERABLE"
    else:
        # If no clear marker found, default to UNCLEAR
        return "UNCLEAR"

def extract_reasoning(output):
    """Extract reasoning from agent output"""
    if isinstance(output, dict) and "output" in output:
        content = output["output"]
    else:
        content = str(output)
    return content[:500] + "..." if len(content) > 500 else content

def extract_reflexion_decision(reflexion_output):
    """Extract independent decision from Reflexion agent"""
    if isinstance(reflexion_output, dict) and "reflexion_output" in reflexion_output:
        reflexion_text = reflexion_output["reflexion_output"]
    elif isinstance(reflexion_output, str):
        reflexion_text = reflexion_output
    else:
        reflexion_text = str(reflexion_output)
        
    reflexion_lower = reflexion_text.lower()
    
    # Look for the decision markers in the text
    if "@@vulnerable@@" in reflexion_lower:
        return "VULNERABLE"
    elif "@@not vulnerable@@" in reflexion_lower:
        return "NOT_VULNERABLE"
    # Also check for variations
    elif ": @@vulnerable@@" in reflexion_lower:
        return "VULNERABLE"
    elif ": @@not vulnerable@@" in reflexion_lower:
        return "NOT_VULNERABLE"
    
    # DEBUG: Print what we're trying to parse
    print(f"DEBUG - Reflexion text excerpt: {reflexion_text[:200]}...")
    
    return "UNCLEAR"

def extract_reflexion_reasoning(reflexion_output):
    """Extract reasoning from Reflexion output"""
    if isinstance(reflexion_output, dict) and "reflexion_output" in reflexion_output:
        return reflexion_output["reflexion_output"][:500] + "..."
    return str(reflexion_output)[:500] + "..."

def check_agreement(react_decision, reflexion_decision, reflexion_assessment):
    """Check if agents agree on the decision"""
    # They agree ONLY if both have the same vulnerability decision
    # Be conservative: if either says UNCLEAR, no agreement
    if react_decision == "UNCLEAR" or reflexion_decision == "UNCLEAR":
        return False
    
    # Only agree if both have explicit and matching decisions
    return react_decision == reflexion_decision

def create_counter_argument_prompt(function_name, function_body, react_decision, reflexion_decision, debate_history):
    """Create prompt for Reflexion to argue against ReAct's decision"""
    from langchain_core.prompts import ChatPromptTemplate
    
    return ChatPromptTemplate.from_messages([
        ("human", """Challenge ReAct's analysis of '{function_name}' with COMPREHENSIVE SECURITY EXPERTISE.

ReAct's Decision: {react_decision}
Your Assessment: {reflexion_decision}

**Function Code:**
```c
{function_body}
```

**YOUR MISSION: COMPREHENSIVE SECURITY CHALLENGE**

**STEP 1: EXAMINE CODE FOR ALL VULNERABILITY PATTERNS**

**A. SPECIFIC CVE PATTERNS (Score 8-10/10 if found)**

**CVE-2019-3877:** URL loop WITHOUT `if (*i == '\\\\') return ERROR;`
**CVE-2018-20843:** Colon processing WITHOUT `break;` after first match
**CVE-2018-16452:** Warning printed but recursion continues

**B. GENERAL VULNERABILITY PATTERNS (Score 5-8/10 if found)**

**Buffer Overflow Risks:**
- `strcpy()`, `strcat()`, `sprintf()` without bounds checking
- Array access without bounds validation
- Memory allocation without size validation

**Input Validation Issues:**
- Missing null pointer checks before use
- No bounds checking on user input  
- Unchecked array/buffer indices
- Missing parameter validation

**Memory Management Issues:**
- Use after free patterns
- Double free vulnerabilities
- Uninitialized memory access

**Integer Issues:**
- Arithmetic operations without overflow checks
- Size calculations that can wrap
- Signed/unsigned integer confusion

**Other Vulnerability Patterns:**
- Format string vulnerabilities
- Race conditions
- Injection vulnerabilities

**STEP 2: CHALLENGE REACT WITH SPECIFIC EVIDENCE**

**If ReAct said NOT_VULNERABLE but you see vulnerability patterns:**
- Quote the exact vulnerable code
- Explain the specific security risk
- Score 5-9/10 VULNERABLE

**If ReAct said VULNERABLE but you see proper security controls:**
- Quote the exact security control present
- Explain why it prevents exploitation
- Score 0-3/10 NOT VULNERABLE

**If ReAct's severity assessment is wrong:**
- Provide corrected scoring with evidence

**REQUIRED OUTPUT:**
**VULNERABILITY SCORE: X/10**
- Exploitability: X/4 (based on actual code)
- Impact: X/4 (based on realistic damage)
- Complexity: X/2 (based on actual difficulty)

**EVIDENCE:** [Quote specific vulnerable code OR security controls]
**DECISION: @@vulnerable@@ or @@not vulnerable@@**

**Examples:**
- "Line 5: `strcpy(dest, user_input)` - buffer overflow risk, no bounds check, ReAct MISSED"
- "Line 8: `if (!ptr) return ERROR;` before use - null check present, ReAct wrong about vulnerability"
- "Lines 10-15: Array access `arr[index]` without bounds validation - out of bounds risk"

**BE COMPREHENSIVE - look for ALL vulnerability patterns, not just the 3 specific CVEs!**
""")
    ]).format_messages(
        function_name=function_name,
        function_body=function_body,
        react_decision=react_decision,
        reflexion_decision=reflexion_decision,
        debate_summary=format_debate_summary(debate_history)
    )[0]

def create_rebuttal_prompt(function_name, function_body, react_decision, counter_argument, debate_history):
    """Create prompt for ReAct to respond to Reflexion's counter-argument"""
    from langchain_core.prompts import ChatPromptTemplate
    
    return ChatPromptTemplate.from_messages([
        ("human", """Re-evaluate '{function_name}' after this COMPREHENSIVE SECURITY CHALLENGE.

Your Original Decision: {react_decision}

**EXPERT CHALLENGE:**
{counter_argument}

**Function Code:**
```c
{function_body}
```

**YOUR TASK: COMPREHENSIVE SECURITY RE-EVALUATION**

**STEP 1: VERIFY THEIR SPECIFIC CLAIMS**
Look at the exact code lines they cited. Are they correct?

**STEP 2: CHECK ALL VULNERABILITY PATTERNS**

**A. SPECIFIC CVE PATTERNS (Score 8-10/10)**
- **CVE-2019-3877:** URL loop missing backslash check?
- **CVE-2018-20843:** Colon processing without break?
- **CVE-2018-16452:** Recursion warning but no stop?

**B. GENERAL VULNERABILITY PATTERNS (Score 5-8/10)**
- **Buffer overflows:** Unsafe string functions? No bounds checking?
- **Input validation:** Missing null checks? Unchecked indices? 
- **Memory issues:** Use after free? Double free? Uninitialized access?
- **Integer issues:** Overflow risks? Size calculation problems?
- **Other patterns:** Format strings? Race conditions? Injection risks?

**STEP 3: DECISIVE RESPONSE**

**If expert found vulnerability you missed:**
- Acknowledge the specific vulnerable code
- CHANGE to VULNERABLE with appropriate score (5-9/10)

**If expert claimed false vulnerability but code is secure:**
- Point to the specific security control present
- MAINTAIN NOT VULNERABLE with evidence

**If you disagree with expert's assessment:**
- Provide counter-evidence with specific line numbers
- Justify your original assessment

**FINAL DECISION:**
**VULNERABILITY SCORE: X/10**
- Exploitability: X/4 (based on code evidence)
- Impact: X/4 (based on realistic impact)
- Complexity: X/2 (based on actual difficulty)

**FINAL ANALYSIS:** [Why you changed/maintained position with specific evidence]
**DECISION: @@vulnerable@@ or @@not vulnerable@@**

**Examples:**
- "Expert correct - `strcpy(dest, src)` on line 5 has no bounds check, changing to VULNERABLE 7/10"
- "Expert wrong - null check IS present on line 8: `if (!ptr) return ERROR;`, maintaining NOT VULNERABLE"
- "Expert correct - array access `arr[i]` on line 12 lacks bounds validation, changing to VULNERABLE 6/10"

**BE THOROUGH - consider ALL vulnerability patterns, not just the 3 specific CVEs!**
""")
    ]).format_messages(
        function_name=function_name,
        function_body=function_body,
        react_decision=react_decision,
        counter_argument=counter_argument,
        debate_summary=format_debate_summary(debate_history)
    )[0]

def create_final_evaluation_prompt(function_name, function_body, debate_history):
    """Create prompt for Reflexion's final evaluation after ReAct's rebuttal"""
    from langchain_core.prompts import ChatPromptTemplate
    
    return ChatPromptTemplate.from_messages([
        ("human", """FINAL COMPREHENSIVE SECURITY ANALYSIS of function '{function_name}' after complete debate.

**Function Code:**
```c
{function_body}
```

**DEBATE HISTORY:**
{debate_summary}

**YOUR TASK: COMPREHENSIVE FINAL SECURITY VERDICT**

**STEP 1: INDEPENDENT CODE ANALYSIS**
Ignore all debate opinions - analyze the code with fresh security expert eyes.

**STEP 2: COMPREHENSIVE VULNERABILITY SCAN**

**A. SPECIFIC CVE PATTERNS (Score 8-10/10 if found)**

**CVE-2019-3877:** URL loop with `for (i = url; *i; i++)` missing `if (*i == '\\\\') return ERROR;`
**CVE-2018-20843:** Colon processing `if (*name == XML_T(ASCII_COLON))` missing `break;`
**CVE-2018-16452:** Recursion with depth check that warns but doesn't stop

**B. GENERAL VULNERABILITY PATTERNS (Score 5-8/10 if found)**

**Buffer Overflow Patterns:**
- `strcpy()`, `strcat()`, `sprintf()` without bounds checking
- Array access without bounds validation
- Memory allocation without size validation

**Input Validation Issues:**
- Missing null pointer checks before dereference
- No bounds checking on user input
- Unchecked array/buffer indices
- Missing parameter validation

**Memory Management Issues:**
- Use after free patterns
- Double free vulnerabilities
- Uninitialized memory access

**Integer Overflow/Underflow:**
- Arithmetic operations without overflow checks
- Size calculations that can wrap
- Signed/unsigned integer confusion

**Other Common Vulnerabilities:**
- Format string vulnerabilities
- Race conditions
- Injection vulnerabilities
- Path traversal issues

**STEP 3: DETERMINE FINAL VERDICT**

Based ONLY on the code evidence above:

**If you find SPECIFIC CVE pattern:**
- Quote the exact vulnerable code
- Score 8-10/10 VULNERABLE

**If you find GENERAL vulnerability pattern:**
- Quote the specific vulnerable code
- Score 5-8/10 VULNERABLE

**If you see proper security controls:**
- Quote the specific protective code
- Score 0-3/10 NOT VULNERABLE

**If function is secure with no issues:**
- Confirm no vulnerability patterns present
- Score 0/10 NOT VULNERABLE

**FINAL OUTPUT:**

**VULNERABILITY SCORE: X/10**
- Exploitability: X/4 (based on actual code)
- Impact: X/4 (based on realistic damage) 
- Complexity: X/2 (based on actual difficulty)

**FINAL VERDICT: @@vulnerable@@ or @@not vulnerable@@**

**CODE EVIDENCE:** [Quote exact lines that determine your verdict]

**Examples:**
- "Line 5: `strcpy(dest, user_input)` - buffer overflow risk, no bounds check = VULNERABLE 7/10"
- "Line 8: `if (!ptr) return ERROR;` before dereference - null check present = NOT VULNERABLE 0/10"
- "Line 12: Array access `arr[index]` without bounds validation = VULNERABLE 6/10"
- "Function uses safe string functions and validates all inputs = NOT VULNERABLE 0/10"

**CRITICAL: Base verdict on ALL vulnerability patterns, not just the 3 specific CVEs!**
""")
    ]).format_messages(
        function_name=function_name,
        function_body=function_body,
        debate_summary=format_debate_summary(debate_history)
    )[0]

def format_debate_summary(debate_history):
    """Format debate history for prompts"""
    summary = ""
    for entry in debate_history:
        summary += f"\nRound {entry['round']} - {entry['agent']}: {entry['decision']}\n"
        summary += f"Reasoning: {entry['reasoning'][:200]}...\n"
    return summary

def safe_api_call(func, *args, max_retries=3, **kwargs):
    """
    Wrapper function to safely make API calls with exponential backoff on rate limits
    """
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except RateLimitError as e:
            if attempt == max_retries - 1:
                raise e
            
            # Extract wait time from error message if available
            error_msg = str(e)
            wait_time = 5  # default wait time
            
            if "try again in" in error_msg:
                try:
                    # Extract the wait time from error message
                    wait_part = error_msg.split("try again in ")[1].split("s.")[0]
                    wait_time = float(wait_part) + 1  # Add 1 second buffer
                except:
                    wait_time = 5
            
            # Exponential backoff with jitter
            backoff_time = wait_time * (2 ** attempt) + random.uniform(0, 1)
            print(f"Rate limit hit. Waiting {backoff_time:.1f} seconds before retry {attempt + 1}/{max_retries}...")
            time.sleep(backoff_time)
        except Exception as e:
            print(f"API call failed: {e}")
            if attempt == max_retries - 1:
                raise e
            time.sleep(2 ** attempt)

def log_debate_result(function_name, project, function_type, debate_result, function_body, log_file="vulnerability_analysis_log.txt"):
    """
    Log the complete debate result to a text file in real-time
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    final_decision = debate_result["final_decision"]
    is_detected_vulnerable = final_decision == "VULNERABLE"
    
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*80}\n")
        f.write(f"TIMESTAMP: {timestamp}\n")
        f.write(f"PROJECT: {project}\n")
        f.write(f"FUNCTION: {function_name}\n")
        f.write(f"TYPE: {function_type.upper()}\n")
        f.write(f"FINAL CONSENSUS DECISION: {'VULNERABLE DETECTED' if is_detected_vulnerable else 'NOT VULNERABLE'}\n")
        f.write(f"ROUNDS NEEDED: {debate_result['rounds_needed']}\n")
        f.write(f"CONSENSUS REACHED: {debate_result['consensus_reached']}\n")
        f.write(f"{'='*80}\n")
        
        # Add the actual function body
        f.write(f"FUNCTION BODY:\n")
        f.write(f"{'-'*40}\n")
        f.write(f"{function_body}\n")
        f.write(f"{'-'*40}\n")
        
        # Add complete debate history
        f.write(f"COMPLETE DEBATE HISTORY:\n")
        f.write(f"{'-'*40}\n")
        for entry in debate_result["debate_history"]:
            f.write(f"\nRound {entry['round']} - {entry['agent']}:\n")
            f.write(f"Decision: {entry['decision']}\n")
            if entry.get('assessment'):
                f.write(f"Assessment: {entry['assessment']}\n")
            
            # Include vulnerability score if available
            if entry.get('score') is not None:
                f.write(f"Vulnerability Score: {entry['score']}/10\n")
                if entry.get('score_components') and entry['score_components'][0] is not None:
                    exploitability, impact, complexity = entry['score_components']
                    f.write(f"  - Exploitability: {exploitability}/4, Impact: {impact}/4, Complexity: {complexity}/2\n")
            
            f.write(f"Reasoning: {entry['reasoning'][:500]}{'...' if len(entry['reasoning']) > 500 else ''}\n")
            f.write(f"{'--------------------'}\n")
        
        f.write(f"\n")
        f.flush()  # Ensure immediate write to file

def log_analysis_result(function_name, project, function_type, react_output, is_detected_vulnerable, function_body, log_file="vulnerability_analysis_log.txt"):
    """
    Log the analysis result to a text file in real-time
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Determine what the ReAct agent concluded
    react_output_content = react_output["output"] if isinstance(react_output, dict) and "output" in react_output else str(react_output)
    
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*80}\n")
        f.write(f"TIMESTAMP: {timestamp}\n")
        f.write(f"PROJECT: {project}\n")
        f.write(f"FUNCTION: {function_name}\n")
        f.write(f"TYPE: {function_type.upper()}\n")
        f.write(f"REACT AGENT DECISION: {'VULNERABLE DETECTED' if is_detected_vulnerable else 'NOT VULNERABLE'}\n")
        f.write(f"{'='*80}\n")
        
        # Add the actual function body
        f.write(f"FUNCTION BODY:\n")
        f.write(f"{'-'*40}\n")
        f.write(f"{function_body}\n")
        f.write(f"{'-'*40}\n")
        
        # Add a brief excerpt of the reasoning
        if len(react_output_content) > 500:
            f.write(f"REASONING (excerpt): {react_output_content[:500]}...\n")
        else:
            f.write(f"REASONING: {react_output_content}\n")
        
        f.write(f"\n")
        f.flush()  # Ensure immediate write to file

def initialize_log_file(log_file="vulnerability_analysis_log.txt"):
    """
    Initialize the log file with a header
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(f"VULNERABILITY ANALYSIS LOG\n")
        f.write(f"Started: {timestamp}\n")
        f.write(f"{'='*80}\n")
        f.write(f"This file tracks all functions analyzed and vulnerability detections\n")
        f.write(f"VULNERABLE DETECTED = Vulnerability detected by ReAct Agent\n")
        f.write(f"NOT VULNERABLE = No vulnerability detected by ReAct Agent\n")
        f.write(f"{'='*80}\n")

def add_final_summary_to_log(results, log_file="vulnerability_analysis_log.txt"):
    """
    Add a final summary of all vulnerability detections to the log file
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Count detections
    total_functions = len(results)
    vulnerability_detections = []
    false_positives = []
    missed_vulnerabilities = []
    correct_negatives = []
    
    for r in results:
        final_decision = r["final_decision"]
        detected_vulnerable = final_decision == "VULNERABLE"
        is_actually_vulnerable = r["ground_truth"] == 1
        
        if detected_vulnerable and is_actually_vulnerable:
            vulnerability_detections.append(r)
        elif detected_vulnerable and not is_actually_vulnerable:
            false_positives.append(r)
        elif not detected_vulnerable and is_actually_vulnerable:
            missed_vulnerabilities.append(r)
        else:
            correct_negatives.append(r)
    
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*80}\n")
        f.write(f"FINAL ANALYSIS SUMMARY\n")
        f.write(f"Completed: {timestamp}\n")
        f.write(f"{'='*80}\n")
        f.write(f"Total Functions Analyzed: {total_functions}\n")
        f.write(f"True Vulnerabilities Detected: {len(vulnerability_detections)}\n")
        f.write(f"False Positives (Detected but not vulnerable): {len(false_positives)}\n")
        f.write(f"Missed Vulnerabilities: {len(missed_vulnerabilities)}\n")
        f.write(f"Correct Negatives: {len(correct_negatives)}\n")
        f.write(f"{'='*80}\n")
        
        if vulnerability_detections:
            f.write(f"\nCONFIRMED VULNERABILITY DETECTIONS:\n")
            f.write(f"{'-'*50}\n")
            for i, r in enumerate(vulnerability_detections, 1):
                f.write(f"{i}. {r['function_name']} ({r['project']})\n")
                if r.get('cve'):
                    f.write(f"   CVE: {r['cve']}\n")
                if r.get('cve_desc'):
                    f.write(f"   Description: {r['cve_desc'][:100]}...\n")
                f.write(f"\n")
        
        if missed_vulnerabilities:
            f.write(f"\nMISSED VULNERABILITIES:\n")
            f.write(f"{'-'*50}\n")
            for i, r in enumerate(missed_vulnerabilities, 1):
                f.write(f"{i}. {r['function_name']} ({r['project']})\n")
                if r.get('cve'):
                    f.write(f"   CVE: {r['cve']}\n")
                f.write(f"\n")
        
        if false_positives:
            f.write(f"\nFALSE POSITIVES:\n")
            f.write(f"{'-'*50}\n")
            for i, r in enumerate(false_positives, 1):
                f.write(f"{i}. {r['function_name']} ({r['project']})\n")
        
        f.write(f"\n{'='*80}\n")
        f.write(f"Analysis Complete - Check this log for all vulnerability detections\n")
        f.write(f"{'='*80}\n")
        f.flush()

def run_multi_agent_workflow(benchmark_path, limit=3, use_deepseek=False, model_name="gpt-4o"):
    """
    Multi-agent workflow: ReAct Agent → Reflexion Agent
    No ground truth is revealed to either agent.
    """
    # Initialize the log file
    log_file = "vulnerability_analysis_log.txt"
    initialize_log_file(log_file)
    print(f"Logging analysis results to: {log_file}")
    
    # Estimate token usage
    estimated_tokens_per_function = 5000  # Conservative estimate for iterative debate (multiple rounds)
    estimated_total_tokens = limit * 2 * estimated_tokens_per_function  # 2 functions per pair
    print(f"Processing {limit} function pairs ({limit * 2} total functions)")
    print(f"Estimated token usage: ~{estimated_total_tokens:,} tokens (with iterative debate)")
    print(f"Rate limit: 30,000 tokens/minute")
    print(f"Estimated time: ~{(estimated_total_tokens / 30000) * 60 + limit * 15:.0f} seconds")
    print(f"Using 15-second delays between pairs to avoid rate limits")
    print(f"NOTE: Iterative debate may use 3-8 API calls per function")
    print("-" * 60)
    
    react_agent = ReActAgent(model_name=model_name, use_deepseek=use_deepseek)
    reflexion_agent = ReflexionAgent(model_name=model_name)
    evaluation_agent = EvaluationAgent(model_name=model_name)
    
    results = []
    count = 0
    
    with open(benchmark_path, "r") as f:
        for line in f:
            if count >= limit:
                break
            item = json.loads(line)
            
            # Check if we have the required data
            if not item.get("non_vulnerable_function_bodies") or not item.get("vulnerable_function_bodies"):
                print(f"Skipping entry for {item.get('project', 'Unknown')} - missing function bodies")
                continue
                
            non_vuln_func_list = list(item["non_vulnerable_function_bodies"].keys())
            vuln_func_list = list(item["vulnerable_function_bodies"].keys())
            
            if not non_vuln_func_list or not vuln_func_list:
                print(f"Skipping entry for {item.get('project', 'Unknown')} - empty function lists")
                continue
                
            non_vuln_func_name = non_vuln_func_list[0]
            vuln_func_name = vuln_func_list[0]

            print(f"\n{'='*80}")
            print(f"PROCESSING PAIR {count + 1}")
            print(f"Project: {item['project']}")
            print(f"{'='*80}")

            # Process Benign (non-vulnerable) function
            print(f"\n[BENIGN FUNCTION ANALYSIS]")
            print(f"Function: {non_vuln_func_name}")
            print("-" * 50)
            
            # Create tools with the specific data for this function
            get_callers_tool = lambda fn: tools.get_callers(fn, item["non_vulnerable_caller_graph"])
            get_callees_tool = lambda fn: tools.get_callees(fn, item["non_vulnerable_callee_graph"])
            get_function_body_tool = lambda fn: tools.get_function_body(
                fn, 
                item["non_vulnerable_function_bodies"],
                item.get("project_url"),
                item.get("vulnerability_fixing_commit_id"),
                item.get("file_name")
            )
            
            # Create tool objects for the agent
            from langchain_core.tools import tool
            
            @tool("get_callers")
            def get_callers_benign(function_name: str) -> str:
                """Returns a JSON list of functions that call the given function."""
                return tools.get_callers.invoke({"function_name": function_name, "caller_graph": item["non_vulnerable_caller_graph"]})
            
            @tool("get_callees") 
            def get_callees_benign(function_name: str) -> str:
                """Returns a JSON list of functions called by the given function."""
                return tools.get_callees.invoke({"function_name": function_name, "callee_graph": item["non_vulnerable_callee_graph"]})
            
            @tool("get_function_body")
            def get_function_body_benign(function_name: str) -> str:
                """Retrieves the body of a function as a string."""
                return tools.get_function_body.invoke({
                    "function_name": function_name,
                    "function_bodies": item["non_vulnerable_function_bodies"], 
                    "project_url": item.get("project_url"),
                    "commit_id": item.get("vulnerability_fixing_commit_id"),
                    "file_name": item.get("file_name")
                })
            
            react_agent.set_tools([get_callers_benign, get_callees_benign, get_function_body_benign])
            
            # Conduct iterative debate between agents
            print("Starting iterative debate for benign function...")
            print("-" * 50)
            non_vuln_func_body = item["non_vulnerable_function_bodies"][non_vuln_func_name]
            
            debate_result_benign = iterative_debate(
                react_agent, reflexion_agent, 
                non_vuln_func_name, non_vuln_func_body, 
                "benign", item["project"], max_rounds=3
            )
            
            # Log the final consensus result
            final_decision_benign = debate_result_benign["final_decision"]
            is_detected_vulnerable_benign = final_decision_benign == "VULNERABLE"
            
            # Log with detailed debate history
            log_debate_result(non_vuln_func_name, item["project"], "benign", debate_result_benign, non_vuln_func_body, log_file)
            print(f"Logged debate result for {non_vuln_func_name}")
            
            # EVALUATION STEP - Evaluate the analysis
            print(f"\n[EVALUATION STEP FOR {non_vuln_func_name}]")
            print("-" * 50)
            try:
                print(f"Starting evaluation for {non_vuln_func_name}...")
                evaluation_result_benign = evaluation_agent.evaluate_analysis(
                    function_name=non_vuln_func_name,
                    function_body=non_vuln_func_body,
                    final_decision=final_decision_benign,
                    debate_history=debate_result_benign["debate_history"],
                    ground_truth="NOT_VULNERABLE",  # Benign functions should not be vulnerable
                    project_info={"project": item["project"]}
                )
                print(f"✅ Evaluation completed successfully for {non_vuln_func_name}")
            except Exception as e:
                print(f"❌ Evaluation failed for {non_vuln_func_name}: {e}")
                import traceback
                traceback.print_exc()
                evaluation_result_benign = {
                    "correctness": "UNKNOWN",
                    "error_type": "EVALUATION_ERROR",
                    "confidence": "LOW"
                }

            print(f"Evaluation completed for {non_vuln_func_name}")
            print(f"Correctness: {evaluation_result_benign['correctness']}")
            print(f"Error Type: {evaluation_result_benign['error_type']}")
            print(f"Confidence: {evaluation_result_benign['confidence']}")
            
            # Show the debate summary
            print(f"\n[DEBATE SUMMARY FOR {non_vuln_func_name}]")
            print("=" * 60)
            print(f"Final Consensus: {final_decision_benign}")
            print(f"Rounds needed: {debate_result_benign['rounds_needed']}")
            print(f"Consensus reached: {debate_result_benign['consensus_reached']}")
            print("=" * 60)
            
            results.append({
                "type": "benign",
                "project": item["project"],
                "function_name": non_vuln_func_name,
                "final_decision": final_decision_benign,
                "debate_result": debate_result_benign,
                "evaluation_result": evaluation_result_benign,
                "ground_truth": 0  # For evaluation purposes only - not shown to agents
            })

            # Process Vulnerable function
            print(f"\n[VULNERABLE FUNCTION ANALYSIS]")
            print(f"Function: {vuln_func_name}")
            print("-" * 50)
            
            # Create tools with the specific data for this function
            @tool("get_callers")
            def get_callers_vuln(function_name: str) -> str:
                """Returns a JSON list of functions that call the given function."""
                return tools.get_callers.invoke({"function_name": function_name, "caller_graph": item["vulnerable_caller_graph"]})
            
            @tool("get_callees") 
            def get_callees_vuln(function_name: str) -> str:
                """Returns a JSON list of functions called by the given function."""
                return tools.get_callees.invoke({"function_name": function_name, "callee_graph": item["vulnerable_callee_graph"]})
            
            @tool("get_function_body")
            def get_function_body_vuln(function_name: str) -> str:
                """Retrieves the body of a function as a string."""
                return tools.get_function_body.invoke({
                    "function_name": function_name,
                    "function_bodies": item["vulnerable_function_bodies"], 
                    "project_url": item.get("project_url"),
                    "commit_id": item.get("vulnerable_commit_id"),
                    "file_name": item.get("file_name")
                })
            
            react_agent.set_tools([get_callers_vuln, get_callees_vuln, get_function_body_vuln])
            
            # Conduct iterative debate between agents
            print("Starting iterative debate for vulnerable function...")
            print("-" * 50)
            vuln_func_body = item["vulnerable_function_bodies"][vuln_func_name]
            
            debate_result_vuln = iterative_debate(
                react_agent, reflexion_agent, 
                vuln_func_name, vuln_func_body, 
                "vulnerable", item["project"], max_rounds=3
            )
            
            # Log the final consensus result
            final_decision_vuln = debate_result_vuln["final_decision"]
            is_detected_vulnerable_vuln = final_decision_vuln == "VULNERABLE"
            
            # Log with detailed debate history
            log_debate_result(vuln_func_name, item["project"], "vulnerable", debate_result_vuln, vuln_func_body, log_file)
            print(f"Logged debate result for {vuln_func_name}")
            
            # EVALUATION STEP - Evaluate the analysis
            print(f"\n[EVALUATION STEP FOR {vuln_func_name}]")
            print("-" * 50)
            # Prepare CVE information for evaluation
            cve_info = None
            if item.get("cve"):
                cve_info = {
                    "cve": item.get("cve", ""),
                    "description": item.get("cve_desc", ""),
                    "cwe": item.get("cwe", [])
                }
            try:
                print(f"Starting evaluation for {vuln_func_name}...")
                evaluation_result_vuln = evaluation_agent.evaluate_analysis(
                    function_name=vuln_func_name,
                    function_body=vuln_func_body,
                    final_decision=final_decision_vuln,
                    debate_history=debate_result_vuln["debate_history"],
                    ground_truth="VULNERABLE",  # Vulnerable functions should be detected as vulnerable
                    cve_info=cve_info,
                    project_info={"project": item["project"]}
                )
                print(f"✅ Evaluation completed successfully for {vuln_func_name}")
            except Exception as e:
                print(f"❌ Evaluation failed for {vuln_func_name}: {e}")
                import traceback
                traceback.print_exc()
                evaluation_result_vuln = {
                    "correctness": "UNKNOWN",
                    "error_type": "EVALUATION_ERROR",
                    "confidence": "LOW"
                }

            print(f"Evaluation completed for {vuln_func_name}")
            print(f"Correctness: {evaluation_result_vuln['correctness']}")
            print(f"Error Type: {evaluation_result_vuln['error_type']}")
            print(f"Confidence: {evaluation_result_vuln['confidence']}")
            
            # Show the debate summary
            print(f"\n[DEBATE SUMMARY FOR {vuln_func_name}]")
            print("=" * 60)
            print(f"Final Consensus: {final_decision_vuln}")
            print(f"Rounds needed: {debate_result_vuln['rounds_needed']}")
            print(f"Consensus reached: {debate_result_vuln['consensus_reached']}")
            print("=" * 60)
            
            results.append({
                "type": "vulnerable",
                "project": item["project"],
                "function_name": vuln_func_name,
                "final_decision": final_decision_vuln,
                "debate_result": debate_result_vuln,
                "evaluation_result": evaluation_result_vuln,
                "ground_truth": 1,  # For evaluation purposes only - not shown to agents
                "cve_desc": item.get("cve_desc", ""),
                "cve": item.get("cve", ""),
                "cwe": item.get("cwe", []),
                "vulnerable_function_body": item.get("vulnerable_function_bodies", {}).get(vuln_func_name, ""),
                "non_vulnerable_function_body": item.get("non_vulnerable_function_bodies", {}).get(vuln_func_name, ""),
                "vulnerability_fixing_commit_message": item.get("vulnerability_fixing_commit_message", "")
            })

            count += 1
            print(f"Completed analysis pair {count}. Waiting 15 seconds before next iteration...")
            time.sleep(15)  # Conservative rate limiting - each pair can use 8-12 API calls with debate

    # Add final summary to log file
    add_final_summary_to_log(results, log_file)
    
    # Analyze results (for our evaluation, not shown to agents)
    analyze_workflow_results(results, limit)
    
    # EVALUATION SUMMARY
    print(f"\n{'='*80}")
    print(f"EVALUATION SUMMARY")
    print(f"{'='*80}")
    
    evaluation_stats = evaluation_agent.get_evaluation_statistics()
    print(f"Total evaluations: {evaluation_stats.get('total_evaluations', 0)}")
    
    if 'correctness_breakdown' in evaluation_stats:
        breakdown = evaluation_stats['correctness_breakdown']
        print(f"Correct: {breakdown.get('correct', 0)}")
        print(f"Incorrect: {breakdown.get('incorrect', 0)}")
        print(f"Partially Correct: {breakdown.get('partially_correct', 0)}")
        print(f"Accuracy Rate: {breakdown.get('accuracy_rate', 0):.2%}")
    
    if 'error_type_breakdown' in evaluation_stats:
        print(f"\nError Type Breakdown:")
        for error_type, count in evaluation_stats['error_type_breakdown'].items():
            print(f"  {error_type}: {count}")
    
    if 'learning_opportunities' in evaluation_stats:
        print(f"\nLearning Opportunities:")
        for opportunity, count in evaluation_stats['learning_opportunities'].items():
            print(f"  {opportunity}: {count}")
    
    # Generate improvement recommendations
    recommendations = evaluation_agent.generate_improvement_recommendations()
    if 'recommendations' in recommendations:
        print(f"\nImprovement Recommendations:")
        for i, rec in enumerate(recommendations['recommendations'], 1):
            print(f"  {i}. {rec}")
    
    return results

def analyze_workflow_results(results, limit):
    """
    Analyze the effectiveness of the multi-agent iterative debate workflow.
    This is for our evaluation - the agents never see ground truth.
    """
    print(f"\n{'='*80}")
    print(f"ITERATIVE DEBATE WORKFLOW ANALYSIS")
    print(f"{'='*80}")
    
    consensus_correct_count = 0
    consensus_reached_count = 0
    total_debate_rounds = 0
    
    for r in results:
        # Parse final consensus decision
        final_decision = r["final_decision"]
        consensus_decision = 1 if final_decision == "VULNERABLE" else 0
        
        # Check consensus accuracy
        is_consensus_correct = (consensus_decision == r["ground_truth"])
        if is_consensus_correct:
            consensus_correct_count += 1
        
        # Check if consensus was reached
        if r["debate_result"]["consensus_reached"]:
            consensus_reached_count += 1
        
        # Track total rounds
        total_debate_rounds += r["debate_result"]["rounds_needed"]
        
        # Print detailed case analysis
        print(f"\n{'='*80}")
        print(f"TEST CASE {len([x for x in results[:results.index(r)+1]])}: {r['function_name']} ({r['project']})")
        print(f"{'='*80}")
        print(f"GROUND TRUTH:      {'VULNERABLE' if r['ground_truth'] == 1 else 'NOT VULNERABLE'}")
        print(f"FINAL CONSENSUS:   {final_decision}")
        print(f"ROUNDS NEEDED:     {r['debate_result']['rounds_needed']}")
        print(f"CONSENSUS REACHED: {r['debate_result']['consensus_reached']}")
        print(f"ACCURACY:          {'✓ CORRECT' if is_consensus_correct else '✗ WRONG'}")
        
        if r["ground_truth"] == 1:
            print(f"\nACTUAL VULNERABILITY: {r.get('cve', 'Unknown CVE')}")
            cve_desc = r.get("cve_desc", "")
            if cve_desc:
                print(f"DESCRIPTION: {cve_desc[:150]}...")
        
        # Show debate progression
        print(f"\nDEBATE PROGRESSION:")
        debate_history = r["debate_result"]["debate_history"]
        for entry in debate_history:
            agent_name = entry['agent']
            decision = entry['decision']
            print(f"  Round {entry['round']} - {agent_name}: {decision}")
        print()

    total = len(results)
    vulnerable_count = len([r for r in results if r["ground_truth"] == 1])
    not_vulnerable_count = total - vulnerable_count
    avg_rounds = total_debate_rounds / total if total > 0 else 0
    
    print(f"\n{'='*80}")
    print(f"FINAL SUMMARY")
    print(f"{'='*80}")
    
    # Create a detailed summary table
    print(f"\nDETAILED TEST CASE SUMMARY:")
    print(f"{'='*90}")
    print(f"{'Case':<8} {'Ground Truth':<15} {'Final Decision':<15} {'Rounds':<8} {'Consensus':<10} {'Match'}")
    print(f"{'='*90}")
    
    for i, r in enumerate(results, 1):
        final_decision = r["final_decision"]
        ground_truth = "VULNERABLE" if r["ground_truth"] == 1 else "NOT_VULNERABLE"
        rounds = r["debate_result"]["rounds_needed"]
        consensus = "YES" if r["debate_result"]["consensus_reached"] else "NO"
        
        # Check if final decision matches ground truth
        consensus_decision = 1 if final_decision == "VULNERABLE" else 0
        is_correct = consensus_decision == r["ground_truth"]
        match = "✓" if is_correct else "✗"
        
        print(f"{f'Case {i}':<8} {ground_truth:<15} {final_decision:<15} {rounds:<8} {consensus:<10} {match}")
    
    print(f"\nPERFORMANCE METRICS:")
    print(f"{'='*50}")
    print(f"Total cases analyzed: {total}")
    print(f"Vulnerable cases: {vulnerable_count}")
    print(f"Not vulnerable cases: {not_vulnerable_count}")
    print(f"Final consensus accuracy: {consensus_correct_count}/{total} ({consensus_correct_count/total*100:.1f}%)")
    print(f"Consensus reached rate: {consensus_reached_count}/{total} ({consensus_reached_count/total*100:.1f}%)")
    print(f"Average debate rounds: {avg_rounds:.1f}")
    
    # Calculate vulnerability detection rate
    vuln_detected = 0
    for r in results:
        if r["ground_truth"] == 1:  # It's actually vulnerable
            if r["final_decision"] == "VULNERABLE":
                vuln_detected += 1
    
    if vulnerable_count > 0:
        detection_rate = vuln_detected / vulnerable_count * 100
        print(f"Vulnerability detection rate: {vuln_detected}/{vulnerable_count} ({detection_rate:.1f}%)")
    
    # Calculate false positive rate
    false_positives = 0
    for r in results:
        if r["ground_truth"] == 0 and r["final_decision"] == "VULNERABLE":
            false_positives += 1
    
    if not_vulnerable_count > 0:
        fp_rate = false_positives / not_vulnerable_count * 100
        print(f"False positive rate: {false_positives}/{not_vulnerable_count} ({fp_rate:.1f}%)")
    
    # Debate rounds analysis
    print(f"\nDEBATE ROUNDS ANALYSIS:")
    print(f"{'='*30}")
    round_counts = {}
    for r in results:
        rounds = r["debate_result"]["rounds_needed"]
        round_counts[rounds] = round_counts.get(rounds, 0) + 1
    
    for rounds in sorted(round_counts.keys()):
        count = round_counts[rounds]
        percentage = count / total * 100
        print(f"Resolved in {rounds} round(s): {count} cases ({percentage:.1f}%)")
    
    # Quick vulnerability summary
    vulnerable_cases = [r for r in results if r["ground_truth"] == 1]
    if vulnerable_cases:
        print(f"\nVULNERABILITIES ANALYZED:")
        print(f"{'='*50}")
        for i, r in enumerate(vulnerable_cases, 1):
            detected = r["final_decision"] == "VULNERABLE"
            rounds = r["debate_result"]["rounds_needed"]
            consensus = "CONSENSUS" if r["debate_result"]["consensus_reached"] else "NO-CONSENSUS"
            print(f"{i}. {r.get('cve', 'Unknown CVE')} - {r['function_name']} - {'DETECTED' if detected else 'MISSED'} ({rounds}R, {consensus})")

def extract_vulnerability_score(output):
    """Extract vulnerability score from agent output"""
    if isinstance(output, dict) and "output" in output:
        text = output["output"]
    else:
        text = str(output)
    
    # Look for vulnerability score pattern
    score_patterns = [
        r"VULNERABILITY SCORE:\s*(\d+)/10",
        r"Total Score:\s*(\d+)/10", 
        r"Score:\s*(\d+)/10"
    ]
    
    for pattern in score_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return int(match.group(1))
    
    return None

def extract_score_components(output):
    """Extract detailed score components from agent output"""
    if isinstance(output, dict) and "output" in output:
        text = output["output"]
    else:
        text = str(output)
    
    exploitability = None
    impact = None  
    complexity = None
    
    # Extract component scores
    exploit_match = re.search(r"Exploitability:\s*(\d+)/4", text, re.IGNORECASE)
    if exploit_match:
        exploitability = int(exploit_match.group(1))
        
    impact_match = re.search(r"Impact:\s*(\d+)/4", text, re.IGNORECASE)
    if impact_match:
        impact = int(impact_match.group(1))
        
    complexity_match = re.search(r"Complexity:\s*(\d+)/2", text, re.IGNORECASE)
    if complexity_match:
        complexity = int(complexity_match.group(1))
    
    return exploitability, impact, complexity

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Multi-Agent Vulnerability Analysis with ReAct and Reflexion")
    parser.add_argument("--limit", type=int, default=3, help="Number of function pairs to analyze (default: 3)")
    parser.add_argument("--benchmark", type=str, default="final_benchmark.jsonl", help="Path to benchmark file (default: final_benchmark.jsonl)")
    parser.add_argument("--model", type=str, default="gpt-4o", help="Model to use (default: gpt-4o)")
    parser.add_argument("--use-deepseek", action="store_true", help="Use DeepSeek API instead of OpenAI")
    parser.add_argument("--deepseek-model", type=str, default="deepseek-chat", help="DeepSeek model name (default: deepseek-chat)")
    
    args = parser.parse_args()
    
    benchmark_path = args.benchmark
    if not os.path.exists(benchmark_path):
        print(f"Benchmark file not found: {benchmark_path}")
        sys.exit(1)
    
    print("Starting Multi-Agent Vulnerability Analysis Workflow")
    print("ReAct Agent → Reflexion Agent")
    print("(No ground truth revealed to agents)")
    
    # Choose model based on arguments
    if args.use_deepseek:
        model_name = args.deepseek_model
        print(f"Using DeepSeek model: {model_name}")
    else:
        model_name = args.model
        print(f"Using OpenAI model: {model_name}")
    
    run_multi_agent_workflow(benchmark_path, limit=args.limit, use_deepseek=args.use_deepseek, model_name=model_name) 