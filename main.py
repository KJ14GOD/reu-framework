import json
import sys
import os
import textwrap
from react_agent import ReActAgent
from reflexion_agent import ReflexionAgent
import time
import tools

def run_multi_agent_workflow(benchmark_path, limit=5):
    """
    Multi-agent workflow: ReAct Agent → Reflexion Agent
    No ground truth is revealed to either agent.
    """
    react_agent = ReActAgent(model_name="gpt-4o")
    reflexion_agent = ReflexionAgent(model_name="gpt-4o")
    
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
            
            # Step 1: ReAct Agent Analysis
            print("Step 1: ReAct Agent analyzing...")
            print("-" * 30)
            react_output_benign = react_agent.predict(non_vuln_func_name)
            
            # Show what the ReAct agent produced
            print(f"\n[REACT AGENT OUTPUT FOR {non_vuln_func_name}]")
            print("=" * 60)
            react_output_content_benign = react_output_benign["output"] if isinstance(react_output_benign, dict) and "output" in react_output_benign else str(react_output_benign)
            print(react_output_content_benign)
            print("=" * 60)
            
            # Step 2: Reflexion Agent Review
            print("\nStep 2: Reflexion Agent reviewing...")
            print("-" * 30)
            non_vuln_func_body = item["non_vulnerable_function_bodies"][non_vuln_func_name]
            reflexion_output_benign = reflexion_agent.reflect_on_analysis(non_vuln_func_name, non_vuln_func_body, react_output_benign)
            
            results.append({
                "type": "benign",
                "project": item["project"],
                "function_name": non_vuln_func_name,
                "react_output": react_output_benign,
                "reflexion_output": reflexion_output_benign,
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
            
            # Step 1: ReAct Agent Analysis
            print("Step 1: ReAct Agent analyzing...")
            print("-" * 30)
            react_output_vuln = react_agent.predict(vuln_func_name)
            
            # Show what the ReAct agent produced
            print(f"\n[REACT AGENT OUTPUT FOR {vuln_func_name}]")
            print("=" * 60)
            react_output_content_vuln = react_output_vuln["output"] if isinstance(react_output_vuln, dict) and "output" in react_output_vuln else str(react_output_vuln)
            print(react_output_content_vuln)
            print("=" * 60)
            
            # Step 2: Reflexion Agent Review
            print("\nStep 2: Reflexion Agent reviewing...")
            print("-" * 30)
            vuln_func_body = item["vulnerable_function_bodies"][vuln_func_name]
            reflexion_output_vuln = reflexion_agent.reflect_on_analysis(vuln_func_name, vuln_func_body, react_output_vuln)
            
            results.append({
                "type": "vulnerable",
                "project": item["project"],
                "function_name": vuln_func_name,
                "react_output": react_output_vuln,
                "reflexion_output": reflexion_output_vuln,
                "ground_truth": 1,  # For evaluation purposes only - not shown to agents
                "cve_desc": item.get("cve_desc", ""),
                "cve": item.get("cve", ""),
                "cwe": item.get("cwe", []),
                "vulnerable_function_body": item.get("vulnerable_function_bodies", {}).get(vuln_func_name, ""),
                "non_vulnerable_function_body": item.get("non_vulnerable_function_bodies", {}).get(vuln_func_name, ""),
                "vulnerability_fixing_commit_message": item.get("vulnerability_fixing_commit_message", "")
            })

            count += 1
            time.sleep(2)  # Rate limiting

    # Analyze results (for our evaluation, not shown to agents)
    analyze_workflow_results(results, limit)
    return results

def analyze_workflow_results(results, limit):
    """
    Analyze the effectiveness of the multi-agent workflow.
    This is for our evaluation - the agents never see ground truth.
    """
    print(f"\n{'='*80}")
    print(f"WORKFLOW ANALYSIS SUMMARY")
    print(f"{'='*80}")
    
    react_correct_count = 0
    reflexion_correct_count = 0
    reflexion_high_confidence_count = 0
    
    for r in results:
        # Parse ReAct agent's decision
        react_output_content = r["react_output"]["output"] if isinstance(r["react_output"], dict) and "output" in r["react_output"] else str(r["react_output"])
        
        if "@@vulnerable@@" in react_output_content.lower():
            react_decision = 1
        elif "@@not vulnerable@@" in react_output_content.lower():
            react_decision = 0
        else:
            react_decision = -1  # Unclear
        
        # Check ReAct accuracy
        is_react_correct = (react_decision == r["ground_truth"])
        if is_react_correct:
            react_correct_count += 1
        
        # Check Reflexion assessment
        reflexion_assessment = r["reflexion_output"]["assessment"]
        reflexion_confidence = r["reflexion_output"]["confidence"]
        
        if reflexion_assessment == "CORRECT":
            reflexion_correct_count += 1
        
        if reflexion_confidence == "HIGH":
            reflexion_high_confidence_count += 1
        
        # Extract what each agent said
        react_says = "VULNERABLE" if react_decision == 1 else "NOT VULNERABLE" if react_decision == 0 else "UNCLEAR"
        
        # Extract Reflexion agent's independent conclusion
        reflexion_says = "UNKNOWN"
        reflexion_explanation = ""
        if isinstance(r["reflexion_output"], dict) and "reflexion_output" in r["reflexion_output"]:
            reflexion_text = r["reflexion_output"]["reflexion_output"]
            if "YOUR INDEPENDENT CONCLUSION" in reflexion_text:
                conclusion_section = reflexion_text.split("YOUR INDEPENDENT CONCLUSION")[1]
                if "@@vulnerable@@" in conclusion_section.lower():
                    reflexion_says = "VULNERABLE"
                elif "@@not vulnerable@@" in conclusion_section.lower():
                    reflexion_says = "NOT VULNERABLE"
            
            # Get reflexion explanation
            if "RATIONALE FOR ASSESSMENT" in reflexion_text:
                reflexion_explanation = reflexion_text.split("RATIONALE FOR ASSESSMENT")[1].split("YOUR INDEPENDENT CONCLUSION")[0].strip()
            else:
                reflexion_explanation = reflexion_text[:200] + "..."
        
        # Extract ReAct explanation
        react_explanation = ""
        if isinstance(r["react_output"], dict) and "output" in r["react_output"]:
            react_text = r["react_output"]["output"]
            if "@@vulnerable@@" in react_text:
                react_explanation = react_text.split("@@vulnerable@@", 1)[1].strip()[:200] + "..."
            elif "@@not vulnerable@@" in react_text:
                react_explanation = react_text.split("@@not vulnerable@@", 1)[1].strip()[:200] + "..."
        
        # Print clean result
        print(f"\n{'='*80}")
        print(f"TEST CASE {len([x for x in results[:results.index(r)+1]])}: {r['function_name']} ({r['project']})")
        print(f"{'='*80}")
        print(f"GROUND TRUTH:      {'VULNERABLE' if r['ground_truth'] == 1 else 'NOT VULNERABLE'}")
        print(f"REACT AGENT SAYS:  {react_says}")
        print(f"REFLEXION SAYS:    {reflexion_says}")
        print(f"REFLEXION THINKS REACT WAS: {reflexion_assessment}")
        print(f"")
        print(f"RESULTS: ReAct={'✓ CORRECT' if is_react_correct else '✗ WRONG'} | Reflexion={'✓ AGREES' if reflexion_assessment == 'CORRECT' else '✗ DISAGREES'}")
        
        if r["ground_truth"] == 1:
            print(f"\nACTUAL VULNERABILITY: {r.get('cve', 'Unknown CVE')}")
            cve_desc = r.get("cve_desc", "")
            if cve_desc:
                print(f"DESCRIPTION: {cve_desc[:150]}...")
        
        print(f"\nREACT REASONING: {react_explanation if react_explanation else 'No explanation'}")
        print(f"REFLEXION REASONING: {reflexion_explanation[:150] + '...' if len(reflexion_explanation) > 150 else reflexion_explanation}")


    total = len(results)
    vulnerable_count = len([r for r in results if r["ground_truth"] == 1])
    not_vulnerable_count = total - vulnerable_count
    
    print(f"\n{'='*80}")
    print(f"FINAL SUMMARY")
    print(f"{'='*80}")
    
    # Create a summary table
    print(f"\nTEST CASE SUMMARY:")
    print(f"{'='*60}")
    print(f"{'Case':<15} {'Ground Truth':<15} {'ReAct Says':<15} {'Reflexion Says':<15} {'Match'}")
    print(f"{'='*60}")
    
    for i, r in enumerate(results, 1):
        react_output_content = r["react_output"]["output"] if isinstance(r["react_output"], dict) and "output" in r["react_output"] else str(r["react_output"])
        
        if "@@vulnerable@@" in react_output_content.lower():
            react_decision = 1
        elif "@@not vulnerable@@" in react_output_content.lower():
            react_decision = 0
        else:
            react_decision = -1
        
        react_says = "VULNERABLE" if react_decision == 1 else "NOT_VULNERABLE" if react_decision == 0 else "UNCLEAR"
        ground_truth = "VULNERABLE" if r["ground_truth"] == 1 else "NOT_VULNERABLE"
        
        # Extract Reflexion's independent conclusion
        reflexion_says = "UNKNOWN"
        if isinstance(r["reflexion_output"], dict) and "reflexion_output" in r["reflexion_output"]:
            reflexion_text = r["reflexion_output"]["reflexion_output"]
            if "YOUR INDEPENDENT CONCLUSION" in reflexion_text:
                conclusion_section = reflexion_text.split("YOUR INDEPENDENT CONCLUSION")[1]
                if "@@vulnerable@@" in conclusion_section.lower():
                    reflexion_says = "VULNERABLE"
                elif "@@not vulnerable@@" in conclusion_section.lower():
                    reflexion_says = "NOT_VULNERABLE"
        
        react_correct = "✓" if react_decision == r["ground_truth"] else "✗"
        
        print(f"{f'Case {i}':<15} {ground_truth:<15} {react_says:<15} {reflexion_says:<15} {react_correct}")
    
    print(f"\nPERFORMANCE METRICS:")
    print(f"{'='*40}")
    print(f"Total cases analyzed: {total}")
    print(f"Vulnerable cases: {vulnerable_count}")
    print(f"Not vulnerable cases: {not_vulnerable_count}")
    print(f"ReAct Agent accuracy: {react_correct_count}/{total} ({react_correct_count/total*100:.1f}%)")
    print(f"Reflexion 'CORRECT' assessments: {reflexion_correct_count}/{total} ({reflexion_correct_count/total*100:.1f}%)")
    
    # Calculate vulnerability detection rate
    vuln_detected = 0
    for r in results:
        if r["ground_truth"] == 1:  # It's actually vulnerable
            react_output_content = r["react_output"]["output"] if isinstance(r["react_output"], dict) and "output" in r["react_output"] else str(r["react_output"])
            if "@@vulnerable@@" in react_output_content.lower():
                vuln_detected += 1
    
    if vulnerable_count > 0:
        detection_rate = vuln_detected / vulnerable_count * 100
        print(f"Vulnerability detection rate: {vuln_detected}/{vulnerable_count} ({detection_rate:.1f}%)")
    
    # Agreement analysis
    agree_count = 0
    for r in results:
        reflexion_assessment = r["reflexion_output"]["assessment"]
        react_output_content = r["react_output"]["output"] if isinstance(r["react_output"], dict) and "output" in r["react_output"] else str(r["react_output"])
        react_decision = 1 if "@@vulnerable@@" in react_output_content.lower() else 0 if "@@not vulnerable@@" in react_output_content.lower() else -1
        is_react_correct = (react_decision == r["ground_truth"])
        
        if (reflexion_assessment == "CORRECT" and is_react_correct) or (reflexion_assessment in ["INCORRECT", "PARTIALLY_CORRECT"] and not is_react_correct):
            agree_count += 1
    
    agreement_rate = agree_count / total * 100 if total > 0 else 0
    print(f"Reflexion agreement with ground truth: {agree_count}/{total} ({agreement_rate:.1f}%)")
    
    # Quick vulnerability summary
    vulnerable_cases = [r for r in results if r["ground_truth"] == 1]
    if vulnerable_cases:
        print(f"\nVULNERABILITIES ANALYZED:")
        print(f"{'='*50}")
        for i, r in enumerate(vulnerable_cases, 1):
            react_output_content = r["react_output"]["output"] if isinstance(r["react_output"], dict) and "output" in r["react_output"] else str(r["react_output"])
            detected = "@@vulnerable@@" in react_output_content.lower()
            print(f"{i}. {r.get('cve', 'Unknown CVE')} - {r['function_name']} - {'DETECTED' if detected else 'MISSED'}")

if __name__ == "__main__":
    benchmark_path = "final_benchmark.jsonl"
    if not os.path.exists(benchmark_path):
        print(f"Benchmark file not found: {benchmark_path}")
        sys.exit(1)
    
    print("Starting Multi-Agent Vulnerability Analysis Workflow")
    print("ReAct Agent → Reflexion Agent")
    print("(No ground truth revealed to agents)")
    
    run_multi_agent_workflow(benchmark_path, limit=5) 