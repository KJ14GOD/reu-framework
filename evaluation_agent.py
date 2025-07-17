import os
from langchain_openai import ChatOpenAI
import json
from datetime import datetime

os.environ["OPENAI_API_KEY"] = "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"

class EvaluationAgent:
    def __init__(self, model_name="gpt-4o"):
        self.llm = ChatOpenAI(model=model_name, temperature=0)
        self.learning_history = []
        self.evaluation_log = []

    def evaluate_analysis(self, function_name, function_body, final_decision, debate_history, 
                         ground_truth=None, cve_info=None, project_info=None):
        """
        Evaluate the correctness of the vulnerability analysis and learn from mistakes.
        
        Args:
            function_name: Name of the function analyzed
            function_body: The source code of the function
            final_decision: The final decision (VULNERABLE/NOT_VULNERABLE)
            debate_history: History of the debate between agents
            ground_truth: Optional ground truth (VULNERABLE/NOT_VULNERABLE)
            cve_info: Optional CVE information if this is a known vulnerability
            project_info: Optional project information
        """
        
        print(f"\n[EVALUATION AGENT]")
        print(f"Evaluating analysis of function: {function_name}")
        print(f"{'='*60}")
        
        # Create evaluation prompt
        prompt = self._create_evaluation_prompt(
            function_name, function_body, final_decision, 
            debate_history, ground_truth, cve_info, project_info
        )
        
        response = self.llm.invoke(prompt)
        evaluation_text = response.content.strip()
        
        # Parse evaluation results
        evaluation_result = self._parse_evaluation(evaluation_text)
        
        # Store evaluation for learning
        evaluation_record = {
            "timestamp": datetime.now().isoformat(),
            "function_name": function_name,
            "project": project_info.get("project", "unknown") if project_info else "unknown",
            "cve": cve_info.get("cve", "unknown") if cve_info else "unknown",
            "final_decision": final_decision,
            "ground_truth": ground_truth,
            "evaluation_result": evaluation_result,
            "evaluation_text": evaluation_text,
            "debate_history": debate_history
        }
        
        self.evaluation_log.append(evaluation_record)
        
        # Learn from mistakes
        if evaluation_result["correctness"] == "INCORRECT":
            self._learn_from_mistake(evaluation_record)
        
        print("EVALUATION AGENT OUTPUT:")
        print(f"{'='*60}")
        print(evaluation_text)
        print(f"{'='*60}")
        
        return evaluation_result

    def _create_evaluation_prompt(self, function_name, function_body, final_decision, 
                                 debate_history, ground_truth, cve_info, project_info):
        """Create the evaluation prompt"""
        
        # Format debate history
        debate_summary = self._format_debate_history(debate_history)
        
        # Ground truth context
        ground_truth_context = ""
        if ground_truth:
            ground_truth_context = f"""
**GROUND TRUTH:**
- Expected decision: {ground_truth}
- This is a {'known vulnerability' if cve_info else 'test case'}
"""
        
        cve_context = ""
        if cve_info:
            cve_context = f"""
**CVE INFORMATION:**
- CVE: {cve_info.get('cve', 'Unknown')}
- Description: {cve_info.get('description', 'No description available')}
- CWE: {cve_info.get('cwe', 'Unknown')}
"""
        
        return f"""You are an EXPERT security evaluation specialist analyzing vulnerability detection accuracy.

**🎯 MISSION: Evaluate the correctness of vulnerability analysis and identify learning opportunities**

**FUNCTION ANALYSIS:**
Function: {function_name}
Project: {project_info.get('project', 'Unknown') if project_info else 'Unknown'}

**FUNCTION CODE:**
```c
{function_body}
```

**FINAL DECISION:**
{final_decision}

**DEBATE HISTORY:**
{debate_summary}

{ground_truth_context}
{cve_context}

**YOUR EVALUATION TASK:**

**STEP 1: CORRECTNESS ASSESSMENT**
- Is the final decision correct given the code and context?
- If ground truth is provided, compare against it
- If no ground truth, assess based on code analysis

**STEP 2: REASONING QUALITY**
- Was the reasoning sound and evidence-based?
- Were the right tools and analysis methods used?
- Was the debate productive and focused?

**STEP 3: ERROR ANALYSIS (if incorrect)**
- What specific mistake was made?
- Was it a false positive or false negative?
- What evidence was missed or misinterpreted?
- How could this be prevented in future analyses?

**STEP 4: LEARNING OPPORTUNITIES**
- What patterns should be learned from this case?
- What analysis techniques need improvement?
- What additional context would have helped?

**STEP 5: CONFIDENCE ASSESSMENT**
- How confident should we be in this evaluation?
- What factors affect the reliability of this assessment?

**EVALUATION CRITERIA:**

**Correctness:**
- ✅ CORRECT: Decision matches ground truth or accurate code analysis
- ❌ INCORRECT: Decision contradicts ground truth or code analysis
- ⚠️ PARTIALLY_CORRECT: Decision direction correct but reasoning flawed

**Error Types:**
- False Positive: Called vulnerable when actually secure
- False Negative: Called secure when actually vulnerable
- Reasoning Error: Correct decision but wrong reasoning
- Evidence Error: Missed key evidence or misinterpreted code

**Learning Categories:**
- Pattern Recognition: Missed specific vulnerability patterns
- Tool Usage: Ineffective use of analysis tools
- Context Understanding: Failed to consider important context
- Reasoning Logic: Flawed logical reasoning
- Evidence Gathering: Incomplete evidence collection

**REQUIRED OUTPUT:**

**EVALUATION SUMMARY:**
- Correctness: [CORRECT/INCORRECT/PARTIALLY_CORRECT]
- Error Type: [FALSE_POSITIVE/FALSE_NEGATIVE/REASONING_ERROR/EVIDENCE_ERROR/NONE]
- Confidence: [HIGH/MEDIUM/LOW]

**DETAILED ANALYSIS:**
- **Code Evidence:** [Specific code patterns that support or contradict the decision]
- **Reasoning Quality:** [Assessment of the logical reasoning used]
- **Tool Effectiveness:** [How well the analysis tools were used]
- **Context Understanding:** [Whether important context was considered]

**ERROR ANALYSIS (if incorrect):**
- **Root Cause:** [Specific reason for the error]
- **Missed Evidence:** [Key evidence that was overlooked]
- **Misinterpretation:** [How evidence was misunderstood]

**LEARNING OPPORTUNITIES:**
- **Pattern Learning:** [Specific patterns to recognize in future]
- **Tool Improvement:** [How to better use analysis tools]
- **Context Enhancement:** [Additional context that would help]
- **Reasoning Enhancement:** [How to improve logical reasoning]

**RECOMMENDATIONS:**
- **Immediate Actions:** [What should be done differently next time]
- **System Improvements:** [How to improve the overall analysis system]
- **Training Focus:** [What areas need more training/attention]

**Examples:**
- "CORRECT - Properly identified buffer overflow in strcpy usage"
- "INCORRECT - False positive: missed bounds checking in strncpy"
- "PARTIALLY_CORRECT - Right decision but missed the actual vulnerability pattern"
- "INCORRECT - False negative: failed to recognize integer overflow pattern"

**CRITICAL: Be thorough and constructive. Focus on actionable learning opportunities.**"""

    def _format_debate_history(self, debate_history):
        """Format debate history for evaluation"""
        if not debate_history:
            return "No debate history available."
        
        formatted = []
        for entry in debate_history:
            round_num = entry.get("round", "?")
            agent = entry.get("agent", "Unknown")
            decision = entry.get("decision", "Unknown")
            reasoning = entry.get("reasoning", "No reasoning provided")
            
            formatted.append(f"Round {round_num} - {agent}:")
            formatted.append(f"  Decision: {decision}")
            formatted.append(f"  Reasoning: {reasoning[:200]}...")
            formatted.append("")
        
        return "\n".join(formatted)

    def _parse_evaluation(self, evaluation_text):
        """Parse the evaluation results from the agent's response"""
        
        # Extract key information
        correctness = "UNKNOWN"
        error_type = "NONE"
        confidence = "UNKNOWN"
        
        text_upper = evaluation_text.upper()
        
        # Parse correctness
        if "CORRECT" in text_upper:
            correctness = "CORRECT"
        elif "INCORRECT" in text_upper:
            correctness = "INCORRECT"
        elif "PARTIALLY_CORRECT" in text_upper:
            correctness = "PARTIALLY_CORRECT"
        
        # Parse error type
        if "FALSE_POSITIVE" in text_upper:
            error_type = "FALSE_POSITIVE"
        elif "FALSE_NEGATIVE" in text_upper:
            error_type = "FALSE_NEGATIVE"
        elif "REASONING_ERROR" in text_upper:
            error_type = "REASONING_ERROR"
        elif "EVIDENCE_ERROR" in text_upper:
            error_type = "EVIDENCE_ERROR"
        
        # Parse confidence
        if "HIGH" in text_upper and "CONFIDENCE" in text_upper:
            confidence = "HIGH"
        elif "MEDIUM" in text_upper and "CONFIDENCE" in text_upper:
            confidence = "MEDIUM"
        elif "LOW" in text_upper and "CONFIDENCE" in text_upper:
            confidence = "LOW"
        
        return {
            "correctness": correctness,
            "error_type": error_type,
            "confidence": confidence,
            "full_evaluation": evaluation_text
        }

    def _learn_from_mistake(self, evaluation_record):
        """Learn from mistakes and update learning history"""
        print(f"\n[LEARNING FROM MISTAKE]")
        print(f"Function: {evaluation_record['function_name']}")
        print(f"Error Type: {evaluation_record['evaluation_result']['error_type']}")

        learning_entry = {
            "timestamp": evaluation_record["timestamp"],
            "function_name": evaluation_record["function_name"],
            "project": evaluation_record["project"],
            "cve": evaluation_record["cve"],
            "error_type": evaluation_record["evaluation_result"]["error_type"],
            "learning_opportunities": self._extract_learning_opportunities(
                evaluation_record["evaluation_text"]
            ),
            "function_body": evaluation_record.get("function_body", ""),
            "final_decision": evaluation_record.get("final_decision", ""),
            "ground_truth": evaluation_record.get("ground_truth", ""),
            "debate_history": evaluation_record.get("debate_history", []),
            "evaluation_text": evaluation_record.get("evaluation_text", "")
        }

        self.learning_history.append(learning_entry)

        # Save learning history to file
        try:
            with open("evaluation_learning_history.json", "w") as f:
                import json
                json.dump(self.learning_history, f, indent=2)
            print(f"✅ Learning entry saved. Total learning examples: {len(self.learning_history)}")
            print(f"Learning opportunities identified: {', '.join(learning_entry['learning_opportunities'])}")
        except Exception as e:
            print(f"❌ Failed to save learning history: {e}")
        return learning_entry

    def _extract_learning_opportunities(self, evaluation_text):
        """Extract learning opportunities from evaluation text"""
        # This is a simplified extraction - in practice, you might use more sophisticated parsing
        opportunities = []
        
        if "PATTERN" in evaluation_text.upper():
            opportunities.append("Pattern Recognition")
        if "TOOL" in evaluation_text.upper():
            opportunities.append("Tool Usage")
        if "CONTEXT" in evaluation_text.upper():
            opportunities.append("Context Understanding")
        if "REASONING" in evaluation_text.upper():
            opportunities.append("Reasoning Logic")
        if "EVIDENCE" in evaluation_text.upper():
            opportunities.append("Evidence Gathering")
        
        return opportunities if opportunities else ["General Improvement"]

    def _save_learning_history(self):
        """Save learning history to file"""
        try:
            with open("evaluation_learning_history.json", "w") as f:
                json.dump(self.learning_history, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save learning history: {e}")

    def get_evaluation_statistics(self):
        """Get statistics about evaluations performed"""
        if not self.evaluation_log:
            return {"message": "No evaluations performed yet"}
        
        total_evaluations = len(self.evaluation_log)
        correct_count = sum(1 for eval in self.evaluation_log 
                          if eval["evaluation_result"]["correctness"] == "CORRECT")
        incorrect_count = sum(1 for eval in self.evaluation_log 
                            if eval["evaluation_result"]["correctness"] == "INCORRECT")
        partially_correct_count = sum(1 for eval in self.evaluation_log 
                                    if eval["evaluation_result"]["correctness"] == "PARTIALLY_CORRECT")
        
        # Error type breakdown
        error_types = {}
        for eval in self.evaluation_log:
            error_type = eval["evaluation_result"]["error_type"]
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        # Learning opportunities breakdown
        learning_opportunities = {}
        for entry in self.learning_history:
            for opportunity in entry.get("learning_opportunities", []):
                learning_opportunities[opportunity] = learning_opportunities.get(opportunity, 0) + 1
        
        return {
            "total_evaluations": total_evaluations,
            "correctness_breakdown": {
                "correct": correct_count,
                "incorrect": incorrect_count,
                "partially_correct": partially_correct_count,
                "accuracy_rate": correct_count / total_evaluations if total_evaluations > 0 else 0
            },
            "error_type_breakdown": error_types,
            "learning_opportunities": learning_opportunities,
            "recent_evaluations": self.evaluation_log[-5:] if len(self.evaluation_log) >= 5 else self.evaluation_log
        }

    def generate_improvement_recommendations(self):
        """Generate recommendations based on learning history"""
        if not self.learning_history:
            return {"message": "No learning history available"}
        
        # Analyze common patterns in mistakes
        error_patterns = {}
        learning_patterns = {}
        
        for entry in self.learning_history:
            error_type = entry["error_type"]
            error_patterns[error_type] = error_patterns.get(error_type, 0) + 1
            
            for opportunity in entry.get("learning_opportunities", []):
                learning_patterns[opportunity] = learning_patterns.get(opportunity, 0) + 1
        
        # Generate recommendations
        recommendations = []
        
        if error_patterns.get("FALSE_POSITIVE", 0) > error_patterns.get("FALSE_NEGATIVE", 0):
            recommendations.append("Focus on reducing false positives - be more conservative in vulnerability detection")
        else:
            recommendations.append("Focus on reducing false negatives - be more thorough in vulnerability detection")
        
        if learning_patterns.get("Pattern Recognition", 0) > 0:
            recommendations.append("Improve pattern recognition training - add more specific vulnerability patterns")
        
        if learning_patterns.get("Tool Usage", 0) > 0:
            recommendations.append("Enhance tool usage training - better utilization of analysis tools")
        
        if learning_patterns.get("Context Understanding", 0) > 0:
            recommendations.append("Improve context understanding - consider more environmental factors")
        
        return {
            "error_patterns": error_patterns,
            "learning_patterns": learning_patterns,
            "recommendations": recommendations
        } 