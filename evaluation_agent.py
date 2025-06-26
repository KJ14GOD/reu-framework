import os
from langchain_openai import ChatOpenAI

os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

class EvaluationAgent:
    def __init__(self, model_name="gpt-3.5-turbo-0125"):
        self.llm = ChatOpenAI(model=model_name, temperature=0)

    def evaluate(self, react_output, function_name, ground_truth, cve_desc=None):
        # react_output: dict with 'output' (the LLM's output from ReAct agent)
        # ground_truth: 1 = vulnerable, 0 = not vulnerable
        # function_name: name of the function analyzed
        # cve_desc: ground truth rationale (optional, only for vulnerable cases)
        rationale = react_output["output"] if isinstance(react_output, dict) and "output" in react_output else str(react_output)
        gt_label = "vulnerable" if ground_truth == 1 else "not vulnerable"
        prompt = f"""
You are a security expert. Here is the output of a vulnerability detection agent analyzing the function '{function_name}':

{rationale}

The ground truth label for this function is: {gt_label}.

Does the agent's output correctly identify the vulnerability status and provide a valid rationale? Reply with 'MATCH' if both are correct, otherwise 'MISMATCH'.
"""
        response = self.llm.invoke(prompt)
        label_match = response.content.strip()

        rationale_match = None
        if ground_truth == 1 and cve_desc:
            # Only compare rationales for vulnerable cases
            rationale_prompt = f"""
You are a security expert. Compare the following agent's rationale for why the function is vulnerable to the official CVE description. If the agent's rationale captures the same technical root cause or mechanism as the CVE, even if the wording is different, consider it a MATCH. Only reply 'MISMATCH' if the agent's rationale misses the core issue described in the CVE. Reply with 'MATCH' or 'MISMATCH' and explain.

Agent rationale:
{rationale}

CVE description:
{cve_desc}
"""
            rationale_response = self.llm.invoke(rationale_prompt)
            rationale_match = rationale_response.content.strip()

        return {"label_match": label_match, "rationale_match": rationale_match} 