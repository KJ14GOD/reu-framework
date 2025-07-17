import json

def analyze_dataset():
    meaningful_samples = 0
    total_samples = 0
    
    with open('data/final_benchmark.jsonl', 'r') as f:
        for line in f:
            total_samples += 1
            data = json.loads(line)
            
            # Check if caller/callee graphs have meaningful information
            non_vuln_caller = data.get('non_vulnerable_caller_graph', {})
            non_vuln_callee = data.get('non_vulnerable_callee_graph', {})
            vuln_caller = data.get('vulnerable_caller_graph', {})
            vuln_callee = data.get('vulnerable_callee_graph', {})
            
            # Check if any function has callers (not just empty callers list)
            has_meaningful_caller = False
            has_meaningful_callee = False
            
            for func_name, func_data in non_vuln_caller.items():
                if func_data.get('callers', []):
                    has_meaningful_caller = True
                    break
                    
            for func_name, func_data in non_vuln_callee.items():
                if func_data.get('callers', []):
                    has_meaningful_callee = True
                    break
            
            # Same check for vulnerable versions
            for func_name, func_data in vuln_caller.items():
                if func_data.get('callers', []):
                    has_meaningful_caller = True
                    break
                    
            for func_name, func_data in vuln_callee.items():
                if func_data.get('callers', []):
                    has_meaningful_callee = True
                    break
            
            if has_meaningful_caller or has_meaningful_callee:
                meaningful_samples += 1
                print(f"Sample {total_samples}: {data.get('project', 'unknown')} - {data.get('file_name', 'unknown')}")
                print(f"  Non-vuln caller: {non_vuln_caller}")
                print(f"  Non-vuln callee: {non_vuln_callee}")
                print(f"  Vuln caller: {vuln_caller}")
                print(f"  Vuln callee: {vuln_callee}")
                print()
    
    print(f"Total samples: {total_samples}")
    print(f"Samples with meaningful caller/callee info: {meaningful_samples}")
    print(f"Percentage: {meaningful_samples/total_samples*100:.2f}%")

if __name__ == "__main__":
    analyze_dataset() 