# Multi-Agent Vulnerability Analysis with Learning

A sophisticated vulnerability detection system that uses multiple AI agents (ReAct, Reflexion, and Evaluation) to analyze code for security vulnerabilities, with built-in learning capabilities to improve over time.

## 🎯 Overview

This system implements a multi-agent workflow for vulnerability detection:

1. **ReAct Agent**: Performs initial vulnerability analysis using reasoning and action
2. **Reflexion Agent**: Reviews and critiques the ReAct agent's analysis
3. **Evaluation Agent**: Evaluates the correctness of analyses and learns from mistakes

The system includes a learning mechanism that accumulates knowledge from mistakes, creating a training dataset for continuous improvement.

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- OpenAI API key
- Required packages (see requirements.txt)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd react-correct-integration
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up your OpenAI API key:**
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   ```

### Running the Analysis

**Basic usage:**
```bash
python main.py
```

**With custom parameters:**
```bash
python main.py --limit 5 --benchmark final_benchmark.jsonl
```

## 📊 Understanding the Output

### Console Output

The system provides detailed console output showing:

- **Analysis Progress**: Each function being analyzed
- **Debate Results**: How agents reach consensus
- **Evaluation Results**: Correctness assessment and learning
- **Learning Messages**: When the system learns from mistakes

Example output:
```
[EVALUATION STEP FOR am_check_url]
Starting evaluation for am_check_url...
✅ Evaluation completed successfully for am_check_url

[LEARNING FROM MISTAKE]
Function: am_check_url
Error Type: FALSE_POSITIVE
✅ Learning entry saved. Total learning examples: 1
Learning opportunities identified: Pattern Recognition, Context Understanding
```

### Generated Files

1. **`vulnerability_analysis_log.txt`**: Detailed analysis log
2. **`evaluation_learning_history.json`**: Training data from mistakes
3. **Console output**: Real-time progress and results

## 🧠 Learning System

### How Learning Works

The evaluation agent automatically learns from mistakes:

1. **Detects Errors**: Identifies incorrect vulnerability assessments
2. **Extracts Patterns**: Analyzes what went wrong
3. **Saves Training Data**: Stores function code, decisions, and corrections
4. **Generates Recommendations**: Provides improvement suggestions

### Learning Categories

- **Pattern Recognition**: Missed vulnerability patterns
- **Tool Usage**: Ineffective use of analysis tools
- **Context Understanding**: Failed to consider important context
- **Reasoning Logic**: Flawed logical reasoning
- **Evidence Gathering**: Incomplete evidence collection

### Viewing Learning Progress

Check the learning history:
```bash
cat evaluation_learning_history.json
```

The file contains structured data about each learning event:
```json
[
  {
    "timestamp": "2025-07-16T20:30:00",
    "function_name": "am_check_url",
    "project": "mod_auth_mellon",
    "error_type": "FALSE_POSITIVE",
    "learning_opportunities": ["Pattern Recognition"],
    "function_body": "...",
    "final_decision": "VULNERABLE",
    "ground_truth": "NOT_VULNERABLE"
  }
]
```

## 🔧 Configuration

### Environment Variables

- `OPENAI_API_KEY`: Your OpenAI API key
- `LANGCHAIN_TRACING_V2`: Set to "true" for tracing (optional)
- `LANGCHAIN_API_KEY`: LangSmith API key (optional)

### Parameters

- `--limit`: Number of function pairs to analyze (default: 3)
- `--benchmark`: Path to benchmark data file (default: final_benchmark.jsonl)

## 📈 Understanding Results

### Analysis Metrics

The system tracks:
- **Total Functions Analyzed**: Number of functions processed
- **True Vulnerabilities Detected**: Correctly identified vulnerabilities
- **False Positives**: Incorrectly flagged as vulnerable
- **Missed Vulnerabilities**: Failed to detect actual vulnerabilities
- **Correct Negatives**: Properly identified as non-vulnerable

### Evaluation Statistics

After each run, you'll see:
- **Accuracy Rate**: Percentage of correct assessments
- **Error Type Breakdown**: Distribution of error types
- **Learning Opportunities**: Common areas for improvement
- **Recommendations**: Specific improvement suggestions

## 🛠️ Troubleshooting

### Common Issues

1. **API Key Errors**: Ensure your OpenAI API key is set correctly
2. **Rate Limiting**: The system includes delays to avoid rate limits
3. **Memory Issues**: Large benchmark files may require more memory

### Debug Mode

For detailed debugging, check the console output for:
- `❌ Evaluation failed`: Indicates evaluation agent issues
- `✅ Evaluation completed successfully`: Confirms proper execution
- `[LEARNING FROM MISTAKE]`: Shows learning is working

## 📚 Advanced Usage

### Custom Analysis

To analyze specific functions:
1. Modify the benchmark data file
2. Adjust the limit parameter
3. Run with custom configurations

### Extending the System

The modular design allows for:
- Adding new agents
- Customizing evaluation criteria
- Implementing different learning strategies
- Integrating with other tools

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

[Add your license information here]

## 🙏 Acknowledgments

- OpenAI for providing the language models
- The research community for vulnerability datasets
- Contributors to the multi-agent learning framework
