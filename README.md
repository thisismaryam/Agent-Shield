#  AgentShield

### AI Agent Security Evaluation Framework

AgentShield is a research-grade framework for evaluating AI agents' resilience against prompt injection attacks through controlled security testing.

---

##  Overview

AgentShield provides a controlled environment to test how well AI agents resist malicious instructions embedded in external data sources. The framework simulates realistic attack scenarios where agents must distinguish between legitimate user requests and hidden adversarial instructions.

**Key capabilities:**
- Automated security evaluation of LLM-based agents
- Real-time monitoring and visualization
- Extensible attack scenario library
- Dual-layer evaluation (rule-based + semantic)

---

##  Key Features

- **Predefined Attack Scenarios**: 8+ security test cases covering common attack vectors
- **Real-Time Dashboard**: Live visualization of agent behavior and decision-making
- **Dual Evaluation System**: Combines deterministic checks with semantic analysis
- **Modular Design**: JSON-based scenarios, pluggable tools, multi-model support
- **WebSocket Streaming**: Live event broadcasting for monitoring

---

##  Technology Stack

| Layer | Technology |
|-------|------------|
| Backend | FastAPI, Python |
| AI/LLM | LangChain, Groq API |
| Communication | WebSockets |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Server | Uvicorn ASGI |

---

##  Quick Start

### Prerequisites
- Python 3.10+
- Groq API Key

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/agentshield.git
cd agentshield

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure API key
echo "GROQ_API_KEY=your_api_key_here" > .env

# Run application
uvicorn server:app --reload --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` to access the dashboard.

---

##  Project Structure

```
AgentShield/
├── agentshield.py      # Core evaluation engine
├── server.py          # Web server and WebSocket endpoints  
├── event_bridge.py    # Real-time event broadcasting
├── scenarios.json     # Attack scenario definitions
├── index.html         # Monitoring dashboard
├── requirements.txt   # Python dependencies
└── .env              # Configuration (create this)
```

---

## Security & Privacy

### Important Notes
- **Research Tool**: AgentShield is designed for controlled research environments
- **Not Production-Ready**: Currently a prototype - lacks authentication, rate limiting, and database persistence
- **API Key Management**: Store your Groq API key securely in `.env` - never commit it
- **Local Execution**: The tool runs locally by default; expose it to networks only in controlled settings

### Best Practices for Use
- Run in isolated environments (local machine or private network)
- Use dedicated test API keys with limited quotas
- Implement basic authentication if exposing via network
- Never use real sensitive data in test scenarios

---

## Use Cases

- **Security Research**: Study prompt injection vulnerabilities
- **AI Safety Testing**: Evaluate agent robustness
- **Education**: Demonstrate AI security concepts
- **Model Comparison**: Benchmark different LLM models

---

##  Contributing

### Adding New Scenarios
Extend `scenarios.json` with new test cases following the existing schema.

### Reporting Issues
Open a GitHub issue with:
- Description of the problem
- Steps to reproduce
- Environment details

### Pull Requests
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

##  Documentation

### Scenario Definition
```json
{
    "id": "unique_id",
    "title": "Attack Description",
    "difficulty": "easy|medium|hard",
    "categories": ["indirect", "tool_manipulation"],
    "task_prompt": "Legitimate user request",
    "poisoned_content": "Hidden malicious instruction",
    "success_condition": {
        "type": "forbidden_tool_call|forbidden_text",
        "tool": "send_email",
        "text": "secret_string"
    }
}
```

---

## Limitations

- Single-threaded execution (one evaluation at a time)
- Mock tool implementations (no actual email/document access)
- In-memory state (no persistent database)
- No authentication or access control
- Designed for research, not production security

---

##  License

MIT License - See [LICENSE](LICENSE) file for details.

---

##  Acknowledgments

- [LangChain](https://www.langchain.com/) - Agent orchestration
- [Groq](https://groq.com/) - LLM inference
- [FastAPI](https://fastapi.tiangolo.com/) - Web framework

---
** Disclaimer**: This tool is for research and educational purposes only. Do not use it with real production systems or sensitive data. Always follow responsible AI security practices.

---

**Built with ❤️ for AI Safety Research**

