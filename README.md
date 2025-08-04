# 🛡️ Cyber Threat Intelligence Automation with CrewAI

This project is a multi-agent AI system that automates the process of discovering, analyzing, and responding to the latest cybersecurity threats using LLMs and live threat intelligence sources. It simulates a real-world Security Operations Center (SOC) workflow.

---

## 🚀 Features

- 🔍 Live search for recent cyber threats using **SerpAPI**
- 🧠 Multiple AI agents built using **CrewAI** and **LangChain**
- 🛠 CVE extraction and risk analysis using the **NVD API**
- 📋 Suggested mitigation and response plans
- 📄 Auto-generated Markdown threat intelligence reports

---

## 🎯 Objectives

- Automate cyber threat detection using AI agents
- Fetch and summarize recent threats from open sources
- Extract and analyze CVEs with severity scores
- Recommend actionable mitigation steps
- Generate a structured intelligence report

---

## 🧠 AI Agents

1. **Threat Intelligence Analyst**  
   Searches recent threats, collects data and CVEs.

2. **CVE Vulnerability Analyst**  
   Analyzes the CVEs using the NVD database.

3. **Response Analyst**  
   Suggests mitigation strategies and tools.

4. **Threat Intelligence Reporter**  
   Compiles findings into a final Markdown report.

---

## 🛠 Tools & Technologies

- **CrewAI** – Multi-agent AI orchestration
- **LangChain** – Prompt and LLM management
- **HuggingFace Transformers** – `flan-t5-base` for reasoning
- **SerpAPI** – Live web search for threat data
- **NVD API** – For real-time CVE risk info
- **dotenv** – For secure API key handling

---

## 📦 Setup Instructions

### 1. Clone the repo

```bash
git clone https://github.com/your-username/Cybersec-Agent.git
cd Cybersec-Agent
```
