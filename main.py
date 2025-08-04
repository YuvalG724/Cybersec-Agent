from dotenv import load_dotenv
import os
import re
from langchain_core.prompts import ChatPromptTemplate
from langchain_huggingface import HuggingFacePipeline
from crewai import Agent, Task, Crew
from crewai.tools import BaseTool
import requests
from litellm import completion
from serpapi import GoogleSearch
from huggingface_hub import InferenceClient
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM, pipeline

load_dotenv()

tokenizer = AutoTokenizer.from_pretrained("google/flan-t5-base")
model = AutoModelForSeq2SeqLM.from_pretrained("google/flan-t5-base")
pipe = pipeline("text2text-generation", model=model, tokenizer=tokenizer)
llm = HuggingFacePipeline(pipeline=pipe)

threatAgent=Agent(
    role = "Threat Intelligence Analyst",
    goal = "Discover and summarize the latest threat intelligence reports, focusing on CVEs, severity levels, and suggested mitigations.",
    backstory = "You work at a cybersecurity SOC, monitoring new threats using web intelligence.",
    llm=llm,
    verbose=True,
    allow_delegation = True
)
vulnAgent=Agent(
    role="CVE Vulnerability Analyst",
    goal = "Analyze mentioned CVEs and report their severity and impact",
    backstory = "You assess CVEs for threat reports using the NVD database and CVSS scoring.",
    llm=llm,
    verbose=True,
    allow_delegation = True
)
responder=Agent(
    role="Response Analyst",
    goal = "Provide actionable responses to the threats identified in the reports",
    backstory = "You suggest mitigations and responses based on threat intelligence.",
    llm=llm,
    verbose=True,
    allow_delegation = True
)
reporter=Agent(
    role="Threat Intelligence Reporter",
    goal = "Compile and report the findings from the threat intelligence analysis in a structured manner.",
    backstory = "You create threat intelligence briefs for CISO teams and security engineers.",
    llm=llm,
    verbose=True,
    allow_delegation = True
)
class searchTool(BaseTool):
    name: str = "Search"
    description: str = "Searches for the latest threat intelligence reports using the Exa API."
    def _run(self, tool_input = None) -> str:
        """Searches for the latest threat intelligence reports using the Exa API.
        Returns a summary of the findings including CVEs, severity levels, and suggested mitigations."""
        allResults = []
        queries=[
            "latest ransomware attacks 2025",
            "CVE-2025-12345 exploit details",
            "APT29 recent cyber activity"
        ]
        try:
            for query in queries:
                params = {
                    "engine":"google",
                    "q": query,
                    "api_key": os.getenv("serpapi"),
                    "num": 5,
                }
                result = GoogleSearch(params).get_dict()
                if "error" in result:
                    return f"Error during search: {result['error']}"
                entries=[]
                for item in result.results:
                    entry = f"Title: {item.title}\nURL: {item.url}\nSnippet:{item.text[:200]}\n"
                    entries.append(entry)
                inputEntry=f"Query: {query}\nResults for:\n" + "\n".join(entries)
                allResults.append(inputEntry)
            finalInput="\n\n".join(allResults)
            return finalInput
        except Exception as e:
            return f"Error during search: {e}"
search = searchTool(llm=llm)
def extract(finalInput):
    instances=list(set(re.findall(r'CVE-\d{4}-\d+',finalInput)))
    return instances

def fetch_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(url)
    data = response.json()
    try:
        cve_data = data['result']['CVE_Items'][0]['cve']
        description = cve_data['description']['description_data'][0]['value']
        cvss_score = cve_data['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
        severity = cve_data['impact']['baseMetricV3']['severity']
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity
        }
    except Exception as e:
        return "Error fetching details for CVE: " + str(e)


threatTask = Task(
    description = "Use exa api to discover and summarize latest cyberthreats focusing on CVEs",
    agent = threatAgent,
    async_execution=False,
    output_file="outputs/threatsummary.txt",
    tools=[search],
    expected_output = "A plain text summary of the latest threats, including CVEs, severity levels, and suggested mitigations."
)

class vulnTool(BaseTool):
    name: str = "Vulnerability Analysis Tool"
    description: str = "Extracts CVEs from the threat summary and analyzes their risk and severity."
    def _run(self, tool_input: str) -> str:
        """Extracts CVEs from the threat summary and analyzes their risk and severity.
        Returns a detailed analysis of the CVEs found, including their risk and severity levels."""
        cves = extract(tool_input)
        details = "\n\n".join([fetch_details(cve) for cve in cves])
        return details

vuln = vulnTool(llm=llm)

vulnTask = Task(
    description="Extract CVEs from the threat summary and analyze their risk and severity.",
    agent = vulnAgent,
    async_execution=False,
    context=[threatTask],
    tools = [vuln],
    expected_output = "A detailed analysis of the CVEs found in the threat summary, including their risk and severity levels."
)

responsePrompt = ChatPromptTemplate.from_template("""
You are a cybersecurity analyst and response expert.
Given these CVE details:
{cveInfo}
Suggest:
1.Immediate mitigation steps
2.Long term remediation
3.Relevant tools or patches
""")

responseTask = Task(
    description="Suggest mitigation and response strategies for the analyzed CVEs.",
    agent = responder,
    async_execution=False,
    context = [vulnTask],
    prompt = responsePrompt,
    expected_output = "A structured response plan including immediate mitigation steps, long-term remediation strategies, and relevant tools or patches."
)

reportPrompt = ChatPromptTemplate.from_template("""
You are a report generator.

Summarize the full findings from the team into a structured, clean Markdown report with:

- Section 1: Threat Summary
- Section 2: CVE Analysis
- Section 3: Incident Response Plan
""")

reportTask = Task(
    description="Write a final threat intelligence report using findings from all agents.",
    agent = reporter,
    async_execution = False,
    context = [threatTask,vulnTask,responseTask],
    prompt = reportPrompt,
    expected_output = "A comprehensive report summarizing the threat intelligence findings, CVE analysis, and incident response plan."
)

crew = Crew(
    agents = [threatAgent,vulnAgent,responder,reporter],
    tasks = [threatTask,vulnTask,responseTask,reportTask],
    verbose = True
)

if __name__ == "__main__":
    result = crew.kickoff()
    if result:
        print("Crew result: ",result)
    else:
        print("No result returned from crew execution.")
    