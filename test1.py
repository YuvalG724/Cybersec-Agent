from dotenv import load_dotenv
import os
import re
import requests
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, START ,END
from langchain_huggingface import HuggingFacePipeline
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM, pipeline
from typing import TypedDict, Optional, List
from serpapi import GoogleSearch

load_dotenv()

tokenizer = AutoTokenizer.from_pretrained("google/flan-t5-base")
model = AutoModelForSeq2SeqLM.from_pretrained("google/flan-t5-base")
pipe = pipeline("text2text-generation", model=model, tokenizer=tokenizer)
llm = HuggingFacePipeline(pipeline=pipe)

class state(TypedDict):
    threats:str
    cve_list: List[str]
    cve_info: list
    mitigation: str
    report: str
    # cve_id: Optional[str]
    # cve_description: Optional[str]
    # cve_details: Optional[str]
    # cve_recommendations: Optional[str]

graphBuilder = StateGraph(state)

def searchThreat(state):
    allResults = []
    queries=[
        "latest ransomware attacks 2025",
        "recently discovered CVEs 2025",
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
            for item in result.get('organic_results'):
                entry = f"Title: {item['title']}\nURL: {item['link']}\nSnippet:{item['snippet'][:200]}\n"
                entries.append(entry)
            inputEntry=f"Query: {query}\nResults for:\n" + "\n".join(entries)
            allResults.append(inputEntry)
        finalInput="\n\n".join(allResults)
        return {**state, "threats":finalInput}
    except Exception as e:
        return {**state,"threats":f"Error during search: {e}"}
    
graphBuilder.add_node("searchThreat", searchThreat)

def extractDetails(state):
    try:
        CVEinstances = list(set(re.findall(r'CVE-\d{4}-\d+', state['threats'])))
        return {**state,"cve_list": CVEinstances}
    except Exception as e:
        return {**state,"cve_list":f"Error during search: {e}"}


graphBuilder.add_node("extractDetails", extractDetails)

def fetchDetails(state):
    results = []
    try:
        for item in state['cve_list']:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={item}"
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            dryData = data['vulnerabilities'][0]['cve']
            severityList = ['baseSeverity','attackComplexity','confidentialityImpact','integrityImpact','availabilityImpact']
            cve_id = dryData['id']
            description = dryData['descriptions'][0]['value']
            fullThreatInfo = dryData['metrics']['cvssMetricV31'][0]['cvssData']
            baseCVSS = dryData['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
            exploitability_score = dryData['metrics']['cvssMetricV31'][0]['exploitabilityScore']
            for item in severityList:
                severitySummary = {key: fullThreatInfo[key] for key in severityList}
            results.append({
                    "cve_id": cve_id,
                    "description": description,
                    "full_threat": fullThreatInfo,
                    "CVSS_basescore": baseCVSS,
                    "exploitability_score": exploitability_score,
                    "severity_summary": severitySummary
                })

    except Exception as e:
        return {**state,"cve_info":"Error fetching details for CVE: " + str(e)}
    return {**state, "cve_info": results}
    
    
graphBuilder.add_node("fetchDetails", fetchDetails)

responsePrompt = ChatPromptTemplate.from_template("""
You are a cybersecurity analyst.
Given these CVE details:
{cve_info}

Generate:
1. Immediate mitigation steps
2. Long-term remediation strategy
3. Recommended tools or patches
""")

def responses(state):
    try:
        prompt = responsePrompt.format(cve_info=state['cve_info'])
        response = llm.invoke(prompt).content
        return {**state,"mitigation": response}
    except Exception as e:
            return {**state,"mitigation":f"Error during mitigation: {e}"}

graphBuilder.add_node("response", responses)

reportPrompt = ChatPromptTemplate.from_template("""
Write a clean Markdown report with :

## Section 1: Threat Summary
{threats}

## Section 2: CVE Analysis
{cve_info}

## Section 3: Incident Response Plan
{mitigation}
""")

def report(state):
    try:
        prompt = reportPrompt.format(
        threats=state['threats'],
        cve_info=state['cve_info'],
        mitigation=state['mitigation']
        )
        final_report = llm.invoke(prompt)
    except Exception as e:
        final_report =  {**state,"report":f"Error during report making: {e}"}
    with open("cve_threat_report.md", "w", encoding="utf-8") as f:
        f.write(final_report)
    return {**state, "report": final_report}
# searches = searchThreat(state)
# details = extractDetails(state)
# cve = fetchDetails(state)
# respo = responses(state)
#print(report(state))

graphBuilder.add_node("report", report)

graphBuilder.add_edge("searchThreat", "extractDetails")
graphBuilder.add_edge("extractDetails", "fetchDetails")
graphBuilder.add_edge("fetchDetails", "response")
graphBuilder.add_edge("response", "report")
graphBuilder.add_edge(START,"searchThreat")
graphBuilder.add_edge("report",END)
graph = graphBuilder.compile()
graph.invoke({})