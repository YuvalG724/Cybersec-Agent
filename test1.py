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
from sentence_transformers import SentenceTransformer
import faiss
import pandas as pd
import pickle

load_dotenv()

class HFInferenceWrapper:
    def __init__(self, api_url, token):
        self.api_url = api_url
        self.headers = {"Authorization": f"Bearer {token}"}

    def invoke(self, prompt):
        response = requests.post(
            self.api_url,
            headers=self.headers,
            json={"inputs": prompt}
        )
        
        # Debug: print response details
        print(f"Status Code: {response.status_code}")
        print(f"Response Text: {response.text[:200]}...")
        
        if response.status_code != 200:
            return f"API Error {response.status_code}: {response.text}"
        
        try:
            data = response.json()
        except ValueError:
            return f"Invalid JSON response. Raw response: {response.text[:500]}"
        
        if isinstance(data, list) and len(data) > 0 and "generated_text" in data[0]:
            return data[0]["generated_text"]
        elif isinstance(data, list) and len(data) > 0:
            # Handle GPT-2 response format
            return data[0].get("generated_text", str(data[0]))
        else:
            return str(data)

# Swap out local model with Inference API - using reliable free models
try:
    # Try GPT-2 first (always available and free)
    llm = HFInferenceWrapper(
        "https://api-inference.huggingface.co/models/google/flan-t5-large",
        os.getenv("HF_API_KEY")
    )
    print("Using t5 large model")
except Exception as e:
    print(f"API failed, using local model: {e}")
    # Fallback to local pipeline (completely free, no API needed)
    llm = pipeline("text2text-generation", model="google/flan-t5-base", max_length=512)
    print("Using local FLAN-T5 model")

indexFile = "cveIndex.faiss"
mapFile = "id_map.pkl"

def load_index_and_map(vector_dimension):
    try:
        index = faiss.read_index(indexFile)
        with open(mapFile, "rb") as f:
            mapping = pickle.load(f)
    except:
        index = faiss.IndexFlatIP(vector_dimension)
        mapping = {}
    return index, mapping

def save_index_and_map(index, mapping):
    faiss.write_index(index, indexFile)
    with open(mapFile, "wb") as f:
        pickle.dump(mapping, f)
#Data Preparation
cveInfo=[]
url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
response = requests.get(url)
response.raise_for_status()
data = response.json()
for cves in data['vulnerabilities']:
    dryData = cves['cve']
    metrics = dryData['metrics']
    if "cvssMetricV31" in metrics:
        threatData = metrics["cvssMetricV31"][0]
    elif "cvssMetricV30" in metrics:
        threatData = metrics["cvssMetricV30"][0]
    elif "cvssMetricV2" in metrics:
        threatData = metrics["cvssMetricV2"][0]
    elif "cvssMetricV4" in metrics:
        threatData = metrics["cvssMetricV4"][0]
    else:
        continue
    severityList = ['baseSeverity','attackComplexity','confidentialityImpact','integrityImpact','availabilityImpact']
    cve_id = dryData['id']
    description = dryData['descriptions'][0]['value']
    fullThreatInfo = threatData['cvssData']
    baseCVSS = threatData['cvssData']['baseScore']
    exploitability_score = threatData['exploitabilityScore']
    references = [ref["url"] for ref in dryData.get('references', [])]
    cveInfo.append({
                        "cve_id": cve_id,
                        "description": description,
                        "full_threat": fullThreatInfo,
                        "CVSS_basescore": baseCVSS,
                        "exploitability_score": exploitability_score,
                        "references": references
                    })
df=pd.DataFrame(cveInfo)

info = (df['cve_id']+": "+df['description']).tolist()
encoder = SentenceTransformer("paraphrase-mpnet-base-v2")
vectors=encoder.encode(info)
vector_dimension = vectors.shape[1]
cveIndex,id_map=load_index_and_map(vector_dimension)
if cveIndex.ntotal == 0:
    faiss.normalize_L2(vectors)
    cveIndex.add(vectors)
    for i, row in df.iterrows():
        id_map[i] = {
            "cve_id": row['cve_id'],
            "description": row['description'],
            "full_threat": row['full_threat'],
            "CVSS_basescore": row['CVSS_basescore'],
            "exploitability_score": row['exploitability_score'],
            "references": row['references']
        }
    save_index_and_map(cveIndex, id_map)

#Agents
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
    encoder = SentenceTransformer("paraphrase-mpnet-base-v2")

    for item in state['cve_list']:
        try:
            query_vec = encoder.encode([item])
            faiss.normalize_L2(query_vec)
            D, I = cveIndex.search(query_vec, k=1)
            if D[0][0] > 0.8:
                hit = id_map[I[0][0]]
                results.append(hit)
            else:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={item}"
                response = requests.get(url)
                response.raise_for_status()
                data = response.json()
                dryData = data['vulnerabilities'][0]['cve']
                metrics = dryData['metrics']
                if "cvssMetricV31" in metrics:
                    threatData = metrics["cvssMetricV31"][0]
                elif "cvssMetricV30" in metrics:
                    threatData = metrics["cvssMetricV30"][0]
                elif "cvssMetricV2" in metrics:
                    threatData = metrics["cvssMetricV2"][0]
                elif "cvssMetricV4" in metrics:
                    threatData = metrics["cvssMetricV4"][0]
                else:
                    continue
                description = dryData['descriptions'][0]['value']
                references = [ref["url"] for ref in dryData.get('references', [])]
                new_entry = {
                    "cve_id": dryData['id'],
                    "description": description,
                    "full_threat": threatData.get("cvssData"),
                    "CVSS_basescore": threatData.get("cvssData", {}).get("baseScore"),
                    "exploitability_score": threatData.get("exploitabilityScore"),
                    "references": references
                }
                results.append(new_entry)

                # 4. Add new entry to FAISS + id_map
                vec = encoder.encode([f"{new_entry['cve_id']}: {new_entry['description']}"])
                faiss.normalize_L2(vec)
                cveIndex.add(vec)
                id_map[len(id_map)] = new_entry
                save_index_and_map(cveIndex, id_map)

        except Exception as e:
            results.append({"error": f"Error fetching details for {item}: {e}"})

    return {**state, "cve_info": results}
    
    
graphBuilder.add_node("fetchDetails", fetchDetails)

responsePrompt = ChatPromptTemplate.from_template("""
You are a cybersecurity analyst.
Given these CVE details:
{cve_info}

Use the references provided in the cve details to provide mitigation steps, recommended tools and patches in the format given below:
Generate:
1. Immediate mitigation steps
2. Patches
3. Recommended tools
""")

def responses(state):
    try:
        formatted_info = ""
        for cve in state['cve_info']:
            if "error" in cve:
                formatted_info += f"\nError: {cve['error']}\n"
                continue
            formatted_info += f"\n\nCVE: {cve['cve_id']}\n"
            formatted_info += f"Description: {cve['description']}\n"
            formatted_info += f"Base Score: {cve.get('CVSS_basescore')}\n"
            formatted_info += f"Exploitability: {cve.get('exploitability_score')}\n"
            formatted_info += "References:\n"
            for ref in cve.get("references", []):
                formatted_info += f"- {ref}\n"
        
        prompt = responsePrompt.format(cve_info=formatted_info)
        response = llm.invoke(prompt)
        return {**state, "mitigation": response}
    except Exception as e:
        return {**state, "mitigation": f"Error during mitigation: {e}"}


graphBuilder.add_node("response", responses)

reportPrompt = ChatPromptTemplate.from_template("""
Write a clean Markdown report with the following sections:

## Section 1: Threat Summary
Summarize in **bullet points**.
{threats}

## Section 2: CVE Analysis
For each CVE, include:
- CVE ID
- Description
- Base Score
- Exploitability
- References (as clickable links)
{cve_info}

## Section 3: Incident Response Plan
Use structured sub-sections:
- Immediate Mitigation Steps
- Patches
- Recommended Tools
{mitigation}
""")

def format_cve_info(cve_info_list):
    formatted = ""
    for cve in cve_info_list:
        if "error" in cve:
            formatted += f"\n\n Error: {cve['error']}\n"
            continue
        formatted += f"\n\n### {cve.get('cve_id')}\n"
        formatted += f"**Description:** {cve.get('description')}\n\n"
        formatted += f"- **Base Score:** {cve.get('CVSS_basescore')}\n"
        formatted += f"- **Exploitability:** {cve.get('exploitability_score')}\n"
        if cve.get("references"):
            formatted += "#### References\n"
            for ref in cve["references"]:
                formatted += f"- [{ref}]({ref})\n"
    return formatted

def report(state):
    try:
        formatted_cve_info = format_cve_info(state['cve_info'])
        prompt = reportPrompt.format(
            threats=state['threats'],
            cve_info=formatted_cve_info,
            mitigation=state['mitigation']
        )
        final_report = llm.invoke(prompt)
    except Exception as e:
        final_report = f"Error during report making: {e}"
    
    with open("cve_threat_report.md", "w", encoding="utf-8") as f:
        f.write(str(final_report))
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


