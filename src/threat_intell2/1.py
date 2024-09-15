import asyncio
import aiohttp
from aiohttp_client_cache import CachedSession, SQLiteBackend
from bs4 import BeautifulSoup
from goose3 import Goose
import re
import logging
from datetime import datetime, timezone, timedelta
from typing import TypedDict, List, Optional
from pydantic import BaseModel, Field, field_validator
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.schema import HumanMessage
from dotenv import load_dotenv
import os
import json
from urllib.parse import urljoin
from logging.handlers import RotatingFileHandler
import spacy
import tiktoken

# Initialize NLP model for entity extraction
try:
    nlp = spacy.load("en_core_web_sm")  # Ensure you have installed the spaCy model
except OSError:
    import subprocess
    subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
    nlp = spacy.load("en_core_web_sm")

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create handlers with UTF-8 encoding
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

file_handler = RotatingFileHandler('app.log', maxBytes=5*1024*1024, backupCount=2, encoding='utf-8')
file_handler.setLevel(logging.INFO)

# Create formatter and add it to handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# Load environment variables
load_dotenv()
OPENAI_API_KEY = os.getenv('OPENAI_KEY')
DEFAULT_MODEL = "gpt-4"

if not OPENAI_API_KEY:
    logger.error("OPENAI_KEY environment variable is not set")
    raise ValueError("OPENAI_KEY environment variable is not set")

logger.info("OPENAI_KEY loaded successfully.")

# Initialize the language model
llm = ChatOpenAI(model_name=DEFAULT_MODEL, api_key=OPENAI_API_KEY)

# Define Pydantic models
class TTP(BaseModel):
    tactic: str
    technique: str
    procedure: Optional[str] = None

class IOC(BaseModel):
    type: str
    value: str
    description: Optional[str] = None

    @field_validator('value')
    def validate_value(cls, v):
        # Example validation: simple regex for IP addresses or hashes
        ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        hash_regex = r"^[a-fA-F0-9]{32,64}$"
        if not re.match(ip_regex, v) and not re.match(hash_regex, v):
            raise ValueError('Invalid IOC value format')
        return v

class ThreatActor(BaseModel):
    names: List[str]
    history: Optional[str] = None
    targets: List[str] = []
    ttps: List[TTP] = []
    iocs: List[IOC] = []

class ThreatIntelligenceReport(BaseModel):
    title: str
    date: str
    summary: str
    threat_level: str
    raw_text: str
    threat_actors: List[ThreatActor] = []

class AnalysisCollection(BaseModel):
    reports: List[ThreatIntelligenceReport] = []

# Define the state
class GraphState(TypedDict):
    url: List[str]
    data: str
    messages: List[str]
    reports: List[ThreatIntelligenceReport]
    iteration: int  # To manage feedback loops

# Define cache and headers
cache = SQLiteBackend(cache_name='threat_intel_cache', expire_after=timedelta(days=1))
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
                  ' Chrome/91.0.4472.124 Safari/537.36'
}

# Define a semaphore to limit concurrent requests
semaphore = asyncio.Semaphore(5)  # Adjust the number as needed

# Define functions for each node with enhanced logging

async def fetch_article_links(session: CachedSession, url: str, semaphore: asyncio.Semaphore) -> List[str]:
    async with semaphore:
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                absolute_links = [urljoin(url, link.get('href')) for link in soup.find_all('a') if link.get('href')]
                # Filter links that likely point to articles (simple heuristic)
                article_links = [link for link in absolute_links if '/blog/' in link or '/research/' in link]
                logger.info(f"Fetched {len(article_links)} article links from {url}")
                return article_links
        except Exception as e:
            logger.error(f"Failed to fetch links from {url}: {e}")
            return []

async def scrape_article(session: CachedSession, url: str, semaphore: asyncio.Semaphore) -> Optional[dict]:
    async with semaphore:
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                html = await response.text()
                g = Goose()
                article = g.extract(raw_html=html)
                if not article.cleaned_text:
                    logger.warning(f"No text extracted from {url}")
                    return None
                logger.info(f"Scraped article: {article.title}")
                return {
                    'title': article.title,
                    'text': article.cleaned_text,
                    'url': url
                }
        except Exception as e:
            logger.error(f"Failed to scrape article from {url}: {e}")
            return None

async def scrape_articles(session: CachedSession, links: List[str], semaphore: asyncio.Semaphore) -> List[dict]:
    tasks = [scrape_article(session, link, semaphore) for link in links]
    results = await asyncio.gather(*tasks)
    scraped_articles = [article for article in results if article]
    logger.info(f"Scraped {len(scraped_articles)} articles.")
    return scraped_articles

async def web_scraping(state: GraphState) -> GraphState:
    logger.info("START: Web Scraping")
    try:
        urls = state["url"]  # This is a list of base URLs
        all_articles = []
        async with CachedSession(cache=cache, headers=headers) as session:
            # Fetch article links concurrently
            fetch_tasks = [fetch_article_links(session, url, semaphore) for url in urls]
            links_lists = await asyncio.gather(*fetch_tasks)
            # Flatten the list of lists
            all_links = [link for sublist in links_lists for link in sublist]
            logger.info(f"Total article links fetched: {len(all_links)}")
            # Scrape articles concurrently
            scraped_articles = await scrape_articles(session, all_links, semaphore)
            all_articles.extend(scraped_articles)
        state["data"] = json.dumps(all_articles)
        logger.info("END: Web Scraping completed successfully.")
    except Exception as e:
        logger.error(f"ERROR: Web Scraping failed - {e}")
    state["messages"].append("Web Scraping / Data Collection completed")
    return state

def data_preprocessing(state: GraphState) -> GraphState:
    logger.info("START: Data Preprocessing")
    try:
        articles = json.loads(state["data"])
        preprocessed_articles = []
        seen_urls = set()
        for article in articles:
            text = article['text']
            # Remove extra whitespace and normalize text
            text = re.sub(r'\s+', ' ', text).strip()
            # Remove duplicates based on URL
            if article['url'] in seen_urls:
                logger.debug(f"Duplicate URL found and skipped: {article['url']}")
                continue
            seen_urls.add(article['url'])
            article['text'] = text
            preprocessed_articles.append(article)
        state["data"] = json.dumps(preprocessed_articles)
        logger.info("END: Data Preprocessing completed successfully.")
    except Exception as e:
        logger.error(f"ERROR: Data Preprocessing failed - {e}")
    state["messages"].append("Data Preprocessing completed")
    return state

def entity_extraction(state: GraphState) -> GraphState:
    logger.info("START: Entity Extraction")
    try:
        articles = json.loads(state["data"])
        for article in articles:
            doc = nlp(article['text'])
            threat_actors = set()
            ttps = []
            iocs = set()
            for ent in doc.ents:
                if ent.label_ in ['ORG', 'PERSON']:
                    threat_actors.add(ent.text)
                elif ent.label_ == 'GPE':
                    # Simple heuristic to filter out non-IOC GPEs (e.g., IP addresses)
                    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ent.text):
                        iocs.add(ent.text)
            # Example TTP extraction using regex (to be enhanced)
            ttps_matches = re.findall(r'\b(?:phishing|malware|ransomware|exploit kit)\b', article['text'], re.IGNORECASE)
            ttps = list(set([ttp.capitalize() for ttp in ttps_matches]))
            article['threat_actors'] = list(threat_actors)
            article['ttps'] = ttps
            article['iocs'] = list(iocs)
            logger.debug(f"Extracted from article '{article['title']}': Actors={threat_actors}, TTPs={ttps}, IOCs={iocs}")
        state["data"] = json.dumps(articles)
        logger.info("END: Entity Extraction completed successfully.")
    except Exception as e:
        logger.error(f"ERROR: Entity Extraction failed - {e}")
    state["messages"].append("Entity Extraction completed")
    return state

def data_validation(state: GraphState) -> GraphState:
    logger.info("START: Data Validation and Enrichment")
    try:
        articles = json.loads(state["data"])
        validated_reports = []
        for article in articles:
            # Example validation: ensure required fields are present
            if not all([article.get('title'), article.get('text'), article.get('url')]):
                logger.warning(f"Article missing required fields and skipped: {article}")
                continue
            # Additional validations can be added here (e.g., IOC format)
            validated_reports.append(article)
        state["data"] = json.dumps(validated_reports)
        logger.info("END: Data Validation and Enrichment completed successfully.")
    except Exception as e:
        logger.error(f"ERROR: Data Validation and Enrichment failed - {e}")
    state["messages"].append("Data Validation and Enrichment completed")
    return state

def knowledge_base_integration(state: GraphState) -> GraphState:
    logger.info("START: Knowledge Base Integration")
    try:
        articles = json.loads(state["data"])
        invalid_iocs = 0
        for article in articles:
            valid_iocs = []
            for ioc in article.get('iocs', []):
                if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ioc):
                    valid_iocs.append(ioc)
                else:
                    invalid_iocs += 1
                    logger.warning(f"Invalid IOC skipped: {ioc}")
            report = ThreatIntelligenceReport(
                title=article['title'],
                date=datetime.now(timezone.utc).strftime('%Y-%m-%d'),
                summary=article.get('text')[:500],  # Example summary
                threat_level='Medium',  # Placeholder, can be enhanced
                raw_text=article['text'],
                threat_actors=[
                    ThreatActor(
                        names=[name],
                        targets=[],  # Can be extracted or set
                        ttps=[TTP(tactic=ttp, technique="", procedure="") for ttp in article.get('ttps', [])],
                        iocs=[IOC(type='IP', value=ioc) for ioc in valid_iocs]
                    ) for name in article.get('threat_actors', [])
                ]
            )
            state["reports"].append(report)
        logger.info(f"END: Knowledge Base Integration completed successfully. Invalid IOCs skipped: {invalid_iocs}")
    except Exception as e:
        logger.error(f"ERROR: Knowledge Base Integration failed - {e}")
    state["messages"].append("Knowledge Base Integration completed")
    return state

def count_tokens(text, model="gpt-4"):
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(text))

def chunk_text(text, max_tokens=8000, model="gpt-4"):
    encoding = tiktoken.encoding_for_model(model)
    tokens = encoding.encode(text)
    chunks = []
    for i in range(0, len(tokens), max_tokens):
        chunk_tokens = tokens[i:i + max_tokens]
        chunk = encoding.decode(chunk_tokens)
        chunks.append(chunk)
    return chunks

def data_analysis(state: GraphState) -> GraphState:
    logger.info("START: Data Analysis")
    try:
        reports = state["reports"]
        summarized_reports = [report.summary for report in reports]
        combined_summary = "\n\n".join(summarized_reports)
        
        # Chunk the combined summary to fit within token limits
        tokens_per_chunk = 7000  # Leave room for the model's response
        chunks = chunk_text(combined_summary, max_tokens=tokens_per_chunk)
        logger.info(f"Data Analysis will be performed on {len(chunks)} chunks.")
        
        analyses = []
        
        for idx, chunk in enumerate(chunks, 1):
            prompt = (
                "Analyze the following summarized threat intelligence reports and provide a summary of key findings, "
                "including identified threat actors, their tactics, techniques, and procedures (TTPs), "
                "and any indicators of compromise (IOCs). Ensure the analysis is concise and actionable.\n\n"
                f"Data: {chunk}"
            )
            messages = [HumanMessage(content=prompt)]
            logger.debug(f"Sending chunk {idx} to GPT-4 for analysis.")
            try:
                response = llm.generate([messages])
                analysis = response.generations[0][0].text.strip()
                analyses.append(analysis)
                logger.debug(f"Received analysis for chunk {idx}.")
            except Exception as e:
                logger.error(f"Failed to analyze chunk {idx}: {e}")
        
        # Combine all analyses
        final_analysis = "\n\n".join(analyses)
        state["data"] = f"analyzed data: {final_analysis}"
        logger.info("END: Data Analysis completed successfully.")
    except Exception as e:
        logger.error(f"ERROR: Data Analysis failed - {e}")
        state["data"] = "analyzed data: Analysis failed due to an error."
    state["messages"].append("Data Analysis completed")
    return state

def reporting(state: GraphState) -> GraphState:
    logger.info("START: Reporting and Visualization")
    try:
        # Example: Generate a simple text report
        report_content = state["data"]
        with open('report.txt', 'w', encoding='utf-8') as report_file:
            report_file.write(report_content)
        logger.info("END: Reporting and Visualization completed successfully.")
    except Exception as e:
        logger.error(f"ERROR: Reporting and Visualization failed - {e}")
    state["messages"].append("Reporting and Visualization completed")
    return state

# Create the graph
graph = StateGraph(GraphState)

# Add nodes
graph.add_node("web_scraping", web_scraping)
graph.add_node("data_preprocessing", data_preprocessing)
graph.add_node("entity_extraction", entity_extraction)
graph.add_node("data_validation", data_validation)
graph.add_node("knowledge_base_integration", knowledge_base_integration)
graph.add_node("data_analysis", data_analysis)
graph.add_node("reporting", reporting)

# Add edges
graph.add_edge("web_scraping", "data_preprocessing")
graph.add_edge("data_preprocessing", "entity_extraction")
graph.add_edge("entity_extraction", "data_validation")
graph.add_edge("data_validation", "knowledge_base_integration")
graph.add_edge("knowledge_base_integration", "data_analysis")
graph.add_edge("data_analysis", "reporting")
graph.add_edge("reporting", END)

# Define the entry point and finish point
graph.set_entry_point("web_scraping")

# Compile the graph
compiled_graph = graph.compile()

# Main function to run the analysis
async def main():
    try:
        websites = [
            "https://www.crowdstrike.com/blog/category/threat-intel-research/",
            "https://www.wiz.io/blog/tag/research",
            "https://www.mandiant.com/resources/blog",
            "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/"
        ]
        
        initial_state = {
            "url": websites,  # Pass all URLs at once
            "data": "",
            "messages": [],
            "reports": [],
            "iteration": 0
        }
        result = await compiled_graph.ainvoke(initial_state)
        print("Pipeline Execution Completed.")
        print(json.dumps(result, default=lambda o: o.dict() if hasattr(o, 'dict') else str(o), indent=4))
        
        # Save the result to a JSON file
        with open('output.json', 'w', encoding='utf-8') as json_file:
            # Serialize pydantic models
            serializable_result = result.copy()
            serializable_result["reports"] = [report.dict() for report in serializable_result["reports"]]
            json.dump(serializable_result, json_file, indent=4)
        logger.info("Data saved to output.json")
        
        # Save analysis report
        with open('analysis_report.txt', 'w', encoding='utf-8') as analysis_file:
            analysis_file.write(serializable_result.get("data", "No analysis data available."))
        logger.info("Analysis report saved to analysis_report.txt")
        
    except Exception as e:
        logger.error(f"An error occurred during execution: {e}")

# Run the async main function
if __name__ == "__main__":
    asyncio.run(main())
