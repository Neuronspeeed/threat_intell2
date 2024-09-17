from typing import List, Dict, Any
from ..utils.logging_config import logger
from ..utils.text_processing import chunk_text
from openai import OpenAI
from openai import OpenAIError
from ..config import OPENAI_API_KEY, DEFAULT_MODEL
import json
from ..models.data_models import Article
from ..models.data_models import ThreatLandscapeItem
from ..processors.entity_extractor import extract_entities
from tenacity import retry, stop_after_attempt, wait_random_exponential
import re

client = OpenAI(api_key=OPENAI_API_KEY)

@retry(wait=wait_random_exponential(min=1, max=60), stop=stop_after_attempt(3))
def analyze_chunk(chunk):
    try:
        response = client.chat.completions.create(
            model=DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst specializing in threat intelligence. Your task is to analyze the given text and provide a structured JSON response."},
                {"role": "user", "content": (
                    "Analyze the following text and provide a JSON response with these keys: "
                    "'Executive_Summary', 'Threat_Actors', 'TTPs', 'IOCs', 'Global_Impact', 'Recommendations'. "
                    "Ensure all values are strings, and use empty strings for any sections without relevant information. "
                    "Format lists as comma-separated strings within quotes. "
                    "Your response should be a valid JSON object.\n\n"
                    f"Text to analyze:\n{chunk}"
                )}
            ],
            temperature=0,
            max_tokens=1000
        )
        content = response.choices[0].message.content
        # Attempt to parse JSON immediately to catch any issues
        parsed_content = json.loads(content)
        # Ensure all keys are present
        for key in ['Executive_Summary', 'Threat_Actors', 'TTPs', 'IOCs', 'Global_Impact', 'Recommendations']:
            if key not in parsed_content:
                parsed_content[key] = ""
        return {
            'Executive_Summary': parsed_content.get('Executive_Summary', ''),
            'Threat_Actors': parsed_content.get('Threat_Actors', '').split(', '),
            'TTPs': parsed_content.get('TTPs', '').split(', '),
            'IOCs': parsed_content.get('IOCs', '').split(', '),
            'Global_Impact': parsed_content.get('Global_Impact', ''),
            'Recommendations': parsed_content.get('Recommendations', '').split(', ')
        }
    except json.JSONDecodeError as json_err:
        logger.error(f"Invalid JSON response from OpenAI: {str(json_err)}")
        logger.debug(f"Raw response: {content}")
        return {
            'Executive_Summary': content,
            'Threat_Actors': [],
            'TTPs': [],
            'IOCs': [],
            'Global_Impact': '',
            'Recommendations': []
        }
    except OpenAIError as e:
        logger.error(f"OpenAI API error: {str(e)}")
        raise

def salvage_analysis(analysis_str: str) -> Dict[str, Any]:
    salvaged = {}
    keys = ['Executive_Summary', 'Threat_Actors', 'TTPs', 'IOCs', 'Global_Impact', 'Recommendations']
    for key in keys:
        pattern = rf'"{key}"\s*:\s*"([^"]*)"'
        match = re.search(pattern, analysis_str, re.DOTALL)
        if match:
            salvaged[key] = match.group(1).strip().split(', ')
        else:
            salvaged[key] = []
    return salvaged if any(salvaged.values()) else None

def combine_article_analyses(analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
    combined = {
        "Executive_Summary": "",
        "Threat_Actors": [],
        "TTPs": [],
        "IOCs": [],
        "Global_Impact": "",
        "Recommendations": []
    }
    for analysis in analyses:
        combined["Executive_Summary"] += analysis.get("Executive_Summary", "") + " "
        combined["Threat_Actors"].extend(analysis.get("Threat_Actors", []))
        combined["TTPs"].extend(analysis.get("TTPs", []))
        combined["IOCs"].extend(analysis.get("IOCs", []))
        combined["Global_Impact"] += analysis.get("Global_Impact", "") + " "
        combined["Recommendations"].extend(analysis.get("Recommendations", []))
    
    # Deduplicate lists
    combined["Threat_Actors"] = list({actor for actor in combined["Threat_Actors"] if actor})
    combined["TTPs"] = list({ttp for ttp in combined["TTPs"] if ttp})
    combined["IOCs"] = list({ioc for ioc in combined["IOCs"] if ioc})
    combined["Recommendations"] = list({rec for rec in combined["Recommendations"] if rec})
    
    combined["Executive_Summary"] = combined["Executive_Summary"].strip()
    combined["Global_Impact"] = combined["Global_Impact"].strip()
    
    return combined

def analyze_data(articles: List[Article]) -> List[Dict[str, Any]]:
    logger.info("START: Data Analysis")
    all_analyses = []

    for article in articles:
        chunks = chunk_text(article.text)
        article_analysis = []
        for chunk in chunks:
            try:
                analysis = analyze_chunk(chunk)
                article_analysis.append(analysis)
            except Exception as e:
                logger.error(f"Error analyzing chunk from article {article.title}: {str(e)}")
        
        if article_analysis:
            combined_analysis = combine_article_analyses(article_analysis)
            all_analyses.append({
                "title": article.title,
                "url": str(article.url),  # Ensure Url object is converted to string
                "analysis": combined_analysis
            })

    logger.info("END: Data Analysis completed successfully.")
    return all_analyses
