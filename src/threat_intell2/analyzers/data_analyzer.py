from typing import List, Dict, Any
from ..utils.logging_config import logger
from ..utils.text_processing import chunk_text
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.schema import HumanMessage
from ..config import OPENAI_API_KEY, DEFAULT_MODEL
from ..models.data_models import Article
import json
from ..models.data_models import ThreatLandscapeItem


llm = ChatOpenAI(model_name=DEFAULT_MODEL, api_key=OPENAI_API_KEY)

def analyze_data(articles: List[Article]) -> Dict[str, Any]:
    logger.info("START: Data Analysis")
    try:
        summarized_reports = []
        for article in articles:
            report = f"Title: {article.title}\nURL: {article.url}\n"
            if article.summary:
                report += f"Summary: {article.summary}\n"
            if article.threat_actors:
                report += "Threat Actors:\n"
                for actor in article.threat_actors:
                    report += f"- {', '.join(actor.names)}\n"
                    if actor.summary:
                        report += f"  Summary: {actor.summary}\n"
                    if actor.motivation:
                        report += f"  Motivation: {actor.motivation}\n"
                    if actor.targets:
                        report += f"  Targets: {', '.join(actor.targets)}\n"
                    if actor.tactics:
                        report += f"  Tactics: {', '.join(actor.tactics)}\n"
                    if actor.techniques:
                        report += f"  Techniques: {', '.join(actor.techniques)}\n"
                    if actor.procedures:
                        report += f"  Procedures: {', '.join(actor.procedures)}\n"
                    if actor.related_iocs:
                        report += f"  Related IOCs: {', '.join(actor.related_iocs)}\n"
            if article.ttps:
                report += "TTPs:\n"
                for ttp in article.ttps:
                    report += f"- Tactic: {ttp.tactic}, Technique: {ttp.technique}\n"
                    if ttp.procedure:
                        report += f"  Procedure: {ttp.procedure}\n"
            if article.iocs:
                report += "IOCs:\n"
                for ioc in article.iocs:
                    report += f"- Type: {ioc.type}, Value: {ioc.value}\n"
            summarized_reports.append(report)
        
        combined_summary = "\n\n".join(summarized_reports)
        
        tokens_per_chunk = 7000
        chunks = chunk_text(combined_summary, max_tokens=tokens_per_chunk)
        logger.info(f"Data Analysis will be performed on {len(chunks)} chunks.")
        
        analyses = []
        
        for idx, chunk in enumerate(chunks, 1):
            prompt = ChatPromptTemplate.from_messages([
                HumanMessage(content=(
                    "As an expert threat intelligence analyst, provide a comprehensive analysis of the following summarized threat intelligence reports. "
                    "Focus on threat actors, their tactics, techniques, procedures, and indicators of compromise. "
                    "Your analysis should be detailed, actionable, and structured as follows:\n\n"
                    "1. Executive Summary: Brief overview of key findings.\n"
                    "2. Threat Actors: Detailed analysis of identified threat actors, their motivations, capabilities, and potential impacts.\n"
                    "3. Threat Landscape: Detailed analysis of the current threat environment, including emerging threats and trends.\n"
                    "4. TTPs: Analysis of the tactics, techniques, and procedures used by the threat actors.\n"
                    "5. IOCs: List and analysis of the indicators of compromise associated with the threats.\n"
                    "6. Global Impact: Assessment of the potential global impact of these threats.\n"
                    "7. Recommendations: Actionable mitigation strategies and defense recommendations.\n\n"
                    "Output the analysis in a structured JSON format, ensuring all sections are included.\n\n"
                    f"Analyze the following data:\n{chunk}"
                ))
            ])
            
            logger.debug(f"Sending chunk {idx} to GPT-4 for analysis.")
            try:
                response = llm.invoke(prompt.format_messages())
                analysis = json.loads(response.content)
                analyses.append(analysis)
                logger.debug(f"Received analysis for chunk {idx}.")
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse GPT-4 response for chunk {idx}: {e}")
                logger.debug(f"Raw response: {response.content}")
            except Exception as e:
                logger.error(f"Failed to analyze chunk {idx}: {e}")
        
        if not analyses:
            raise ValueError("No analyses were generated")

        final_analysis = {
            "executive_summary": "\n".join([a.get("Executive Summary", "") for a in analyses]),
            "threat_actors": [actor for a in analyses for actor in a.get("Threat Actors", [])],
            "threat_landscape": {
                "overview": "\n".join([a.get("Threat Landscape", {}).get("overview", "") for a in analyses]),
                "emerging_threats": [threat for a in analyses for threat in a.get("Threat Landscape", {}).get("emerging_threats", [])]
            },
            "ttps": [ttp for a in analyses for ttp in a.get("TTPs", [])],
            "iocs": [ioc for a in analyses for ioc in a.get("IOCs", [])],
            "global_impact": {
                "overall": "\n".join([a.get("Global Impact", {}).get("overall", "") for a in analyses])
            },
            "recommendations": [rec for a in analyses for rec in a.get("Recommendations", [])]
        }
        logger.info("END: Data Analysis completed successfully.")
        return final_analysis
    except Exception as e:
        logger.error(f"ERROR: Data Analysis failed - {e}")
        return {
            "executive_summary": f"Analysis failed: {str(e)}",
            "threat_actors": [],
            "threat_landscape": {"overview": "Analysis failed", "emerging_threats": []},
            "ttps": [],
            "iocs": [],
            "global_impact": {"overall": "Analysis failed"},
            "recommendations": []
        }