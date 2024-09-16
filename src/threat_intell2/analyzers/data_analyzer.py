from typing import List, Dict
from ..utils.logging_config import logger
from ..utils.text_processing import chunk_text
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.schema import HumanMessage
from ..config import OPENAI_API_KEY, DEFAULT_MODEL

llm = ChatOpenAI(model_name=DEFAULT_MODEL, api_key=OPENAI_API_KEY)

def analyze_data(articles: List[Dict]) -> str:
    logger.info("START: Data Analysis")
    try:
        summarized_reports = [article['text'][:500] for article in articles]  # Use first 500 chars as summary
        combined_summary = "\n\n".join(summarized_reports)
        
        tokens_per_chunk = 7000
        chunks = chunk_text(combined_summary, max_tokens=tokens_per_chunk)
        logger.info(f"Data Analysis will be performed on {len(chunks)} chunks.")
        
        analyses = []
        
        for idx, chunk in enumerate(chunks, 1):
            prompt = ChatPromptTemplate.from_messages([
                HumanMessage(content=(
                    "Analyze the following summarized threat intelligence reports and provide a summary of key findings, "
                    "including identified threat actors, their tactics, techniques, and procedures (TTPs), "
                    "and any indicators of compromise (IOCs). Ensure the analysis is concise and actionable.\n\n"
                    f"Data: {chunk}"
                ))
            ])
            
            logger.debug(f"Sending chunk {idx} to GPT-4 for analysis.")
            try:
                response = llm.invoke(prompt.format_messages())
                analysis = response.content
                analyses.append(analysis)
                logger.debug(f"Received analysis for chunk {idx}.")
            except Exception as e:
                logger.error(f"Failed to analyze chunk {idx}: {e}")
        
        final_analysis = "\n\n".join(analyses)
        logger.info("END: Data Analysis completed successfully.")
        return final_analysis
    except Exception as e:
        logger.error(f"ERROR: Data Analysis failed - {e}")
        return "Analysis failed due to an error."