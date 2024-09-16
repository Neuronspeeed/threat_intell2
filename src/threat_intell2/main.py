import asyncio
from datetime import datetime
from threat_intell2.scrapers.web_scraper import web_scraping
from threat_intell2.processors.data_preprocessor import preprocess_data
from threat_intell2.processors.entity_extractor import extract_entities
from threat_intell2.processors.data_validator import validate_data
from threat_intell2.analyzers.data_analyzer import analyze_data
from threat_intell2.reporting.report_generator import generate_report
from threat_intell2.config import WEBSITES, OUTPUTS_DIR
from threat_intell2.utils.logging_config import logger, setup_file_logging
import os
import json

async def main():
    try:
        # Setup file logging
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(OUTPUTS_DIR, f'cybersecurity_analysis_{timestamp}.log')
        setup_file_logging(log_file)

        # Web Scraping
        articles = await web_scraping(WEBSITES)
        
        # Data Preprocessing
        preprocessed_articles = preprocess_data(articles)
        
        # Entity Extraction
        articles_with_entities = extract_entities(preprocessed_articles)
        
        # Data Validation
        validated_articles = validate_data(articles_with_entities)
        
        # Data Analysis
        analysis = analyze_data(validated_articles)
        
        # Ensure the outputs directory exists
        os.makedirs(OUTPUTS_DIR, exist_ok=True)
        
        # Combine article data with analysis
        output_data = {
            "articles": [article.dict(exclude={'text'}) for article in validated_articles],
            "analysis": analysis
        }
        
        # Save the combined result to a JSON file
        output_json_path = os.path.join(OUTPUTS_DIR, f'threat_intelligence_report_{timestamp}.json')
        with open(output_json_path, 'w', encoding='utf-8') as json_file:
            json.dump(output_data, json_file, indent=4, default=str)
        logger.info(f"Combined threat intelligence report saved to {output_json_path}")
        
        logger.info("Threat Intelligence Analysis Pipeline Completed Successfully")
    except Exception as e:
        logger.error(f"An error occurred during execution: {e}")

if __name__ == "__main__":
    asyncio.run(main())