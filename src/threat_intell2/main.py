import asyncio
from threat_intell2.scrapers.web_scraper import web_scraping
from threat_intell2.processors.data_preprocessor import preprocess_data
from threat_intell2.processors.entity_extractor import extract_entities
from threat_intell2.processors.data_validator import validate_data
from threat_intell2.analyzers.data_analyzer import analyze_data
from threat_intell2.reporting.report_generator import generate_report
from threat_intell2.config import WEBSITES, OUTPUTS_DIR
from threat_intell2.utils.logging_config import logger
import os
import json

async def main():
    try:
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
        
        # Reporting
        generate_report(analysis)
        
        # Ensure the outputs directory exists
        os.makedirs(OUTPUTS_DIR, exist_ok=True)
        
        # Save the result to a JSON file
        output_json_path = os.path.join(OUTPUTS_DIR, 'output.json')
        with open(output_json_path, 'w', encoding='utf-8') as json_file:
            json.dump(validated_articles, json_file, indent=4)
        logger.info(f"Data saved to {output_json_path}")
        
        # Save analysis report
        analysis_report_path = os.path.join(OUTPUTS_DIR, 'analysis_report.txt')
        with open(analysis_report_path, 'w', encoding='utf-8') as analysis_file:
            analysis_file.write(analysis)
        logger.info(f"Analysis report saved to {analysis_report_path}")
        
        logger.info("Threat Intelligence Analysis Pipeline Completed Successfully")
    except Exception as e:
        logger.error(f"An error occurred during execution: {e}")

if __name__ == "__main__":
    asyncio.run(main())