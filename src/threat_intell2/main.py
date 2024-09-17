import asyncio
from datetime import datetime
import uuid
from threat_intell2.scrapers.web_scraper import web_scraping
from threat_intell2.processors.data_preprocessor import preprocess_data
from threat_intell2.processors.entity_extractor import extract_entities
from threat_intell2.processors.data_validator import validate_data
from threat_intell2.analyzers.data_analyzer import analyze_data
from threat_intell2.reporting.report_generator import generate_report
from threat_intell2.config import WEBSITES, OUTPUTS_DIR
from threat_intell2.utils.logging_config import logger, setup_file_logging
from threat_intell2.models.data_models import ThreatIntelligenceReport, Analysis, ThreatItem, RecommendationItem
import os
import json

async def main():
    try:
        log_file = os.path.join(OUTPUTS_DIR, "threat_intel.log")
        setup_file_logging(log_file)
        logger.info("Starting threat intelligence gathering process...")

        # Web scraping
        articles = await web_scraping(WEBSITES)
        logger.info(f"Scraped {len(articles)} articles")

        # Data preprocessing
        preprocessed_data = preprocess_data(articles)
        logger.info("Data preprocessing completed")

        # Entity extraction
        extracted_entities = extract_entities(preprocessed_data)
        logger.info("Entity extraction completed")

        # Data validation
        validated_data = validate_data(extracted_entities)
        logger.info("Data validation completed")

        # Data analysis
        analyzed_data = analyze_data(validated_data)
        logger.info("Data analysis completed")

        # Report generation
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = generate_report(analyzed_data, timestamp)
        logger.info("Report generation completed")

        # Aggregate analysis data into Analysis model
        executive_summary = " ".join(
            [item["analysis"]["Executive_Summary"] for item in analyzed_data if "analysis" in item]
        )
        threat_landscape = {}
        emerging_threats = []
        global_impact = ""
        recommendations = []

        for item in analyzed_data:
            analysis = item.get("analysis", {})
            # Assuming 'Threat_Actors' is a list of strings
            for actor in analysis.get("Threat_Actors", []):
                if actor not in threat_landscape:
                    threat_landscape[actor] = {"description": ""}
            # Assuming 'TTPs' is a list of strings
            emerging_threats.extend([ThreatItem(description=ttp) for ttp in analysis.get("TTPs", [])])
            global_impact += analysis.get("Global_Impact", " ") + " "
            recommendations.extend([RecommendationItem(description=rec) for rec in analysis.get("Recommendations", [])])

        # Remove duplicates
        emerging_threats = list({threat.description: threat for threat in emerging_threats}.values())
        recommendations = list({rec.description: rec for rec in recommendations}.values())
        global_impact = global_impact.strip()

        analysis_instance = Analysis(
            executive_summary=executive_summary,
            threat_landscape=threat_landscape,
            emerging_threats=emerging_threats,
            global_impact=global_impact,
            recommendations=recommendations
        )

        # Create ThreatIntelligenceReport instance
        threat_report = ThreatIntelligenceReport(
            id=str(uuid.uuid4()),  # Generate a unique UUID
            timestamp=datetime.now(),
            articles=validated_data,
            analysis=analysis_instance,
            version="0.1.0",
            generated_by="threat-intell2"
        )

        # Save the report using Pydantic's .json() method
        report_filename = f"threat_intel_report_{timestamp}.json"
        report_path = os.path.join(OUTPUTS_DIR, report_filename)
        with open(report_path, "w") as f:
            json.dump(threat_report.dict(), f, indent=2, default=str)
        logger.info(f"Report saved to {report_path}")

        logger.info("Threat intelligence gathering process completed successfully")
    except Exception as e:
        logger.error(f"An error occurred during execution: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())