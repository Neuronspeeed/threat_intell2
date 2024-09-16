from typing import List, Dict
from ..utils.logging_config import logger

def validate_data(articles: List[Dict]) -> List[Dict]:
    logger.info("START: Data Validation")
    try:
        validated_articles = []
        for article in articles:
            if not all([article.get('title'), article.get('text'), article.get('url')]):
                logger.warning(f"Article missing required fields and skipped: {article}")
                continue
            validated_articles.append(article)
        logger.info("END: Data Validation completed successfully.")
        return validated_articles
    except Exception as e:
        logger.error(f"ERROR: Data Validation failed - {e}")
        return articles