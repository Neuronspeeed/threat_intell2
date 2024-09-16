from typing import List
from ..models.data_models import Article
from ..utils.logging_config import logger

def validate_data(articles: List[Article]) -> List[Article]:
    logger.info("START: Data Validation")
    try:
        validated_articles = []
        for article in articles:
            if article.title and article.text and article.url:
                validated_articles.append(article)
            else:
                logger.warning(f"Article missing required fields and skipped: {article}")
        logger.info("END: Data Validation completed successfully.")
        return validated_articles
    except Exception as e:
        logger.error(f"ERROR: Data Validation failed - {e}")
        return articles