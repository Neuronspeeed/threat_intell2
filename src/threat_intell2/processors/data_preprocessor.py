from typing import List
from ..models.data_models import Article
from ..utils.logging_config import logger

def preprocess_data(articles: List[Article]) -> List[Article]:
    logger.info("START: Data Preprocessing")
    try:
        preprocessed_articles = []
        seen_urls = set()
        for article in articles:
            if article.url in seen_urls:
                logger.debug(f"Duplicate URL found and skipped: {article.url}")
                continue
            seen_urls.add(article.url)
            preprocessed_articles.append(article)
        logger.info("END: Data Preprocessing completed successfully.")
        return preprocessed_articles
    except Exception as e:
        logger.error(f"ERROR: Data Preprocessing failed - {e}")
        return articles