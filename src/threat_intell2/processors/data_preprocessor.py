import re
from typing import List, Dict
from ..utils.logging_config import logger

def preprocess_data(articles: List[Dict]) -> List[Dict]:
    logger.info("START: Data Preprocessing")
    try:
        preprocessed_articles = []
        seen_urls = set()
        for article in articles:
            text = article['text']
            text = re.sub(r'\s+', ' ', text).strip()
            if article['url'] in seen_urls:
                logger.debug(f"Duplicate URL found and skipped: {article['url']}")
                continue
            seen_urls.add(article['url'])
            article['text'] = text
            preprocessed_articles.append(article)
        logger.info("END: Data Preprocessing completed successfully.")
        return preprocessed_articles
    except Exception as e:
        logger.error(f"ERROR: Data Preprocessing failed - {e}")
        return articles