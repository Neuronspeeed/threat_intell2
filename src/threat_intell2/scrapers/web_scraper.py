import asyncio
from typing import List, Optional
from urllib.parse import urljoin

import aiohttp
from aiohttp_client_cache import CachedSession
from bs4 import BeautifulSoup
from goose3 import Goose

from threat_intell2.config import (
    HEADERS,
    WEBSITES,
    SEMAPHORE_LIMIT,
    ARTICLES_PER_WEBSITE  # Import the new configuration
)
from threat_intell2.utils.logging_config import logger
from ..models.data_models import Article

async def fetch_article_links(
    session: CachedSession, url: str, semaphore: asyncio.Semaphore
) -> List[str]:
    async with semaphore:
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Extract absolute links
                absolute_links = [
                    urljoin(url, link.get('href'))
                    for link in soup.find_all('a')
                    if link.get('href')
                ]
                
                # Filter links that likely point to articles
                article_links = [
                    link for link in absolute_links
                    if '/blog/' in link or '/research/' in link
                ]
                
                # Limit the number of articles per website
                limited_article_links = article_links[:ARTICLES_PER_WEBSITE]
                
                logger.info(
                    f"Fetched {len(limited_article_links)} article links from {url}"
                )
                return limited_article_links
        except Exception as e:
            logger.error(f"Failed to fetch links from {url}: {e}")
            return []


async def scrape_article(
    session: CachedSession, url: str, semaphore: asyncio.Semaphore
) -> Optional[Article]:
    async with semaphore:
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                html = await response.text()
                g = Goose()
                extracted = g.extract(raw_html=html)
                
                if not extracted.cleaned_text:
                    logger.warning(f"No text extracted from {url}")
                    return None
                
                article = Article(
                    title=extracted.title,
                    text=extracted.cleaned_text,
                    url=url
                )
                logger.info(f"Scraped article: {article.title}")
                return article
        except Exception as e:
            logger.error(f"Failed to scrape article from {url}: {e}")
            return None


async def scrape_articles(
    session: CachedSession, links: List[str], semaphore: asyncio.Semaphore
) -> List[dict]:
    tasks = [scrape_article(session, link, semaphore) for link in links]
    results = await asyncio.gather(*tasks)
    scraped_articles = [article for article in results if article]
    logger.info(f"Scraped {len(scraped_articles)} articles.")
    return scraped_articles


async def web_scraping(urls: List[str]) -> List[Article]:
    logger.info("START: Web Scraping")
    try:
        all_articles = []
        async with CachedSession(headers=HEADERS) as session:
            semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)
            
            # Fetch article links with limits
            fetch_tasks = [
                fetch_article_links(session, url, semaphore) for url in urls
            ]
            links_lists = await asyncio.gather(*fetch_tasks)
            
            # Flatten the list of lists
            all_links = [link for sublist in links_lists for link in sublist]
            logger.info(f"Total article links fetched: {len(all_links)}")
            
            # Scrape the articles
            scraped_articles = await scrape_articles(session, all_links, semaphore)
            all_articles.extend(scraped_articles)
        
        logger.info("END: Web Scraping completed successfully.")
        return all_articles
    except Exception as e:
        logger.error(f"ERROR: Web Scraping failed - {e}")
        return []
