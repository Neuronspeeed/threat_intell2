import asyncio
import aiohttp
from aiohttp_client_cache import CachedSession
from bs4 import BeautifulSoup
from goose3 import Goose
from urllib.parse import urljoin
from typing import List, Optional
from threat_intell2.utils.logging_config import logger
from threat_intell2.config import HEADERS, WEBSITES, SEMAPHORE_LIMIT

async def fetch_article_links(session: CachedSession, url: str, semaphore: asyncio.Semaphore) -> List[str]:
    async with semaphore:
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                absolute_links = [urljoin(url, link.get('href')) for link in soup.find_all('a') if link.get('href')]
                article_links = [link for link in absolute_links if '/blog/' in link or '/research/' in link]
                logger.info(f"Fetched {len(article_links)} article links from {url}")
                return article_links
        except Exception as e:
            logger.error(f"Failed to fetch links from {url}: {e}")
            return []

async def scrape_article(session: CachedSession, url: str, semaphore: asyncio.Semaphore) -> Optional[dict]:
    async with semaphore:
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                html = await response.text()
                g = Goose()
                article = g.extract(raw_html=html)
                if not article.cleaned_text:
                    logger.warning(f"No text extracted from {url}")
                    return None
                logger.info(f"Scraped article: {article.title}")
                return {
                    'title': article.title,
                    'text': article.cleaned_text,
                    'url': url
                }
        except Exception as e:
            logger.error(f"Failed to scrape article from {url}: {e}")
            return None

async def scrape_articles(session: CachedSession, links: List[str], semaphore: asyncio.Semaphore) -> List[dict]:
    tasks = [scrape_article(session, link, semaphore) for link in links]
    results = await asyncio.gather(*tasks)
    scraped_articles = [article for article in results if article]
    logger.info(f"Scraped {len(scraped_articles)} articles.")
    return scraped_articles

async def web_scraping(urls: List[str]) -> List[dict]:
    logger.info("START: Web Scraping")
    try:
        all_articles = []
        async with CachedSession(headers=HEADERS) as session:
            semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)
            fetch_tasks = [fetch_article_links(session, url, semaphore) for url in urls]
            links_lists = await asyncio.gather(*fetch_tasks)
            all_links = [link for sublist in links_lists for link in sublist]
            logger.info(f"Total article links fetched: {len(all_links)}")
            scraped_articles = await scrape_articles(session, all_links, semaphore)
            all_articles.extend(scraped_articles)
        logger.info("END: Web Scraping completed successfully.")
        return all_articles
    except Exception as e:
        logger.error(f"ERROR: Web Scraping failed - {e}")
        return []