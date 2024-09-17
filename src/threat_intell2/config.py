import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# OpenAI API configuration
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
DEFAULT_MODEL = "gpt-4"

# Scraping configuration
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}


# Number of articles to scrape per website
ARTICLES_PER_WEBSITE = 5  # Adjust this number as needed

# Websites to scrape
WEBSITES = [
    "https://www.crowdstrike.com/blog/category/threat-intel-research/",
    "https://www.wiz.io/blog/tag/research",
    "https://www.mandiant.com/resources/blog",
    "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/"
]

# Concurrency settings
SEMAPHORE_LIMIT = 5

# Logging configuration
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FILE = 'app.log'
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 2

# Rate limiting
RATE_LIMIT = 1  # Requests per second
MAX_RETRIES = 3
RETRY_DELAY = 5

# Text processing
MAX_TOKENS_PER_CHUNK = 7000

# Validate configuration
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_KEY environment variable is not set")

# Outputs configuration
OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), 'outputs')