import re
import spacy
from typing import List, Dict
from ..utils.logging_config import logger

try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    import subprocess
    subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
    nlp = spacy.load("en_core_web_sm")

def extract_entities(articles: List[Dict]) -> List[Dict]:
    logger.info("START: Entity Extraction")
    try:
        for article in articles:
            doc = nlp(article['text'])
            threat_actors = set()
            ttps = []
            iocs = set()
            for ent in doc.ents:
                if ent.label_ in ['ORG', 'PERSON']:
                    threat_actors.add(ent.text)
                elif ent.label_ == 'GPE':
                    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ent.text):
                        iocs.add(ent.text)
            ttps_matches = re.findall(r'\b(?:phishing|malware|ransomware|exploit kit)\b', article['text'], re.IGNORECASE)
            ttps = list(set([ttp.capitalize() for ttp in ttps_matches]))
            article['threat_actors'] = list(threat_actors)
            article['ttps'] = ttps
            article['iocs'] = list(iocs)
            logger.debug(f"Extracted from article '{article['title']}': Actors={threat_actors}, TTPs={ttps}, IOCs={iocs}")
        logger.info("END: Entity Extraction completed successfully.")
        return articles
    except Exception as e:
        logger.error(f"ERROR: Entity Extraction failed - {e}")
        return articles