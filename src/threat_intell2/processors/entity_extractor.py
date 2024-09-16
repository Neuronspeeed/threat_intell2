import spacy
from typing import List
from ..utils.logging_config import logger
from ..models.data_models import Article, ThreatActor, TTP, IOC

try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    import subprocess
    subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
    nlp = spacy.load("en_core_web_sm")

def extract_entities(articles: List[Article]) -> List[Article]:
    logger.info("START: Entity Extraction")
    try:
        for article in articles:
            doc = nlp(article.text)
            
            # Extract threat actors
            threat_actors = []
            for ent in doc.ents:
                if ent.label_ in ['ORG', 'PERSON']:
                    existing_actor = next((actor for actor in threat_actors if ent.text in actor.names), None)
                    if existing_actor:
                        existing_actor.names.append(ent.text)
                    else:
                        threat_actor = ThreatActor(
                            names=[ent.text],
                            description=f"Extracted from article: {article.title}",
                        )
                        sentence = ent.sent
                        threat_actor.targets = [e.text for e in sentence.ents if e.label_ in ['GPE', 'ORG'] and e.text != ent.text]
                        threat_actor.tactics = [e.text for e in sentence.ents if e.label_ == 'EVENT']
                        threat_actor.techniques = [e.text for e in doc.ents if e.label_ == 'WORK_OF_ART' and e.sent == sentence]
                        
                        context = sentence.text
                        threat_actor.summary = f"Potential threat actor '{ent.text}' identified in the context: '{context}'"
                        
                        # Extract motivation (if available)
                        motivation_keywords = ['motivated by', 'aims to', 'goal is', 'objective is']
                        for keyword in motivation_keywords:
                            if keyword in sentence.text.lower():
                                threat_actor.motivation = sentence.text
                                break
                        
                        threat_actors.append(threat_actor)

            # Extract TTPs
            ttps = [TTP(tactic="Unknown", technique=ent.text) for ent in doc.ents if ent.label_ in ['EVENT', 'WORK_OF_ART']]
            
            # Extract IOCs
            iocs = [IOC(type="Unknown", value=ent.text) for ent in doc.ents if ent.label_ in ['PRODUCT', 'GPE', 'LOC']]
            
            # Add more sophisticated IOC extraction
            for token in doc:
                if token.like_url:
                    iocs.append(IOC(type="URL", value=token.text))
                elif token.like_email:
                    iocs.append(IOC(type="Email", value=token.text))
                elif token.shape_.startswith('dd') and len(token.text) > 8:
                    iocs.append(IOC(type="Potential Hash", value=token.text))

            # Link IOCs to threat actors
            for threat_actor in threat_actors:
                threat_actor.related_iocs = [ioc.value for ioc in iocs if any(name.lower() in ioc.value.lower() for name in threat_actor.names)]

            article.threat_actors = threat_actors
            article.ttps = ttps
            article.iocs = iocs

        logger.info("END: Entity Extraction completed successfully.")
        return articles
    except Exception as e:
        logger.error(f"ERROR: Entity Extraction failed - {e}")
        return articles