import spacy
import torch
from typing import List
from ..utils.logging_config import logger
from ..models.data_models import Article, ThreatActor, TTP, IOC
from spacy.matcher import Matcher
import tiktoken

def load_spacy_model():
    models = ["en_core_web_trf", "en_core_web_lg", "en_core_web_sm"]
    for model in models:
        try:
            nlp = spacy.load(model)
            if "sentencizer" not in nlp.pipe_names:
                nlp.add_pipe("sentencizer", before="parser")
            if torch.cuda.is_available():
                nlp.to("cuda")
            logger.info(f"Loaded spaCy model: {model}")
            return nlp
        except OSError:
            logger.warning(f"Spacy model '{model}' not found. Attempting to download...")
            try:
                spacy.cli.download(model)
                nlp = spacy.load(model)
                if "sentencizer" not in nlp.pipe_names:
                    nlp.add_pipe("sentencizer", before="parser")
                if torch.cuda.is_available():
                    nlp.to("cuda")
                logger.info(f"Successfully downloaded and loaded spaCy model: {model}")
                return nlp
            except Exception as e:
                logger.error(f"Failed to download {model}: {e}")
        except ValueError as e:
            if "Can't find factory for 'curated_transformer'" in str(e):
                logger.warning(f"Curated transformer not available for {model}. Trying next model.")
            else:
                logger.error(f"Error loading {model}: {e}")
    
    raise ValueError("No suitable spaCy model could be loaded. Please install at least en_core_web_sm manually.")

nlp = load_spacy_model()
matcher = Matcher(nlp.vocab)

# Define patterns for IP addresses, file hashes, etc.
ip_pattern = [{"TEXT": {"REGEX": r"\b(?:\d{1,3}\.){3}\d{1,3}\b"}}]
md5_pattern = [{"TEXT": {"REGEX": r"\b[a-fA-F0-9]{32}\b"}}]
sha1_pattern = [{"TEXT": {"REGEX": r"\b[a-fA-F0-9]{40}\b"}}]
sha256_pattern = [{"TEXT": {"REGEX": r"\b[a-fA-F0-9]{64}\b"}}]
cve_pattern = [{"TEXT": {"REGEX": r"CVE-\d{4}-\d{4,7}"}}]

matcher.add("IP_ADDRESS", [ip_pattern])
matcher.add("MD5_HASH", [md5_pattern])
matcher.add("SHA1_HASH", [sha1_pattern])
matcher.add("SHA256_HASH", [sha256_pattern])
matcher.add("CVE", [cve_pattern])

def chunk_text(text: str, max_tokens: int = 3000) -> list[str]:
    encoding = tiktoken.get_encoding('cl100k_base')
    tokens = encoding.encode(text)
    chunks = []
    current_chunk = []
    current_length = 0
    
    for token in tokens:
        if current_length + 1 > max_tokens:
            chunks.append(encoding.decode(current_chunk))
            current_chunk = []
            current_length = 0
        current_chunk.append(token)
        current_length += 1
    
    if current_chunk:
        chunks.append(encoding.decode(current_chunk))
    
    return chunks

def extract_entities(articles: List[Article]) -> List[Article]:
    logger.info("START: Entity Extraction")
    for article in articles:
        try:
            doc = nlp(article.text)
            
            # Extract threat actors
            threat_actors = []
            for ent in doc.ents:
                if ent.label_ in ['ORG', 'PERSON', 'NORP']:
                    existing_actor = next((actor for actor in threat_actors if ent.text.lower() in [name.lower() for name in actor.names]), None)
                    if existing_actor:
                        if ent.text not in existing_actor.names:
                            existing_actor.names.append(ent.text)
                    else:
                        threat_actor = ThreatActor(
                            names=[ent.text],
                            description=f"Extracted from article: {article.title}",
                        )
                        sentence = ent.sent
                        threat_actor.targets = [e.text for e in sentence.ents if e.label_ in ['GPE', 'ORG', 'PRODUCT'] and e.text.lower() != ent.text.lower()]
                        threat_actor.tactics = [e.text for e in sentence.ents if e.label_ in ['EVENT', 'WORK_OF_ART']]
                        threat_actor.techniques = [e.text for e in doc.ents if e.label_ in ['WORK_OF_ART', 'LAW'] and e.sent == sentence]
                        
                        context = sentence.text
                        threat_actor.summary = f"Potential threat actor '{ent.text}' identified in the context: '{context}'"
                        
                        # Extract motivation (if available)
                        motivation_keywords = ['motivated by', 'aims to', 'goal is', 'objective is', 'intends to', 'purpose is']
                        for keyword in motivation_keywords:
                            if keyword in sentence.text.lower():
                                threat_actor.motivation = sentence.text
                                break
                        
                        threat_actors.append(threat_actor)

            # Extract TTPs
            ttps = [TTP(tactic=ent.label_, technique=ent.text) for ent in doc.ents if ent.label_ in ['EVENT', 'WORK_OF_ART', 'LAW']]
            
            # Extract IOCs
            iocs = [IOC(type=ent.label_, value=ent.text) for ent in doc.ents if ent.label_ in ['PRODUCT', 'GPE', 'LOC', 'FAC', 'MONEY', 'CARDINAL']]
            
            # Add more sophisticated IOC extraction
            matches = matcher(doc)
            for match_id, start, end in matches:
                span = doc[start:end]
                ioc_type = nlp.vocab.strings[match_id]
                iocs.append(IOC(type=ioc_type, value=span.text))

            for token in doc:
                if token.like_url:
                    iocs.append(IOC(type="URL", value=token.text))
                elif token.like_email:
                    iocs.append(IOC(type="Email", value=token.text))

            # Link IOCs to threat actors
            for threat_actor in threat_actors:
                threat_actor.related_iocs = [ioc.value for ioc in iocs if any(name.lower() in ioc.value.lower() for name in threat_actor.names)]

            article.threat_actors = threat_actors
            article.ttps = ttps
            article.iocs = iocs

        except Exception as e:
            logger.error(f"Error processing article {article.url}: {str(e)}")
            # Initialize empty lists if processing fails
            article.threat_actors = []
            article.ttps = []
            article.iocs = []

    logger.info("END: Entity Extraction completed successfully.")
    return articles