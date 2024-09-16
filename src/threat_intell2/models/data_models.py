from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
import re

class TTP(BaseModel):
    tactic: str
    technique: str
    procedure: Optional[str] = None

class IOC(BaseModel):
    type: str
    value: str
    description: Optional[str] = None

    @field_validator('value')
    def validate_value(cls, v):
        ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        hash_regex = r"^[a-fA-F0-9]{32,64}$"
        if not re.match(ip_regex, v) and not re.match(hash_regex, v):
            raise ValueError('Invalid IOC value format')
        return v

class ThreatActor(BaseModel):
    names: List[str]
    history: Optional[str] = None
    targets: List[str] = []
    ttps: List[TTP] = []
    iocs: List[IOC] = []

class ThreatIntelligenceReport(BaseModel):
    title: str
    date: str
    summary: str
    threat_level: str
    raw_text: str
    threat_actors: List[ThreatActor] = []

class AnalysisCollection(BaseModel):
    reports: List[ThreatIntelligenceReport] = []

class GraphState(BaseModel):
    url: List[str]
    data: str
    messages: List[str]
    reports: List[ThreatIntelligenceReport]
    iteration: int