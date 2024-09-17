from pydantic import BaseModel, HttpUrl, Field, validator
from typing import List, Optional, Union, Dict, Any
from pydantic.networks import IPvAnyAddress
from datetime import datetime


class TTP(BaseModel):
    tactic: str
    technique: str
    procedure: Optional[str] = None
    mitre_id: Optional[str] = None
    related_actors: List[str] = []


class IOC(BaseModel):
    type: str
    value: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    related_actors: List[str] = []
    related_ttps: List[str] = []


class ThreatActor(BaseModel):
    names: List[str]
    aliases: List[str] = []
    description: Optional[str] = None
    summary: Optional[str] = None
    motivation: Optional[str] = None
    targets: List[str] = []
    tactics: List[str] = []
    techniques: List[str] = []
    procedures: List[str] = []
    related_iocs: List[str] = []


class Article(BaseModel):
    title: str
    url: HttpUrl
    text: str
    summary: Optional[str] = None
    published_date: Optional[datetime] = None
    author: Optional[str] = None
    source: Optional[str] = None
    threat_actors: List[ThreatActor] = []
    ttps: List[TTP] = []
    iocs: List[IOC] = []
    risk_score: Optional[float] = Field(default=None, ge=0, le=100)
    related_articles: List[str] = []
    tags: List[str] = []

    def dict(self, *args, **kwargs):
        d = super().dict(*args, **kwargs)
        d['url'] = str(d['url'])  # Convert Url to string
        return d



class ThreatItem(BaseModel):
    description: str
    severity: Optional[str] = None

class RecommendationItem(BaseModel):
    description: str
    priority: Optional[str] = None

class Analysis(BaseModel):
    executive_summary: str
    threat_landscape: Dict[str, Dict[str, str]] = Field(default_factory=dict)
    emerging_threats: List[ThreatItem] = Field(default_factory=list)
    global_impact: str
    recommendations: List[RecommendationItem] = Field(default_factory=list)


class ThreatIntelligenceReport(BaseModel):
    id: str
    timestamp: datetime
    articles: List[Article]
    analysis: Analysis
    version: str
    generated_by: str


class AnalysisCollection(BaseModel):
    reports: List[ThreatIntelligenceReport] = []


class GraphState(BaseModel):
    url: List[str]
    data: str
    messages: List[str]
    reports: List[ThreatIntelligenceReport]
    iteration: int


class ThreatLandscapeItem(BaseModel):
    category: str
    description: str
    metrics: Dict[str, Any] = {}

class ThreatAnalysis(BaseModel):
    Executive_Summary: str
    Threat_Actors: List[ThreatActor]
    TTPs: List[TTP]
    IOCs: List[IOC]
    Global_Impact: str
    Recommendations: List[str]
