from typing import List, Dict, Any
from threat_intell2.models.data_models import Analysis, ThreatItem, RecommendationItem

def generate_report(analyzed_data: List[Dict[str, Any]], timestamp: str) -> Dict[str, Any]:
    executive_summary = " ".join(
        [item["analysis"]["Executive_Summary"] for item in analyzed_data if "analysis" in item]
    )
    threat_landscape = {}
    emerging_threats = []
    global_impact = ""
    recommendations = []

    for item in analyzed_data:
        analysis = item.get("analysis", {})
        for actor in analysis.get("Threat_Actors", []):
            if actor not in threat_landscape:
                threat_landscape[actor] = {"description": ""}
        emerging_threats.extend([ThreatItem(description=ttp) for ttp in analysis.get("TTPs", [])])
        global_impact += analysis.get("Global_Impact", " ") + " "
        recommendations.extend([RecommendationItem(description=rec) for rec in analysis.get("Recommendations", [])])

    # Remove duplicates
    emerging_threats = list({threat.description: threat for threat in emerging_threats}.values())
    recommendations = list({rec.description: rec for rec in recommendations}.values())
    global_impact = global_impact.strip()

    analysis = Analysis(
        executive_summary=executive_summary,
        threat_landscape=threat_landscape,
        emerging_threats=emerging_threats,
        global_impact=global_impact,
        recommendations=recommendations
    )

    report = {
        "threat_intelligence": analysis.dict()
    }

    return report