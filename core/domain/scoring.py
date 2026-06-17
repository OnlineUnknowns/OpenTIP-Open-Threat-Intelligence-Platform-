import math
import datetime
from typing import Dict, Any, Optional
from core.config import settings

# Core domain constants for scoring
DEFAULT_IOC_TYPE_WEIGHTS = {
    "file-sha256": 1.0,   # Hashes are highly reliable (low false positives)
    "file-md5": 0.95,
    "domain-name": 0.8,   # Domains can be hijacked/re-registered
    "url": 0.75,          # URLs have moderate lifetime
    "ipv4-addr": 0.6,     # IPs change frequently (DHCP, cloud pools)
    "ipv6-addr": 0.6
}

def calculate_base_score(
    ioc_type: str, 
    confidence: int
) -> float:
    """
    Calculates the base score of an indicator based on its type weight and reporter confidence.
    Resulting base score is in the range [0, 100].
    """
    type_weight = DEFAULT_IOC_TYPE_WEIGHTS.get(ioc_type.lower(), 0.5)
    # Scale confidence (0-100) by the IOC type weight
    return float(confidence) * type_weight


def calculate_enrichment_score(enrichment_data: Dict[str, Any]) -> float:
    """
    Parses VirusTotal and Shodan enrichment data to calculate an aggregated threat score (0-100).
    If no enrichment data is available, returns 0.0.
    """
    scores = []
    
    # 1. VirusTotal Score
    vt_data = enrichment_data.get("virustotal")
    if vt_data and isinstance(vt_data, dict):
        # VirusTotal return format typically includes last_analysis_stats
        # e.g., {'harmless': 70, 'malicious': 14, 'suspicious': 2, 'undetected': 0}
        stats = vt_data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        
        if total > 0:
            # Malicious counts fully, suspicious counts for 50%
            vt_threat_ratio = (malicious + (suspicious * 0.5)) / total
            # Scale to 100
            scores.append(vt_threat_ratio * 100.0)

    # 2. Shodan Score
    shodan_data = enrichment_data.get("shodan")
    if shodan_data and isinstance(shodan_data, dict):
        # Shodan data might contain ports and vulnerabilities (vulns)
        # We assign risk based on vulnerabilities or specific dangerous open ports (e.g. 22, 3389, 445)
        vulns = shodan_data.get("vulns", [])
        ports = shodan_data.get("ports", [])
        
        shodan_score = 0.0
        if vulns:
            # If there are CVEs, start with a high risk score
            shodan_score += min(len(vulns) * 20.0, 70.0)  # Max 70 for vulns
            
        if ports:
            # Having open ports increases vulnerability surface
            critical_ports = {22, 23, 445, 3389, 5900}
            intersect = set(ports).intersection(critical_ports)
            shodan_score += min(len(intersect) * 10.0, 30.0)  # Max 30 for critical ports
            
        scores.append(min(shodan_score, 100.0))

    if not scores:
        return 0.0
        
    # Average the enrichment scores
    return sum(scores) / len(scores)


def calculate_time_decay(
    initial_score: float, 
    last_seen: datetime.datetime, 
    decay_lambda: float = None
) -> float:
    """
    Applies exponential decay over time elapsed since the indicator was last seen:
    S(t) = S_0 * e^(-lambda * t)
    t is measured in days (including fractional days).
    """
    if decay_lambda is None:
        decay_lambda = settings.DECAY_LAMBDA
        
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Handle future dates or timezone mismatches safely
    if last_seen > now:
        return initial_score
        
    time_diff = now - last_seen
    days_elapsed = time_diff.total_seconds() / 86400.0
    
    decay_factor = math.exp(-decay_lambda * days_elapsed)
    return initial_score * decay_factor


def compute_final_risk_score(
    ioc_type: str,
    confidence: int,
    last_seen: datetime.datetime,
    enrichment_data: Dict[str, Any],
    base_weight: float = 0.4,
    enrichment_weight: float = 0.6
) -> float:
    """
    Aggregates the base and enrichment scores using weighted averages, 
    and applies exponential time-decay.
    Returns a score rounded to 2 decimal places, bounded between [0.0, 100.0].
    """
    # 1. Base Score calculation
    base_score = calculate_base_score(ioc_type, confidence)
    
    # 2. Enrichment Score calculation
    enrichment_score = calculate_enrichment_score(enrichment_data)
    
    # 3. Weighted initial score
    # If no enrichment data is available yet, don't penalize; use 100% of base_score
    if not enrichment_data:
        initial_score = base_score
    else:
        initial_score = (base_score * base_weight) + (enrichment_score * enrichment_weight)
        
    # 4. Time Decay
    final_score = calculate_time_decay(initial_score, last_seen)
    
    # 5. Bound the score between 0.0 and 100.0
    final_score = max(0.0, min(100.0, final_score))
    
    return round(final_score, 2)
